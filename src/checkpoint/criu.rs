use crate::checkpoint::metadata::CheckpointMetadata;
use crate::checkpoint::state::CheckpointState;
use crate::container::ContainerState;
use crate::error::{NucleusError, Result, StateTransition};
use nix::unistd::Uid;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::Builder;
use tracing::info;

/// CRIU runtime for checkpoint/restore
///
/// Follows the same pattern as GVisorRuntime: find binary, validate, invoke via Command.
pub struct CriuRuntime {
    binary_path: PathBuf,
    state: CheckpointState,
}

impl CriuRuntime {
    /// Create a new CRIU runtime, finding the criu binary
    pub fn new() -> Result<Self> {
        let binary_path = Self::find_binary()?;

        // Validate binary works
        let output = Command::new(&binary_path)
            .arg("--version")
            .output()
            .map_err(|e| NucleusError::CheckpointError(format!("Failed to execute criu: {}", e)))?;

        if !output.status.success() {
            return Err(NucleusError::CheckpointError(
                "criu --version failed".to_string(),
            ));
        }

        let version = String::from_utf8_lossy(&output.stdout);
        info!("Found CRIU: {}", version.trim());

        Ok(Self {
            binary_path,
            state: CheckpointState::None,
        })
    }

    /// Validate a binary path for safe execution
    fn validate_binary(path: &Path) -> Result<()> {
        let metadata = fs::metadata(path).map_err(|e| {
            NucleusError::CheckpointError(format!("Cannot stat criu binary {:?}: {}", path, e))
        })?;
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(NucleusError::CheckpointError(format!(
                "criu binary {:?} is writable by group/others (mode {:o}), refusing to execute",
                path, mode
            )));
        }
        if mode & 0o111 == 0 {
            return Err(NucleusError::CheckpointError(format!(
                "criu binary {:?} is not executable",
                path
            )));
        }
        Ok(())
    }

    fn find_binary() -> Result<PathBuf> {
        // Check common locations
        for path in &["/usr/sbin/criu", "/usr/bin/criu", "/usr/local/sbin/criu"] {
            let p = PathBuf::from(path);
            if p.exists() {
                Self::validate_binary(&p)?;
                return Ok(p);
            }
        }

        // For privileged execution, do not resolve runtime binaries via PATH.
        // This avoids environment-based binary hijacking when running as root.
        if Uid::effective().is_root() {
            return Err(NucleusError::CheckpointError(
                "CRIU binary not found in trusted system paths".to_string(),
            ));
        }

        // Try PATH for unprivileged execution.
        if let Some(path_var) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("criu");
                if candidate.exists() {
                    Self::validate_binary(&candidate)?;
                    return Ok(candidate);
                }
            }
        }

        Err(NucleusError::CheckpointError(
            "CRIU binary not found. Install criu to use checkpoint/restore.".to_string(),
        ))
    }

    /// Checkpoint a running container
    ///
    /// State transitions: None -> Dumping -> Dumped (or Dumping -> None on failure)
    pub fn checkpoint(
        &mut self,
        state: &ContainerState,
        output_dir: &Path,
        leave_running: bool,
    ) -> Result<()> {
        // Requires root
        if !nix::unistd::Uid::effective().is_root() {
            return Err(NucleusError::CheckpointError(
                "Checkpoint requires root (CRIU needs CAP_SYS_PTRACE)".to_string(),
            ));
        }

        if !state.is_running() {
            return Err(NucleusError::CheckpointError(format!(
                "Container {} is not running",
                state.id
            )));
        }

        // State transition: None -> Dumping
        self.state = self.state.transition(CheckpointState::Dumping)?;

        let images_dir = Self::prepare_checkpoint_dir(output_dir)?;

        // Run criu dump
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("dump")
            .arg("--tree")
            .arg(state.pid.to_string())
            .arg("--images-dir")
            .arg(&images_dir)
            .arg("--shell-job");

        if leave_running {
            cmd.arg("--leave-running");
        }

        info!(
            "Checkpointing container {} (PID {}) to {:?}",
            state.id, state.pid, output_dir
        );

        let output = cmd.output().map_err(|e| {
            // Abort: Dumping -> None
            self.state = self.state.transition(CheckpointState::None).unwrap_or(self.state);
            NucleusError::CheckpointError(format!("Failed to run criu dump: {}", e))
        })?;

        if !output.status.success() {
            // Abort: Dumping -> None
            self.state = self.state.transition(CheckpointState::None).unwrap_or(self.state);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NucleusError::CheckpointError(format!(
                "criu dump failed: {}",
                stderr
            )));
        }

        // Write metadata
        let metadata = CheckpointMetadata::from_state(state);
        metadata.save(output_dir)?;

        // State transition: Dumping -> Dumped
        self.state = self.state.transition(CheckpointState::Dumped)?;

        info!("Checkpoint complete: {:?}", output_dir);
        Ok(())
    }

    /// Restore a container from checkpoint
    ///
    /// State transitions: None -> Restoring -> Restored (or Restoring -> None on failure)
    pub fn restore(&mut self, input_dir: &Path) -> Result<u32> {
        // Requires root
        if !nix::unistd::Uid::effective().is_root() {
            return Err(NucleusError::CheckpointError(
                "Restore requires root (CRIU needs CAP_SYS_PTRACE)".to_string(),
            ));
        }

        // Load and validate metadata
        let metadata = CheckpointMetadata::load(input_dir)?;
        info!(
            "Restoring container {} from checkpoint (originally PID {})",
            metadata.container_id, metadata.original_pid
        );

        let images_dir = input_dir.join("images");
        if !images_dir.exists() {
            return Err(NucleusError::CheckpointError(format!(
                "Images directory not found: {:?}",
                images_dir
            )));
        }

        // State transition: None -> Restoring
        self.state = self.state.transition(CheckpointState::Restoring)?;

        // Capture the restored init PID explicitly.
        let pidfile = Builder::new()
            .prefix("nucleus-criu-restore-")
            .tempfile()
            .map_err(|e| {
                NucleusError::CheckpointError(format!("Failed to create CRIU pidfile: {}", e))
            })?;
        let pidfile_path = pidfile.path().to_path_buf();

        // Run criu restore
        let output = Command::new(&self.binary_path)
            .arg("restore")
            .arg("--images-dir")
            .arg(&images_dir)
            .arg("--shell-job")
            .arg("--pidfile")
            .arg(&pidfile_path)
            .output()
            .map_err(|e| {
                // Abort: Restoring -> None
                self.state = self.state.transition(CheckpointState::None).unwrap_or(self.state);
                NucleusError::CheckpointError(format!("Failed to run criu restore: {}", e))
            })?;

        if !output.status.success() {
            // Abort: Restoring -> None
            self.state = self.state.transition(CheckpointState::None).unwrap_or(self.state);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NucleusError::CheckpointError(format!(
                "criu restore failed: {}",
                stderr
            )));
        }

        // State transition: Restoring -> Restored
        self.state = self.state.transition(CheckpointState::Restored)?;

        // Parse restored PID from pidfile, with output fallback for compatibility.
        let pid_text = fs::read_to_string(&pidfile_path).unwrap_or_default();
        if let Some(pid) = Self::parse_pidfile(&pid_text) {
            info!("Restore complete, new PID: {}", pid);
            return Ok(pid);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(pid) = Self::parse_pid_text(&stdout) {
            info!("Restore complete, new PID: {}", pid);
            return Ok(pid);
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if let Some(pid) = Self::parse_pid_text(&stderr) {
            info!("Restore complete, new PID: {}", pid);
            return Ok(pid);
        }

        Err(NucleusError::CheckpointError(format!(
            "Failed to parse restored PID from CRIU output (pidfile='{}', stdout='{}', stderr='{}')",
            pid_text.trim(),
            stdout.trim(),
            stderr.trim()
        )))
    }

    fn parse_pid_text(text: &str) -> Option<u32> {
        text.split(|c: char| !c.is_ascii_digit())
            .filter(|tok| !tok.is_empty())
            .find_map(|tok| tok.parse::<u32>().ok())
    }

    fn parse_pidfile(text: &str) -> Option<u32> {
        let trimmed = text.trim();
        if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        trimmed.parse::<u32>().ok()
    }

    fn prepare_checkpoint_dir(output_dir: &Path) -> Result<PathBuf> {
        Self::ensure_secure_dir(output_dir, "checkpoint directory")?;
        let images_dir = output_dir.join("images");
        Self::ensure_secure_dir(&images_dir, "checkpoint images directory")?;
        Ok(images_dir)
    }

    fn ensure_secure_dir(path: &Path, label: &str) -> Result<()> {
        Self::reject_symlink_path(path, label)?;

        if path.exists() {
            if !path.is_dir() {
                return Err(NucleusError::CheckpointError(format!(
                    "{} {:?} is not a directory",
                    label, path
                )));
            }
        } else {
            fs::create_dir_all(path).map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to create {} {:?}: {}",
                    label, path, e
                ))
            })?;
        }

        Self::reject_symlink_path(path, label)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to set {} permissions {:?}: {}",
                label, path, e
            ))
        })?;

        Ok(())
    }

    fn reject_symlink_path(path: &Path, label: &str) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(
                NucleusError::CheckpointError(format!(
                    "Refusing symlink {} {:?}",
                    label, path
                )),
            ),
            Ok(_) | Err(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CriuRuntime;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::TempDir;

    #[test]
    fn test_parse_pid_text_plain() {
        assert_eq!(CriuRuntime::parse_pid_text("1234\n"), Some(1234));
    }

    #[test]
    fn test_parse_pid_text_embedded() {
        assert_eq!(
            CriuRuntime::parse_pid_text("restored successfully pid=5678"),
            Some(5678)
        );
    }

    #[test]
    fn test_parse_pid_text_missing() {
        assert_eq!(CriuRuntime::parse_pid_text("no pid here"), None);
    }

    #[test]
    fn test_parse_pidfile_strict() {
        // BUG-22: parse_pid_text must prefer strict pidfile parsing
        // A pidfile should contain just a number, not extract first number from error messages
        assert_eq!(CriuRuntime::parse_pidfile("1234\n"), Some(1234));
        assert_eq!(CriuRuntime::parse_pidfile("  5678  \n"), Some(5678));
        // Error messages should NOT parse as PIDs
        assert_eq!(CriuRuntime::parse_pidfile("Error code: 255 (EPERM)"), None);
        assert_eq!(CriuRuntime::parse_pidfile("restored successfully pid=5678"), None);
        assert_eq!(CriuRuntime::parse_pidfile(""), None);
        assert_eq!(CriuRuntime::parse_pidfile("no pid here"), None);
    }

    #[test]
    fn test_prepare_checkpoint_dir_rejects_symlinked_images_dir() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target");
        fs::create_dir(&target).unwrap();
        let images = tmp.path().join("images");
        symlink(&target, &images).unwrap();

        let err = CriuRuntime::prepare_checkpoint_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink rejection, got: {err}"
        );
    }

    #[test]
    fn test_prepare_checkpoint_dir_creates_images_subdir() {
        let tmp = TempDir::new().unwrap();
        let images = CriuRuntime::prepare_checkpoint_dir(tmp.path()).unwrap();
        assert_eq!(images, tmp.path().join("images"));
        assert!(images.is_dir());

        // Verify permissions are 0o700
        let mode = fs::metadata(&images).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "images dir should be mode 700, got {:o}", mode);
    }

    #[test]
    fn test_prepare_checkpoint_dir_rejects_file_as_output_dir() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("not-a-dir");
        fs::write(&file_path, "").unwrap();

        let err = CriuRuntime::prepare_checkpoint_dir(&file_path).unwrap_err();
        assert!(
            err.to_string().contains("not a directory"),
            "expected 'not a directory' error, got: {err}"
        );
    }

    #[test]
    fn test_prepare_checkpoint_dir_rejects_symlinked_output_dir() {
        let tmp = TempDir::new().unwrap();
        let real_dir = tmp.path().join("real");
        fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        symlink(&real_dir, &link).unwrap();

        let err = CriuRuntime::prepare_checkpoint_dir(&link).unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "expected symlink rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_binary_rejects_group_writable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o775)).unwrap();

        let err = CriuRuntime::validate_binary(&bin).unwrap_err();
        assert!(
            err.to_string().contains("writable by group/others"),
            "expected group-writable rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_binary_rejects_world_writable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o757)).unwrap();

        let err = CriuRuntime::validate_binary(&bin).unwrap_err();
        assert!(
            err.to_string().contains("writable by group/others"),
            "expected world-writable rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_binary_rejects_non_executable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o600)).unwrap();

        let err = CriuRuntime::validate_binary(&bin).unwrap_err();
        assert!(
            err.to_string().contains("not executable"),
            "expected non-executable rejection, got: {err}"
        );
    }

    #[test]
    fn test_validate_binary_accepts_secure_binary() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();

        CriuRuntime::validate_binary(&bin).expect("should accept mode 0755");
    }

    #[test]
    fn test_validate_binary_accepts_owner_only_executable() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("criu");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();

        CriuRuntime::validate_binary(&bin).expect("should accept mode 0700");
    }

    #[test]
    fn test_validate_binary_rejects_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("nonexistent");
        assert!(CriuRuntime::validate_binary(&bin).is_err());
    }

    #[test]
    fn test_checkpoint_state_transitions() {
        use crate::checkpoint::state::CheckpointState;
        use crate::error::StateTransition;

        // Valid forward transitions
        assert!(CheckpointState::None.can_transition_to(&CheckpointState::Dumping));
        assert!(CheckpointState::Dumping.can_transition_to(&CheckpointState::Dumped));
        assert!(CheckpointState::None.can_transition_to(&CheckpointState::Restoring));
        assert!(CheckpointState::Restoring.can_transition_to(&CheckpointState::Restored));

        // Valid abort transitions
        assert!(CheckpointState::Dumping.can_transition_to(&CheckpointState::None));
        assert!(CheckpointState::Restoring.can_transition_to(&CheckpointState::None));

        // Invalid transitions
        assert!(!CheckpointState::None.can_transition_to(&CheckpointState::Dumped));
        assert!(!CheckpointState::None.can_transition_to(&CheckpointState::Restored));
        assert!(!CheckpointState::Dumped.can_transition_to(&CheckpointState::Restoring));
        assert!(!CheckpointState::Restored.can_transition_to(&CheckpointState::Dumping));
    }

    #[test]
    fn test_prepare_checkpoint_dir_sets_secure_permissions() {
        let tmp = TempDir::new().unwrap();
        CriuRuntime::prepare_checkpoint_dir(tmp.path()).unwrap();

        // Both output dir and images subdir should be 0700
        let output_mode = fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        let images_mode = fs::metadata(tmp.path().join("images"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(output_mode, 0o700);
        assert_eq!(images_mode, 0o700);
    }
}
