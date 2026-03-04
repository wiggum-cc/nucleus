use crate::checkpoint::metadata::CheckpointMetadata;
use crate::container::ContainerState;
use crate::error::{NucleusError, Result};
use nix::unistd::Uid;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;

/// CRIU runtime for checkpoint/restore
///
/// Follows the same pattern as GVisorRuntime: find binary, validate, invoke via Command.
pub struct CriuRuntime {
    binary_path: PathBuf,
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

        Ok(Self { binary_path })
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
    pub fn checkpoint(
        &self,
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

        // Create output directory with secure permissions
        fs::create_dir_all(output_dir).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to create checkpoint directory {:?}: {}",
                output_dir, e
            ))
        })?;
        fs::set_permissions(output_dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to set checkpoint directory permissions: {}",
                e
            ))
        })?;

        // Create images subdirectory
        let images_dir = output_dir.join("images");
        fs::create_dir_all(&images_dir).map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to create images directory: {}", e))
        })?;

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
            NucleusError::CheckpointError(format!("Failed to run criu dump: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NucleusError::CheckpointError(format!(
                "criu dump failed: {}",
                stderr
            )));
        }

        // Write metadata
        let metadata = CheckpointMetadata::from_state(state);
        metadata.save(output_dir)?;

        info!("Checkpoint complete: {:?}", output_dir);
        Ok(())
    }

    /// Restore a container from checkpoint
    pub fn restore(&self, input_dir: &Path) -> Result<u32> {
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

        // Run criu restore
        let output = Command::new(&self.binary_path)
            .arg("restore")
            .arg("--images-dir")
            .arg(&images_dir)
            .arg("--shell-job")
            .output()
            .map_err(|e| {
                NucleusError::CheckpointError(format!("Failed to run criu restore: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NucleusError::CheckpointError(format!(
                "criu restore failed: {}",
                stderr
            )));
        }

        // Parse PID from criu output (criu prints the restored PID)
        let stdout = String::from_utf8_lossy(&output.stdout);
        let pid: u32 = stdout.trim().parse().map_err(|_| {
            NucleusError::CheckpointError(format!(
                "Failed to parse restored PID from criu output: '{}'",
                stdout.trim()
            ))
        })?;

        info!("Restore complete, new PID: {}", pid);
        Ok(pid)
    }
}
