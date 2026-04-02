use crate::error::{NucleusError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Container state tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerState {
    /// Container ID (unique 32 hex chars, 128-bit)
    pub id: String,

    /// Container name (user-supplied or same as ID)
    pub name: String,

    /// PID of the container process
    pub pid: u32,

    /// Command being executed
    pub command: Vec<String>,

    /// Start time (Unix timestamp)
    pub started_at: u64,

    /// Memory limit in bytes (None = unlimited)
    pub memory_limit: Option<u64>,

    /// CPU limit in millicores (None = unlimited)
    pub cpu_limit: Option<u64>,

    /// Whether using gVisor runtime
    pub using_gvisor: bool,

    /// Whether using rootless mode
    pub rootless: bool,

    /// cgroup path
    pub cgroup_path: Option<String>,

    /// Desired topology config hash associated with this container, if any.
    #[serde(default)]
    pub config_hash: Option<u64>,

    /// UID of the user who created this container
    #[serde(default)]
    pub creator_uid: u32,

    /// Process start time in clock ticks (from /proc/<pid>/stat field 22)
    /// Used to detect PID reuse in is_running()
    #[serde(default)]
    pub start_ticks: u64,
}

impl ContainerState {
    /// Create a new container state
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        name: String,
        pid: u32,
        command: Vec<String>,
        memory_limit: Option<u64>,
        cpu_limit: Option<u64>,
        using_gvisor: bool,
        rootless: bool,
        cgroup_path: Option<String>,
    ) -> Self {
        let started_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let start_ticks = Self::read_start_ticks(pid);

        Self {
            id,
            name,
            pid,
            command,
            started_at,
            memory_limit,
            cpu_limit,
            using_gvisor,
            rootless,
            cgroup_path,
            config_hash: None,
            creator_uid: nix::unistd::Uid::effective().as_raw(),
            start_ticks,
        }
    }

    /// Read the start time in clock ticks from /proc/<pid>/stat (field 22)
    fn read_start_ticks(pid: u32) -> u64 {
        let stat_path = format!("/proc/{}/stat", pid);
        match std::fs::read_to_string(&stat_path) {
            Ok(content) => Self::parse_start_ticks(&content).unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Parse start time (field 22) from /proc/<pid>/stat content
    fn parse_start_ticks(content: &str) -> Option<u64> {
        // Field 2 (comm) is in parens and may contain spaces; find last ')'
        let after_comm = content.rfind(')')?;
        // After ')' we have fields 3..N; field 22 is index 19 (22 - 3 = 19)
        // Use nth() instead of collecting into a Vec to avoid a heap allocation
        // on every liveness check.
        content[after_comm + 2..]
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()
    }

    /// Check if the container process is still running
    ///
    /// Cross-checks PID start time to detect PID reuse after process exit.
    pub fn is_running(&self) -> bool {
        let stat_path = format!("/proc/{}/stat", self.pid);
        match std::fs::read_to_string(&stat_path) {
            Ok(content) => {
                if self.start_ticks == 0 {
                    // Legacy state without start_ticks – fall back to existence check
                    return true;
                }
                Self::parse_start_ticks(&content)
                    .map(|ticks| ticks == self.start_ticks)
                    .unwrap_or(false)
            }
            Err(_) => false,
        }
    }

    /// Get uptime in seconds
    pub fn uptime(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.started_at)
    }
}

/// Container state manager
///
/// Manages persistent state of running containers
pub struct ContainerStateManager {
    state_dir: PathBuf,
}

impl ContainerStateManager {
    /// Create a new state manager
    ///
    /// Creates the state directory if it doesn't exist
    pub fn new() -> Result<Self> {
        let mut last_error = None;
        for candidate in Self::default_state_dir_candidates() {
            match Self::with_state_dir(candidate.clone()) {
                Ok(manager) => return Ok(manager),
                Err(err) => {
                    debug!(
                        path = ?candidate,
                        error = %err,
                        "State directory candidate unavailable, trying next fallback"
                    );
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            NucleusError::ConfigError("No usable state directory candidates found".to_string())
        }))
    }

    /// Create a state manager rooted at an explicit directory.
    pub fn with_state_dir(state_dir: PathBuf) -> Result<Self> {
        Self::reject_symlink_path(&state_dir)?;

        // Create state directory if it doesn't exist
        if !state_dir.exists() {
            fs::create_dir_all(&state_dir).map_err(|e| {
                NucleusError::ConfigError(format!(
                    "Failed to create state directory {:?}: {}",
                    state_dir, e
                ))
            })?;
        }
        Self::reject_symlink_path(&state_dir)?;
        Self::ensure_secure_state_dir_permissions(&state_dir)?;
        Self::ensure_state_dir_writable(&state_dir)?;

        Ok(Self { state_dir })
    }

    fn reject_symlink_path(state_dir: &Path) -> Result<()> {
        match fs::symlink_metadata(state_dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err(NucleusError::ConfigError(format!(
                    "Refusing symlink state directory path {:?}; use a real directory",
                    state_dir
                )))
            }
            Ok(_) | Err(_) => Ok(()),
        }
    }

    fn ensure_secure_state_dir_permissions(state_dir: &Path) -> Result<()> {
        match fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700)) {
            Ok(()) => Ok(()),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EROFS) | Some(libc::EPERM) | Some(libc::EACCES)
                ) =>
            {
                let metadata = fs::metadata(state_dir).map_err(|meta_err| {
                    NucleusError::ConfigError(format!(
                        "Failed to secure state directory permissions {:?}: {} (and could not \
                         inspect existing permissions: {})",
                        state_dir, e, meta_err
                    ))
                })?;

                let mode = metadata.permissions().mode() & 0o777;
                let owner = metadata.uid();
                let current_uid = nix::unistd::Uid::effective().as_raw();
                let is_owner_ok = owner == current_uid || nix::unistd::Uid::effective().is_root();
                let is_mode_ok = mode & 0o077 == 0;

                if is_owner_ok && is_mode_ok {
                    debug!(
                        path = ?state_dir,
                        mode = format!("{:o}", mode),
                        owner,
                        "State directory already has secure permissions; skipping chmod failure"
                    );
                    Ok(())
                } else {
                    Err(NucleusError::ConfigError(format!(
                        "Failed to secure state directory permissions {:?}: {} (existing mode \
                         {:o}, owner uid {})",
                        state_dir, e, mode, owner
                    )))
                }
            }
            Err(e) => Err(NucleusError::ConfigError(format!(
                "Failed to secure state directory permissions {:?}: {}",
                state_dir, e
            ))),
        }
    }

    fn ensure_state_dir_writable(state_dir: &Path) -> Result<()> {
        let probe_name = format!(
            ".nucleus-write-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let probe_path = state_dir.join(probe_name);

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe_path)
            .map_err(|e| {
                NucleusError::ConfigError(format!(
                    "State directory {:?} is not writable: {}",
                    state_dir, e
                ))
            })?;
        drop(file);

        fs::remove_file(&probe_path).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to cleanup state directory probe {:?}: {}",
                probe_path, e
            ))
        })?;

        Ok(())
    }

    /// Get ordered default state directory candidates.
    fn default_state_dir_candidates() -> Vec<PathBuf> {
        if let Some(path) = std::env::var_os("NUCLEUS_STATE_DIR").filter(|p| !p.is_empty()) {
            return vec![PathBuf::from(path)];
        }

        if nix::unistd::Uid::effective().is_root() {
            vec![PathBuf::from("/var/run/nucleus")]
        } else {
            let mut candidates = Vec::new();

            if let Some(dir) = dirs::runtime_dir() {
                candidates.push(dir.join("nucleus"));
            }
            if let Some(dir) = dirs::data_local_dir() {
                candidates.push(dir.join("nucleus"));
            }
            if let Some(dir) = dirs::home_dir() {
                candidates.push(dir.join(".nucleus"));
            }

            // Final fallback for restricted sandboxes where standard runtime/home
            // paths are mounted read-only. Keep it private to the effective UID.
            candidates.push(PathBuf::from(format!(
                "/tmp/nucleus-{}",
                nix::unistd::Uid::effective().as_raw()
            )));

            candidates
        }
    }

    /// Validate a container ID for safe filesystem use
    fn validate_container_id(container_id: &str) -> Result<()> {
        if container_id.is_empty() {
            return Err(NucleusError::ConfigError(
                "Container ID cannot be empty".to_string(),
            ));
        }

        if !container_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(NucleusError::ConfigError(format!(
                "Invalid container ID (allowed: a-zA-Z0-9_-): {}",
                container_id
            )));
        }

        Ok(())
    }

    fn state_file_path(&self, container_id: &str) -> Result<PathBuf> {
        Self::validate_container_id(container_id)?;
        Ok(self.state_dir.join(format!("{}.json", container_id)))
    }

    /// Resolve a container reference by exact ID, name, or ID prefix
    pub fn resolve_container(&self, reference: &str) -> Result<ContainerState> {
        let states = self.list_states()?;

        // Try exact ID match
        if let Some(state) = states.iter().find(|s| s.id == reference) {
            return Ok(state.clone());
        }

        // Try exact name match (must be unambiguous)
        let name_matches: Vec<&ContainerState> =
            states.iter().filter(|s| s.name == reference).collect();
        match name_matches.len() {
            1 => return Ok(name_matches[0].clone()),
            n if n > 1 => {
                return Err(NucleusError::AmbiguousContainer(format!(
                    "Name '{}' matches {} containers; use container ID instead",
                    reference, n
                )))
            }
            _ => {}
        }

        // Try ID prefix match
        let prefix_matches: Vec<&ContainerState> = states
            .iter()
            .filter(|s| s.id.starts_with(reference))
            .collect();

        match prefix_matches.len() {
            0 => Err(NucleusError::ContainerNotFound(reference.to_string())),
            1 => Ok(prefix_matches[0].clone()),
            _ => Err(NucleusError::AmbiguousContainer(format!(
                "'{}' matches {} containers",
                reference,
                prefix_matches.len()
            ))),
        }
    }

    /// Save container state
    pub fn save_state(&self, state: &ContainerState) -> Result<()> {
        let path = self.state_file_path(&state.id)?;
        let tmp_path = self.state_dir.join(format!("{}.json.tmp", state.id));
        let json = serde_json::to_string_pretty(state).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to serialize container state: {}", e))
        })?;

        // O_NOFOLLOW prevents TOCTOU symlink attacks: if an attacker replaces
        // the temp path with a symlink between check and open, the open fails
        // instead of following the symlink to an attacker-controlled location.
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
            .map_err(|e| {
                NucleusError::ConfigError(format!(
                    "Failed to open temp state file {:?}: {}",
                    tmp_path, e
                ))
            })?;

        file.write_all(json.as_bytes()).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to write state file {:?}: {}", tmp_path, e))
        })?;
        file.sync_all().map_err(|e| {
            NucleusError::ConfigError(format!("Failed to sync state file {:?}: {}", tmp_path, e))
        })?;

        fs::rename(&tmp_path, &path).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to atomically replace state file {:?}: {}",
                path, e
            ))
        })?;

        debug!("Saved container state: {}", state.id);
        Ok(())
    }

    /// Read a file with O_NOFOLLOW to prevent symlink attacks.
    fn read_file_nofollow(path: &std::path::Path) -> std::result::Result<String, std::io::Error> {
        use std::io::Read;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let mut buf = String::new();
        std::io::BufReader::new(file).read_to_string(&mut buf)?;
        Ok(buf)
    }

    /// Load container state
    ///
    /// Opens with O_NOFOLLOW to prevent symlink-based TOCTOU attacks.
    pub fn load_state(&self, container_id: &str) -> Result<ContainerState> {
        let path = self.state_file_path(container_id)?;

        // Use O_NOFOLLOW to atomically reject symlinks at open time
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| {
                NucleusError::ConfigError(format!("Failed to read state file {:?}: {}", path, e))
            })?;

        let json: String = {
            use std::io::Read;
            let mut buf = String::new();
            std::io::BufReader::new(file)
                .read_to_string(&mut buf)
                .map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to read state file {:?}: {}",
                        path, e
                    ))
                })?;
            buf
        };

        let state = serde_json::from_str(&json).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to parse container state: {}", e))
        })?;

        Ok(state)
    }

    /// Delete container state
    pub fn delete_state(&self, container_id: &str) -> Result<()> {
        let path = self.state_file_path(container_id)?;

        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                NucleusError::ConfigError(format!("Failed to delete state file {:?}: {}", path, e))
            })?;
            debug!("Deleted container state: {}", container_id);
        }

        Ok(())
    }

    /// List all container states
    pub fn list_states(&self) -> Result<Vec<ContainerState>> {
        let mut states = Vec::new();

        let entries = fs::read_dir(&self.state_dir).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to read state directory {:?}: {}",
                self.state_dir, e
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                NucleusError::ConfigError(format!("Failed to read directory entry: {}", e))
            })?;

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                // Use O_NOFOLLOW to prevent symlink attacks, consistent with
                // load_state/save_state. Without this, a symlink in the state
                // directory could be used as a file-read oracle.
                match Self::read_file_nofollow(&path) {
                    Ok(json) => match serde_json::from_str::<ContainerState>(&json) {
                        Ok(state) => states.push(state),
                        Err(e) => {
                            warn!("Failed to parse state file {:?}: {}", path, e);
                        }
                    },
                    Err(e) => {
                        warn!("Failed to read state file {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(states)
    }

    /// List only running containers
    pub fn list_running(&self) -> Result<Vec<ContainerState>> {
        let states = self.list_states()?;
        Ok(states.into_iter().filter(|s| s.is_running()).collect())
    }

    /// Clean up stale state files (for containers that are no longer running)
    pub fn cleanup_stale(&self) -> Result<()> {
        let states = self.list_states()?;

        for state in states {
            if !state.is_running() {
                info!(
                    "Cleaning up stale state for container {} (PID {})",
                    state.id, state.pid
                );
                self.delete_state(&state.id)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_state_manager() -> (ContainerStateManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mgr = ContainerStateManager {
            state_dir: temp_dir.path().to_path_buf(),
        };
        (mgr, temp_dir)
    }

    #[test]
    fn test_container_state_new() {
        let state = ContainerState::new(
            "test".to_string(),
            "test".to_string(),
            1234,
            vec!["/bin/sh".to_string()],
            Some(512 * 1024 * 1024),
            Some(2000),
            false,
            false,
            Some("/sys/fs/cgroup/nucleus-test".to_string()),
        );

        assert_eq!(state.id, "test");
        assert_eq!(state.pid, 1234);
        assert_eq!(state.memory_limit, Some(512 * 1024 * 1024));
        assert_eq!(state.cpu_limit, Some(2000));
        assert_eq!(state.creator_uid, nix::unistd::Uid::effective().as_raw());
    }

    #[test]
    fn test_save_and_load_state() {
        let (mgr, _temp_dir) = temp_state_manager();

        let state = ContainerState::new(
            "test".to_string(),
            "test".to_string(),
            1234,
            vec!["/bin/sh".to_string()],
            Some(512 * 1024 * 1024),
            None,
            false,
            false,
            None,
        );

        mgr.save_state(&state).unwrap();

        let loaded = mgr.load_state("test").unwrap();
        assert_eq!(loaded.id, state.id);
        assert_eq!(loaded.pid, state.pid);
        assert_eq!(loaded.command, state.command);
    }

    #[test]
    fn test_delete_state() {
        let (mgr, _temp_dir) = temp_state_manager();

        let state = ContainerState::new(
            "test".to_string(),
            "test".to_string(),
            1234,
            vec!["/bin/sh".to_string()],
            None,
            None,
            false,
            false,
            None,
        );

        mgr.save_state(&state).unwrap();
        assert!(mgr.load_state("test").is_ok());

        mgr.delete_state("test").unwrap();
        assert!(mgr.load_state("test").is_err());
    }

    #[test]
    fn test_list_states() {
        let (mgr, _temp_dir) = temp_state_manager();

        let state1 = ContainerState::new(
            "test1".to_string(),
            "test1".to_string(),
            1234,
            vec!["/bin/sh".to_string()],
            None,
            None,
            false,
            false,
            None,
        );

        let state2 = ContainerState::new(
            "test2".to_string(),
            "test2".to_string(),
            5678,
            vec!["/bin/bash".to_string()],
            None,
            None,
            false,
            false,
            None,
        );

        mgr.save_state(&state1).unwrap();
        mgr.save_state(&state2).unwrap();

        let states = mgr.list_states().unwrap();
        assert_eq!(states.len(), 2);
    }

    #[test]
    fn test_resolve_container_by_id() {
        let (mgr, _temp_dir) = temp_state_manager();

        let state = ContainerState::new(
            "abc123def456".to_string(),
            "mycontainer".to_string(),
            1234,
            vec!["/bin/sh".to_string()],
            None,
            None,
            false,
            false,
            None,
        );
        mgr.save_state(&state).unwrap();

        // Exact ID
        let resolved = mgr.resolve_container("abc123def456").unwrap();
        assert_eq!(resolved.id, "abc123def456");

        // Name
        let resolved = mgr.resolve_container("mycontainer").unwrap();
        assert_eq!(resolved.id, "abc123def456");

        // ID prefix
        let resolved = mgr.resolve_container("abc123").unwrap();
        assert_eq!(resolved.id, "abc123def456");

        // Not found
        assert!(mgr.resolve_container("nonexistent").is_err());
    }

    #[test]
    fn test_load_state_rejects_symlink() {
        // H-3: O_NOFOLLOW must prevent loading state through a symlink
        let (mgr, temp_dir) = temp_state_manager();

        // Create a real state file
        let state = ContainerState::new(
            "real".to_string(),
            "real".to_string(),
            1234,
            vec!["/bin/sh".to_string()],
            None,
            None,
            false,
            false,
            None,
        );
        mgr.save_state(&state).unwrap();

        // Create a symlink pointing to the real state file
        let symlink_path = temp_dir.path().join("symlinked.json");
        let real_path = temp_dir.path().join("real.json");
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        // Loading through the symlink ID must fail (O_NOFOLLOW)
        let result = mgr.load_state("symlinked");
        assert!(result.is_err(), "load_state must reject symlinks");
    }

    #[test]
    fn test_list_states_ignores_symlinks() {
        // list_states must use O_NOFOLLOW, so symlinked state files are skipped
        // rather than followed (which would be a file-read oracle).
        let (mgr, temp_dir) = temp_state_manager();

        // Create a real state file
        let state = ContainerState::new(
            "real123456789012345678".to_string(),
            "real".to_string(),
            1234,
            vec!["/bin/sh".to_string()],
            None,
            None,
            false,
            false,
            None,
        );
        mgr.save_state(&state).unwrap();

        // Create a symlink masquerading as a state file
        let real_path = temp_dir.path().join("real123456789012345678.json");
        let symlink_path = temp_dir.path().join("evil.json");
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();

        // list_states should only return the real file, not follow the symlink
        let states = mgr.list_states().unwrap();
        // The symlink should fail to open with O_NOFOLLOW, leaving only the real state
        assert_eq!(states.len(), 1, "symlinked state file must be skipped");
        assert_eq!(states[0].id, "real123456789012345678");
    }

    #[test]
    fn test_save_state_rejects_symlink_tmp() {
        // H-3: O_NOFOLLOW on save must prevent writing through a symlink
        let (mgr, temp_dir) = temp_state_manager();

        let state = ContainerState::new(
            "target".to_string(),
            "target".to_string(),
            1234,
            vec!["/bin/sh".to_string()],
            None,
            None,
            false,
            false,
            None,
        );

        // Pre-create a symlink at the temp path to simulate an attack
        let tmp_path = temp_dir.path().join("target.json.tmp");
        let evil_path = temp_dir.path().join("evil");
        std::os::unix::fs::symlink(&evil_path, &tmp_path).unwrap();

        // save_state should fail because O_NOFOLLOW rejects the symlink
        let result = mgr.save_state(&state);
        assert!(result.is_err(), "save_state must reject symlinks at tmp path");
    }
}
