use crate::error::{NucleusError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Container state tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerState {
    /// Container ID (unique 12 hex chars)
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
        let fields: Vec<&str> = content[after_comm + 2..].split_whitespace().collect();
        // After ')' we have fields 3..N; field 22 is index 19 (22 - 3 = 19)
        fields.get(19)?.parse().ok()
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
        let state_dir = Self::default_state_dir();

        // Create state directory if it doesn't exist
        if !state_dir.exists() {
            fs::create_dir_all(&state_dir).map_err(|e| {
                NucleusError::ConfigError(format!(
                    "Failed to create state directory {:?}: {}",
                    state_dir, e
                ))
            })?;
        }
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to secure state directory permissions {:?}: {}",
                state_dir, e
            ))
        })?;

        Ok(Self { state_dir })
    }

    /// Get default state directory
    fn default_state_dir() -> PathBuf {
        if nix::unistd::Uid::effective().is_root() {
            PathBuf::from("/var/run/nucleus")
        } else {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("nucleus")
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

        // Try exact name match
        if let Some(state) = states.iter().find(|s| s.name == reference) {
            return Ok(state.clone());
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

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
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

    /// Load container state
    pub fn load_state(&self, container_id: &str) -> Result<ContainerState> {
        let path = self.state_file_path(container_id)?;

        let json = fs::read_to_string(&path).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to read state file {:?}: {}", path, e))
        })?;

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
                match fs::read_to_string(&path) {
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
}
