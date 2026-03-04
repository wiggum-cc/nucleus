use crate::container::ContainerState;
use crate::error::{NucleusError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::SystemTime;

/// Metadata stored alongside checkpoint images
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMetadata {
    /// Container ID
    pub container_id: String,

    /// Container name
    pub container_name: String,

    /// Original PID
    pub original_pid: u32,

    /// Command that was running
    pub command: Vec<String>,

    /// Timestamp of checkpoint
    pub checkpoint_at: u64,

    /// Nucleus version
    pub version: String,

    /// Whether container was using gVisor
    pub using_gvisor: bool,

    /// Whether container was rootless
    pub rootless: bool,
}

impl CheckpointMetadata {
    /// Create metadata from current container state
    pub fn from_state(state: &ContainerState) -> Self {
        let checkpoint_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            container_id: state.id.clone(),
            container_name: state.name.clone(),
            original_pid: state.pid,
            command: state.command.clone(),
            checkpoint_at,
            version: env!("CARGO_PKG_VERSION").to_string(),
            using_gvisor: state.using_gvisor,
            rootless: state.rootless,
        }
    }

    /// Save metadata to checkpoint directory
    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join("metadata.json");
        let tmp_path = dir.join("metadata.json.tmp");
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to serialize metadata: {}", e))
        })?;

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| {
                NucleusError::CheckpointError(format!(
                    "Failed to open temp metadata file {:?}: {}",
                    tmp_path, e
                ))
            })?;

        file.write_all(json.as_bytes()).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to write metadata file {:?}: {}",
                tmp_path, e
            ))
        })?;
        file.sync_all().map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to sync metadata file {:?}: {}",
                tmp_path, e
            ))
        })?;

        fs::rename(&tmp_path, &path).map_err(|e| {
            NucleusError::CheckpointError(format!(
                "Failed to atomically replace metadata file {:?}: {}",
                path, e
            ))
        })?;
        Ok(())
    }

    /// Load metadata from checkpoint directory
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("metadata.json");
        let json = fs::read_to_string(&path).map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to read metadata: {}", e))
        })?;
        let metadata: Self = serde_json::from_str(&json).map_err(|e| {
            NucleusError::CheckpointError(format!("Failed to parse metadata: {}", e))
        })?;
        Ok(metadata)
    }
}
