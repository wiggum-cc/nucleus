use crate::error::{NucleusError, Result};
use crate::resources::{CgroupState, ResourceLimits};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";

/// Cgroup v2 manager
///
/// Implements the cgroup lifecycle state machine from
/// Nucleus_Resources_CgroupLifecycle.tla
pub struct Cgroup {
    path: PathBuf,
    state: CgroupState,
}

impl Cgroup {
    /// Create a new cgroup with the given name
    ///
    /// State transition: Nonexistent -> Created
    pub fn create(name: &str) -> Result<Self> {
        let state = CgroupState::Nonexistent.transition(CgroupState::Created)?;
        let path = PathBuf::from(CGROUP_V2_ROOT).join(name);

        info!("Creating cgroup at {:?}", path);

        // Create cgroup directory
        fs::create_dir_all(&path).map_err(|e| {
            NucleusError::CgroupError(format!("Failed to create cgroup directory: {}", e))
        })?;

        Ok(Self { path, state })
    }

    /// Set resource limits
    ///
    /// State transition: Created -> Configured
    pub fn set_limits(&mut self, limits: &ResourceLimits) -> Result<()> {
        self.state = self.state.transition(CgroupState::Configured)?;

        info!("Configuring cgroup limits: {:?}", limits);

        // Set memory limit
        if let Some(memory_bytes) = limits.memory_bytes {
            self.write_value("memory.max", &memory_bytes.to_string())?;
            debug!("Set memory.max = {}", memory_bytes);
        }

        // Set memory soft limit (high watermark)
        if let Some(memory_high) = limits.memory_high {
            self.write_value("memory.high", &memory_high.to_string())?;
            debug!("Set memory.high = {}", memory_high);
        }

        // Set swap limit
        if let Some(swap_max) = limits.memory_swap_max {
            self.write_value("memory.swap.max", &swap_max.to_string())?;
            debug!("Set memory.swap.max = {}", swap_max);
        }

        // Set CPU limit
        if let Some(cpu_quota_us) = limits.cpu_quota_us {
            let cpu_max = format!("{} {}", cpu_quota_us, limits.cpu_period_us);
            self.write_value("cpu.max", &cpu_max)?;
            debug!("Set cpu.max = {}", cpu_max);
        }

        // Set CPU weight
        if let Some(cpu_weight) = limits.cpu_weight {
            self.write_value("cpu.weight", &cpu_weight.to_string())?;
            debug!("Set cpu.weight = {}", cpu_weight);
        }

        // Set PID limit
        if let Some(pids_max) = limits.pids_max {
            self.write_value("pids.max", &pids_max.to_string())?;
            debug!("Set pids.max = {}", pids_max);
        }

        // Set I/O limits
        for io_limit in &limits.io_limits {
            let line = io_limit.to_io_max_line();
            self.write_value("io.max", &line)?;
            debug!("Set io.max: {}", line);
        }

        info!("Successfully configured cgroup limits");

        Ok(())
    }

    /// Attach a process to this cgroup
    ///
    /// State transition: Configured -> Attached
    pub fn attach_process(&mut self, pid: u32) -> Result<()> {
        self.state = self.state.transition(CgroupState::Attached)?;

        info!("Attaching process {} to cgroup", pid);

        self.write_value("cgroup.procs", &pid.to_string())?;

        info!("Successfully attached process to cgroup");

        Ok(())
    }

    /// Write a value to a cgroup file
    fn write_value(&self, file: &str, value: &str) -> Result<()> {
        let file_path = self.path.join(file);
        fs::write(&file_path, value).map_err(|e| {
            NucleusError::CgroupError(format!(
                "Failed to write {} to {:?}: {}",
                value, file_path, e
            ))
        })?;
        Ok(())
    }

    /// Read a value from a cgroup file
    fn read_value(&self, file: &str) -> Result<String> {
        let file_path = self.path.join(file);
        fs::read_to_string(&file_path).map_err(|e| {
            NucleusError::CgroupError(format!("Failed to read {:?}: {}", file_path, e))
        })
    }

    /// Get current memory usage
    pub fn memory_current(&self) -> Result<u64> {
        let value = self.read_value("memory.current")?;
        value.trim().parse().map_err(|e| {
            NucleusError::CgroupError(format!("Failed to parse memory.current: {}", e))
        })
    }

    /// Get cgroup path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the current state of this cgroup
    pub fn state(&self) -> CgroupState {
        self.state
    }

    /// Clean up the cgroup
    ///
    /// State transition: * -> Removed
    pub fn cleanup(mut self) -> Result<()> {
        self.state = self.state.transition(CgroupState::Removed)?;
        info!("Cleaning up cgroup {:?}", self.path);

        // Try to remove the cgroup directory
        // This will fail if there are still processes in the cgroup
        if self.path.exists() {
            fs::remove_dir(&self.path).map_err(|e| {
                NucleusError::CgroupError(format!("Failed to remove cgroup: {}", e))
            })?;
        }

        info!("Successfully cleaned up cgroup");

        Ok(())
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if !self.state.is_terminal() && self.path.exists() {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_unlimited() {
        let limits = ResourceLimits::unlimited();
        assert!(limits.memory_bytes.is_none());
        assert!(limits.memory_high.is_none());
        assert!(limits.memory_swap_max.is_none());
        assert!(limits.cpu_quota_us.is_none());
        assert!(limits.cpu_weight.is_none());
        assert!(limits.pids_max.is_none());
        assert!(limits.io_limits.is_empty());
    }

    // Note: Testing actual cgroup operations requires root privileges
    // and cgroup v2 filesystem. These are tested in integration tests.
}
