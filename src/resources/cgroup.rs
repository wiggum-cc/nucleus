use crate::error::{NucleusError, Result, StateTransition};
use crate::resources::{CgroupState, ResourceLimits};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";
const NUCLEUS_CGROUP_ROOT_ENV: &str = "NUCLEUS_CGROUP_ROOT";
const CGROUP_CLEANUP_RETRIES: usize = 50;
const CGROUP_CLEANUP_SLEEP: Duration = Duration::from_millis(20);

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
        let path = Self::root_path()?.join(name);

        info!("Creating cgroup at {:?}", path);

        // Create cgroup directory
        fs::create_dir_all(&path).map_err(|e| {
            NucleusError::CgroupError(format!("Failed to create cgroup directory: {}", e))
        })?;

        Ok(Self { path, state })
    }

    fn root_path() -> Result<PathBuf> {
        Self::root_path_from_override(std::env::var_os(NUCLEUS_CGROUP_ROOT_ENV))
    }

    fn root_path_from_override(raw: Option<std::ffi::OsString>) -> Result<PathBuf> {
        match raw {
            Some(raw) if !raw.as_os_str().is_empty() => {
                let path = PathBuf::from(raw);
                if !path.is_absolute() {
                    return Err(NucleusError::CgroupError(format!(
                        "{} must be an absolute path",
                        NUCLEUS_CGROUP_ROOT_ENV
                    )));
                }
                Ok(path)
            }
            _ => Ok(PathBuf::from(CGROUP_V2_ROOT)),
        }
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
        if limits.memory_bytes.is_some()
            || limits.memory_high.is_some()
            || limits.memory_swap_max.is_some()
        {
            self.write_value("memory.oom.group", "1")?;
            debug!("Set memory.oom.group = 1");
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

    fn set_frozen(&self, frozen: bool) -> Result<bool> {
        let freeze_path = self.path.join("cgroup.freeze");
        if !freeze_path.exists() {
            return Ok(false);
        }
        self.write_value("cgroup.freeze", if frozen { "1" } else { "0" })?;
        debug!("Set cgroup.freeze = {}", if frozen { 1 } else { 0 });
        Ok(true)
    }

    fn parse_cgroup_events_populated(events: &str) -> Result<bool> {
        for line in events.lines() {
            if let Some(value) = line.strip_prefix("populated ") {
                return match value.trim() {
                    "0" => Ok(false),
                    "1" => Ok(true),
                    other => Err(NucleusError::CgroupError(format!(
                        "Unexpected populated value in cgroup.events: {}",
                        other
                    ))),
                };
            }
        }
        Err(NucleusError::CgroupError(
            "Missing populated entry in cgroup.events".to_string(),
        ))
    }

    fn read_pids(&self) -> Result<Vec<Pid>> {
        let file_path = self.path.join("cgroup.procs");
        if !file_path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&file_path).map_err(|e| {
            NucleusError::CgroupError(format!("Failed to read {:?}: {}", file_path, e))
        })?;
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                line.trim().parse::<i32>().map(Pid::from_raw).map_err(|e| {
                    NucleusError::CgroupError(format!(
                        "Failed to parse pid '{}' from {:?}: {}",
                        line.trim(),
                        file_path,
                        e
                    ))
                })
            })
            .collect()
    }

    fn is_populated(&self) -> Result<bool> {
        let events_path = self.path.join("cgroup.events");
        if events_path.exists() {
            let events = fs::read_to_string(&events_path).map_err(|e| {
                NucleusError::CgroupError(format!("Failed to read {:?}: {}", events_path, e))
            })?;
            return Self::parse_cgroup_events_populated(&events);
        }
        Ok(!self.read_pids()?.is_empty())
    }

    fn kill_visible_processes(&self) -> Result<()> {
        for pid in self.read_pids()? {
            match kill(pid, Signal::SIGKILL) {
                Ok(()) => {}
                Err(nix::errno::Errno::ESRCH) => {}
                Err(e) => {
                    return Err(NucleusError::CgroupError(format!(
                        "Failed to SIGKILL pid {} in {:?}: {}",
                        pid, self.path, e
                    )))
                }
            }
        }
        Ok(())
    }

    fn kill_all_processes(&self) -> Result<()> {
        let kill_path = self.path.join("cgroup.kill");
        if kill_path.exists() {
            self.write_value("cgroup.kill", "1")?;
            debug!("Triggered cgroup.kill for {:?}", self.path);
        }
        self.kill_visible_processes()
    }

    fn wait_until_empty(&self) -> Result<()> {
        for attempt in 0..CGROUP_CLEANUP_RETRIES {
            if !self.is_populated()? {
                return Ok(());
            }
            if attempt + 1 < CGROUP_CLEANUP_RETRIES {
                self.kill_visible_processes()?;
                thread::sleep(CGROUP_CLEANUP_SLEEP);
            }
        }

        let remaining = self
            .read_pids()?
            .into_iter()
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>();
        Err(NucleusError::CgroupError(format!(
            "Timed out waiting for cgroup {:?} to drain (remaining pids: {})",
            self.path,
            if remaining.is_empty() {
                "<unknown>".to_string()
            } else {
                remaining.join(", ")
            }
        )))
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
    /// State transition: * -> Removed (only on success)
    pub fn cleanup(mut self) -> Result<()> {
        info!("Cleaning up cgroup {:?}", self.path);

        if self.path.exists() {
            let froze = self.set_frozen(true)?;
            let cleanup_result: Result<()> = (|| {
                self.kill_all_processes()?;
                self.wait_until_empty()?;
                fs::remove_dir(&self.path).map_err(|e| {
                    // BUG-06: Do NOT set state to Removed on failure – Drop should
                    // still attempt cleanup when the Cgroup is dropped.
                    NucleusError::CgroupError(format!("Failed to remove cgroup: {}", e))
                })?;
                Ok(())
            })();
            if cleanup_result.is_err() && froze {
                if let Err(e) = self.set_frozen(false) {
                    warn!(
                        "Failed to unfreeze cgroup {:?} after cleanup error: {}",
                        self.path, e
                    );
                }
            }
            cleanup_result?;
        }

        // Only mark as terminal after successful removal
        self.state = CgroupState::Removed;
        info!("Successfully cleaned up cgroup");

        Ok(())
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if !self.state.is_terminal() && self.path.exists() {
            let froze = self.set_frozen(true).unwrap_or(false);
            let _ = self.kill_all_processes();
            let _ = self.wait_until_empty();
            let _ = fs::remove_dir(&self.path);
            if self.path.exists() && froze {
                let _ = self.set_frozen(false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

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

    #[test]
    fn test_cgroup_root_override_requires_absolute_path() {
        assert_eq!(
            Cgroup::root_path_from_override(None).unwrap(),
            PathBuf::from(CGROUP_V2_ROOT)
        );
        assert_eq!(
            Cgroup::root_path_from_override(Some(OsString::from(""))).unwrap(),
            PathBuf::from(CGROUP_V2_ROOT)
        );
        assert_eq!(
            Cgroup::root_path_from_override(Some(OsString::from("/sys/fs/cgroup/example.service")))
            .unwrap(),
            PathBuf::from("/sys/fs/cgroup/example.service")
        );
        assert!(Cgroup::root_path_from_override(Some(OsString::from("relative"))).is_err());
    }

    // Note: Testing actual cgroup operations requires root privileges
    // and cgroup v2 filesystem. These are tested in integration tests.

    #[test]
    fn test_cleanup_sets_removed_only_after_success() {
        // BUG-06: cleanup must not mark state as Removed before the directory
        // is actually removed. Verify structurally by brace-matching the
        // function body instead of using a fragile char-window offset.
        let source = include_str!("cgroup.rs");
        let fn_start = source.find("pub fn cleanup").unwrap();
        let after = &source[fn_start..];
        let open = after.find('{').unwrap();
        let mut depth = 0u32;
        let mut fn_end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let cleanup_body = &after[..fn_end];
        let removed_pos = cleanup_body
            .find("Removed")
            .expect("must reference Removed state");
        let remove_dir_pos = cleanup_body
            .find("remove_dir")
            .expect("must call remove_dir");
        assert!(
            removed_pos > remove_dir_pos,
            "CgroupState::Removed must be set AFTER remove_dir succeeds, not before"
        );
    }

    #[test]
    fn test_parse_cgroup_events_populated() {
        assert!(Cgroup::parse_cgroup_events_populated("populated 1\nfrozen 0\n").unwrap());
        assert!(!Cgroup::parse_cgroup_events_populated("frozen 0\npopulated 0\n").unwrap());
    }

    #[test]
    fn test_set_limits_source_enables_memory_oom_group() {
        let source = include_str!("cgroup.rs");
        let fn_start = source.find("pub fn set_limits").unwrap();
        let after = &source[fn_start..];
        let open = after.find('{').unwrap();
        let mut depth = 0u32;
        let mut fn_end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &after[..fn_end];
        assert!(
            body.contains("memory.oom.group"),
            "set_limits must enable memory.oom.group when memory controls are configured"
        );
    }

    #[test]
    fn test_cleanup_source_kills_processes_before_remove_dir() {
        let source = include_str!("cgroup.rs");
        let fn_start = source.find("pub fn cleanup").unwrap();
        let after = &source[fn_start..];
        let open = after.find('{').unwrap();
        let mut depth = 0u32;
        let mut fn_end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &after[..fn_end];
        let freeze_pos = body.find("set_frozen(true)").unwrap();
        let kill_pos = body.find("kill_all_processes").unwrap();
        let remove_dir_pos = body.find("remove_dir").unwrap();
        assert!(
            freeze_pos < kill_pos && kill_pos < remove_dir_pos,
            "cleanup must freeze and kill the cgroup before attempting remove_dir"
        );
    }
}
