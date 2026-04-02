use crate::container::{ContainerState, ContainerStateManager};
use crate::error::{NucleusError, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use nix::unistd::Uid;
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

/// Container lifecycle operations (stop, kill, delete)
pub struct ContainerLifecycle;

impl ContainerLifecycle {
    fn ensure_container_access(state: &ContainerState) -> Result<()> {
        let current_uid = Uid::effective().as_raw();
        if current_uid == 0 || current_uid == state.creator_uid {
            return Ok(());
        }

        Err(NucleusError::PermissionDenied(format!(
            "container {} owned by UID {}, caller is UID {}",
            state.id, state.creator_uid, current_uid
        )))
    }

    /// Stop a container gracefully: SIGTERM, wait for timeout, then SIGKILL
    pub fn stop(state: &ContainerState, timeout_secs: u64) -> Result<()> {
        Self::ensure_container_access(state)?;

        if !state.is_running() {
            info!("Container {} is already stopped", state.id);
            return Ok(());
        }

        let pid = Pid::from_raw(state.pid as i32);

        // Send SIGTERM
        info!(
            "Sending SIGTERM to container {} (PID {})",
            state.id, state.pid
        );
        if let Err(e) = kill(pid, Signal::SIGTERM) {
            if e == nix::errno::Errno::ESRCH {
                info!("Process already exited");
                return Ok(());
            }
            return Err(NucleusError::ExecError(format!(
                "Failed to send SIGTERM: {}",
                e
            )));
        }

        // Wait for process to exit
        let poll_interval = Duration::from_millis(100);
        let deadline = Duration::from_secs(timeout_secs);
        let mut elapsed = Duration::ZERO;

        while elapsed < deadline {
            if !state.is_running() {
                info!("Container {} stopped gracefully", state.id);
                return Ok(());
            }
            thread::sleep(poll_interval);
            elapsed += poll_interval;
        }

        // Force kill
        warn!(
            "Container {} did not stop after {}s, sending SIGKILL",
            state.id, timeout_secs
        );
        if let Err(e) = kill(pid, Signal::SIGKILL) {
            if e == nix::errno::Errno::ESRCH {
                return Ok(());
            }
            return Err(NucleusError::ExecError(format!(
                "Failed to send SIGKILL: {}",
                e
            )));
        }

        Ok(())
    }

    /// Send an arbitrary signal to a container
    pub fn kill_container(state: &ContainerState, signal: Signal) -> Result<()> {
        Self::ensure_container_access(state)?;

        if !state.is_running() {
            return Err(NucleusError::ContainerNotRunning(format!(
                "Container {} is not running",
                state.id
            )));
        }

        let pid = Pid::from_raw(state.pid as i32);
        info!(
            "Sending {:?} to container {} (PID {})",
            signal, state.id, state.pid
        );

        kill(pid, signal).map_err(|e| {
            NucleusError::ExecError(format!("Failed to send signal {:?}: {}", signal, e))
        })?;

        Ok(())
    }

    /// Remove a stopped container's state
    pub fn remove(
        state_mgr: &ContainerStateManager,
        state: &ContainerState,
        force: bool,
    ) -> Result<()> {
        Self::ensure_container_access(state)?;

        if state.is_running() {
            if force {
                info!("Force removing running container {}", state.id);
                Self::stop(state, 5)?;
            } else {
                return Err(NucleusError::ExecError(format!(
                    "Container {} is still running. Stop it first or use --force",
                    state.id
                )));
            }
        }

        // Clean up cgroup directory if present
        if let Some(ref cgroup_path) = state.cgroup_path {
            let cgroup = std::path::Path::new(cgroup_path);
            if cgroup.exists() {
                if let Err(e) = std::fs::remove_dir(cgroup) {
                    warn!(
                        "Failed to remove cgroup {}: {} (may still have processes)",
                        cgroup_path, e
                    );
                } else {
                    info!("Removed cgroup {}", cgroup_path);
                }
            }
        }

        state_mgr.delete_state(&state.id)?;
        info!("Removed container {}", state.id);
        Ok(())
    }
}

/// Parse a signal name or number string into a Signal
pub fn parse_signal(s: &str) -> Result<Signal> {
    // Try numeric
    if let Ok(num) = s.parse::<i32>() {
        return Signal::try_from(num)
            .map_err(|_| NucleusError::ConfigError(format!("Invalid signal number: {}", num)));
    }

    // Normalize: uppercase and strip optional "SIG" prefix
    let upper = s.to_uppercase();
    let normalized = upper.strip_prefix("SIG").unwrap_or(&upper);

    match normalized {
        "TERM" => Ok(Signal::SIGTERM),
        "KILL" => Ok(Signal::SIGKILL),
        "INT" => Ok(Signal::SIGINT),
        "HUP" => Ok(Signal::SIGHUP),
        "QUIT" => Ok(Signal::SIGQUIT),
        "USR1" => Ok(Signal::SIGUSR1),
        "USR2" => Ok(Signal::SIGUSR2),
        "STOP" => Ok(Signal::SIGSTOP),
        "CONT" => Ok(Signal::SIGCONT),
        _ => Err(NucleusError::ConfigError(format!("Unknown signal: {}", s))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signal_by_name() {
        assert_eq!(parse_signal("TERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("SIGTERM").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("KILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("SIGKILL").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("INT").unwrap(), Signal::SIGINT);
        assert_eq!(parse_signal("HUP").unwrap(), Signal::SIGHUP);
    }

    #[test]
    fn test_parse_signal_by_number() {
        assert_eq!(parse_signal("15").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("9").unwrap(), Signal::SIGKILL);
        assert_eq!(parse_signal("2").unwrap(), Signal::SIGINT);
    }

    #[test]
    fn test_parse_signal_case_insensitive() {
        assert_eq!(parse_signal("term").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("sigterm").unwrap(), Signal::SIGTERM);
        assert_eq!(parse_signal("Term").unwrap(), Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_invalid() {
        assert!(parse_signal("INVALID").is_err());
        assert!(parse_signal("999").is_err());
    }

    #[test]
    fn test_access_check_owner_allowed() {
        let uid = Uid::effective().as_raw();
        let state = ContainerState::new(
            "testid".to_string(),
            "testname".to_string(),
            12345,
            vec!["/bin/true".to_string()],
            None,
            None,
            false,
            true,
            None,
        );
        // Override creator to match current caller for this test.
        let mut state = state;
        state.creator_uid = uid;
        assert!(ContainerLifecycle::ensure_container_access(&state).is_ok());
    }
}
