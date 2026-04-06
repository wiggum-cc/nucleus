use crate::audit::{audit, AuditEventType};
use crate::container::ProcessIdentity;
use crate::error::{NucleusError, Result};
use nix::sys::signal::{kill, Signal};
use nix::sys::signal::{pthread_sigmask, SigSet, SigmaskHow};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, setgid, setgroups, setuid, ForkResult, Gid, Pid, Uid};
use std::ffi::CString;
use tracing::{debug, error, info};

use super::runtime::Container;

impl Container {
    pub(crate) fn apply_process_identity_to_current_process(
        identity: &ProcessIdentity,
        inside_user_namespace: bool,
    ) -> Result<()> {
        if identity.is_root() {
            return Ok(());
        }

        if !inside_user_namespace {
            let groups: Vec<Gid> = identity
                .additional_gids
                .iter()
                .copied()
                .map(Gid::from_raw)
                .collect();
            setgroups(&groups).map_err(|e| {
                NucleusError::ExecError(format!(
                    "Failed to set supplementary groups to {:?}: {}",
                    identity.additional_gids, e
                ))
            })?;
        }

        setgid(Gid::from_raw(identity.gid)).map_err(|e| {
            NucleusError::ExecError(format!("Failed to switch to gid {}: {}", identity.gid, e))
        })?;
        setuid(Uid::from_raw(identity.uid)).map_err(|e| {
            NucleusError::ExecError(format!("Failed to switch to uid {}: {}", identity.uid, e))
        })?;

        info!(
            "Applied workload identity uid={} gid={} supplementary_gids={:?}",
            identity.uid, identity.gid, identity.additional_gids
        );

        Ok(())
    }

    /// Execute the target command.
    ///
    /// This runs in the child process after fork, after all security setup is complete.
    pub(super) fn exec_command(&self) -> Result<()> {
        if self.config.command.is_empty() {
            return Err(NucleusError::ExecError("No command specified".to_string()));
        }

        info!("Executing command: {:?}", self.config.command);

        Self::apply_process_identity_to_current_process(
            &self.config.process_identity,
            self.config.user_ns_config.is_some(),
        )?;

        let program = CString::new(self.config.command[0].as_str())
            .map_err(|e| NucleusError::ExecError(format!("Invalid program name: {}", e)))?;

        let args: Result<Vec<CString>> = self
            .config
            .command
            .iter()
            .map(|arg| {
                CString::new(arg.as_str())
                    .map_err(|e| NucleusError::ExecError(format!("Invalid argument: {}", e)))
            })
            .collect();
        let args = args?;

        let mut env = vec![
            CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
                .map_err(|e| NucleusError::ExecError(format!("Invalid environment PATH: {}", e)))?,
            CString::new("TERM=xterm")
                .map_err(|e| NucleusError::ExecError(format!("Invalid environment TERM: {}", e)))?,
            CString::new("HOME=/")
                .map_err(|e| NucleusError::ExecError(format!("Invalid environment HOME: {}", e)))?,
        ];

        // Pass through sd_notify socket if enabled
        if self.config.sd_notify {
            if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET") {
                env.push(
                    CString::new(format!("NOTIFY_SOCKET={}", notify_socket)).map_err(|e| {
                        NucleusError::ExecError(format!("Invalid NOTIFY_SOCKET: {}", e))
                    })?,
                );
            }
        }

        // Append user-configured environment variables
        for (key, value) in &self.config.environment {
            env.push(CString::new(format!("{}={}", key, value)).map_err(|e| {
                NucleusError::ExecError(format!(
                    "Invalid environment variable {}={}: {}",
                    key, value, e
                ))
            })?);
        }

        nix::unistd::execve(&program, &args, &env)?;

        Ok(())
    }

    /// Run as a minimal PID 1 init process inside the container.
    ///
    /// Forks a child that execs the workload. PID 1 (this process) stays alive to:
    /// - Reap zombie processes (orphaned children)
    /// - Forward SIGTERM/SIGINT/SIGHUP to the workload child
    /// - Exit with the workload's exit code
    ///
    /// This prevents zombie accumulation in long-running production containers
    /// and ensures clean shutdown ordering.
    pub(super) fn run_as_init(&self) -> Result<()> {
        info!("Starting as PID 1 init supervisor (production mode)");
        audit(
            &self.config.id,
            &self.config.name,
            AuditEventType::InitSupervisorStarted,
            "PID 1 init supervisor for zombie reaping and signal forwarding",
        );

        Self::apply_process_identity_to_current_process(
            &self.config.process_identity,
            self.config.user_ns_config.is_some(),
        )?;

        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                // PID 1: mini-init — reap zombies and forward signals

                // Set up signal forwarding to the workload child
                let mut sigset = SigSet::empty();
                for sig in [
                    Signal::SIGTERM,
                    Signal::SIGINT,
                    Signal::SIGHUP,
                    Signal::SIGQUIT,
                    Signal::SIGUSR1,
                    Signal::SIGUSR2,
                ] {
                    sigset.add(sig);
                }

                // Block forwarded signals so we can use sigtimedwait
                pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&sigset), None).map_err(|e| {
                    NucleusError::ExecError(format!("Init: failed to block signals: {}", e))
                })?;

                // Spawn a thread to forward signals to the child
                let child_pid = child;
                let sig_thread = std::thread::spawn(move || {
                    while let Ok(signal) = sigset.wait() {
                        let _ = kill(child_pid, signal);
                    }
                });

                // Main loop: reap all children, exit when workload child exits
                let workload_exit = loop {
                    match waitpid(Pid::from_raw(-1), None) {
                        Ok(WaitStatus::Exited(pid, code)) => {
                            if pid == child {
                                debug!("Init: workload child exited with code {}", code);
                                break code;
                            }
                            debug!("Init: reaped zombie PID {} (exit code {})", pid, code);
                        }
                        Ok(WaitStatus::Signaled(pid, signal, _)) => {
                            if pid == child {
                                let code = 128 + signal as i32;
                                debug!(
                                    "Init: workload child killed by signal {:?} (exit code {})",
                                    signal, code
                                );
                                break code;
                            }
                            debug!("Init: reaped zombie PID {} (killed by {:?})", pid, signal);
                        }
                        Err(nix::errno::Errno::ECHILD) => {
                            // No more children — workload must have exited
                            debug!("Init: no more children, exiting");
                            break 1;
                        }
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(e) => {
                            error!("Init: waitpid error: {}", e);
                            break 1;
                        }
                        _ => continue,
                    }
                };

                // Drop the signal-forwarding thread cleanly before exiting.
                // It will unblock once there are no more signals to wait on.
                drop(sig_thread);
                std::process::exit(workload_exit);
            }
            ForkResult::Child => {
                // Workload child: exec the target command
                self.exec_command()?;
                // Should never reach here
                Ok(())
            }
        }
    }

    pub(super) fn enforce_no_new_privs(&self) -> Result<()> {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(NucleusError::ExecError(format!(
                "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}
