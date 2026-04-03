use crate::error::{NucleusError, Result};
use crate::isolation::{NamespaceCommandRunner, NamespaceProbe};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tracing::{debug, error, info, warn};

use super::runtime::Container;

impl Container {
    /// Run a readiness probe and, if sd_notify is active, send READY=1.
    pub(super) fn run_readiness_probe(
        pid: u32,
        container_name: &str,
        probe: &crate::container::ReadinessProbe,
        rootless: bool,
        using_gvisor: bool,
        notify_socket: Option<&str>,
    ) -> Result<()> {
        use crate::container::ReadinessProbe;

        info!("Running readiness probe for {}", container_name);

        let max_attempts = 60u32; // ~60s total with 1s sleep
        let poll_interval = std::time::Duration::from_secs(1);

        for attempt in 1..=max_attempts {
            // Check that the container is still alive using signal 0
            if kill(Pid::from_raw(pid as i32), None).is_err() {
                return Err(NucleusError::ExecError(format!(
                    "Container process {} exited before becoming ready",
                    pid
                )));
            }

            let ready = match probe {
                ReadinessProbe::Exec { command } => NamespaceCommandRunner::run(
                    pid,
                    rootless,
                    using_gvisor,
                    NamespaceProbe::Exec(command.clone()),
                    Some(std::time::Duration::from_secs(5)),
                )?,
                ReadinessProbe::TcpPort(port) => NamespaceCommandRunner::run(
                    pid,
                    rootless,
                    using_gvisor,
                    NamespaceProbe::TcpConnect(*port),
                    Some(std::time::Duration::from_secs(3)),
                )?,
                ReadinessProbe::SdNotify => {
                    // For SdNotify probe type, the container itself sends READY=1.
                    // We just pass through; the systemd integration handles it.
                    info!("Readiness probe is SdNotify; deferring to container process");
                    return Ok(());
                }
            };

            if ready {
                info!(
                    "Readiness probe passed for {} (attempt {})",
                    container_name, attempt
                );

                // Bridge to sd_notify if configured
                if let Some(socket_path) = notify_socket {
                    Self::send_sd_notify(socket_path, "READY=1")?;
                    info!("Sent READY=1 to sd_notify for {}", container_name);
                }

                return Ok(());
            }

            debug!(
                "Readiness probe attempt {}/{} failed for {}",
                attempt, max_attempts, container_name
            );
            std::thread::sleep(poll_interval);
        }

        Err(NucleusError::ExecError(format!(
            "Readiness probe timed out after {} attempts for {}",
            max_attempts, container_name
        )))
    }

    /// Send a notification to the systemd notify socket.
    pub(super) fn send_sd_notify(socket_path: &str, message: &str) -> Result<()> {
        use std::os::unix::net::UnixDatagram;

        let sock = UnixDatagram::unbound().map_err(|e| {
            NucleusError::ExecError(format!("Failed to create notify socket: {}", e))
        })?;
        sock.send_to(message.as_bytes(), socket_path).map_err(|e| {
            NucleusError::ExecError(format!(
                "Failed to send to notify socket {}: {}",
                socket_path, e
            ))
        })?;
        Ok(())
    }

    /// Run periodic health checks against the container via nsenter.
    pub(super) fn health_check_loop(
        pid: u32,
        container_name: &str,
        rootless: bool,
        using_gvisor: bool,
        hc: &crate::container::HealthCheck,
        cancel: &std::sync::atomic::AtomicBool,
    ) {
        // BUG-18: Use cancellable sleep so we exit promptly on container stop.
        let cancellable_sleep = |dur: std::time::Duration| -> bool {
            let step = std::time::Duration::from_millis(100);
            let start = std::time::Instant::now();
            while start.elapsed() < dur {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return true; // cancelled
                }
                std::thread::sleep(step.min(dur.saturating_sub(start.elapsed())));
            }
            cancel.load(std::sync::atomic::Ordering::Relaxed)
        };

        // Wait for start_period before beginning checks
        if cancellable_sleep(hc.start_period) {
            return;
        }

        let mut consecutive_failures: u32 = 0;

        loop {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                debug!("Health check: cancelled for {}", container_name);
                return;
            }

            // Check if the container process is still alive using signal 0
            if kill(Pid::from_raw(pid as i32), None).is_err() {
                debug!("Health check: container process {} gone, stopping", pid);
                return;
            }

            match NamespaceCommandRunner::run(
                pid,
                rootless,
                using_gvisor,
                NamespaceProbe::Exec(hc.command.clone()),
                Some(hc.timeout),
            ) {
                Ok(true) => {
                    if consecutive_failures > 0 {
                        info!(
                            "Health check passed for {} after {} failures",
                            container_name, consecutive_failures
                        );
                    }
                    consecutive_failures = 0;
                }
                Ok(false) => {
                    consecutive_failures += 1;
                    warn!(
                        "Health check failed for {} ({}/{})",
                        container_name, consecutive_failures, hc.retries
                    );

                    if consecutive_failures >= hc.retries {
                        error!(
                            "Container {} is unhealthy after {} consecutive failures",
                            container_name, consecutive_failures
                        );
                        // Signal the container to stop — the parent will handle cleanup
                        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                        return;
                    }
                }
                Err(e) => {
                    error!(
                        "Health check execution failed for {}: {}",
                        container_name, e
                    );
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                    return;
                }
            }

            if cancellable_sleep(hc.interval) {
                return;
            }
        }
    }
}
