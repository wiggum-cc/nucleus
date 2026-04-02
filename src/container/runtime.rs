use crate::audit::{audit, audit_error, AuditEventType};
use crate::container::{
    ContainerConfig, ContainerState, ContainerStateManager, KernelLockdownMode, ServiceMode,
    TrustLevel,
};
use crate::error::{NucleusError, Result};
use crate::filesystem::{
    audit_mounts, bind_mount_host_paths, bind_mount_rootfs, create_dev_nodes, create_minimal_fs,
    mask_proc_paths, mount_procfs, mount_secrets, mount_secrets_inmemory, snapshot_context_dir,
    switch_root, verify_context_manifest, verify_rootfs_attestation, ContextPopulator,
    FilesystemState, LazyContextPopulator, TmpfsMount, resolve_container_destination,
};
use crate::isolation::{NamespaceCommandRunner, NamespaceManager, NamespaceProbe};
use crate::network::{BridgeNetwork, NetworkMode};
use crate::resources::Cgroup;
use crate::security::{
    seccomp_trace::SeccompTraceReader, CapabilityManager, GVisorNetworkMode, GVisorRuntime,
    LandlockManager, OciBundle, OciConfig, OciMount, SeccompManager, SecurityState,
};
use nix::sys::signal::{kill, Signal};
use nix::sys::signal::{pthread_sigmask, SigSet, SigmaskHow};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, pipe, read, write, ForkResult, Pid};
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use tempfile::Builder;
use tracing::{debug, error, info, info_span, warn};

/// Container runtime that orchestrates all isolation mechanisms
///
/// Execution flow matches the formal specifications:
/// 1. Create namespaces (Nucleus_Isolation_NamespaceLifecycle.tla)
/// 2. Create and configure cgroups (Nucleus_Resources_CgroupLifecycle.tla)
/// 3. Mount tmpfs and populate context (Nucleus_Filesystem_FilesystemLifecycle.tla)
/// 4. Drop capabilities and apply seccomp (Nucleus_Security_SecurityEnforcement.tla)
/// 5. Execute target process
pub struct Container {
    config: ContainerConfig,
    /// Pre-resolved runsc path, resolved before fork so that user-namespace
    /// UID changes don't block PATH-based lookup.
    runsc_path: Option<String>,
}

impl Container {
    pub fn new(config: ContainerConfig) -> Self {
        Self {
            config,
            runsc_path: None,
        }
    }

    /// Run the container
    ///
    /// This orchestrates all components according to the formal specifications
    pub fn run(&self) -> Result<i32> {
        let lifecycle_span = info_span!(
            "container.lifecycle",
            container.id = %self.config.id,
            container.name = %self.config.name,
            runtime = if self.config.use_gvisor { "gvisor" } else { "native" }
        );
        let _enter = lifecycle_span.enter();

        info!(
            "Starting container: {} (ID: {})",
            self.config.name, self.config.id
        );
        audit(
            &self.config.id,
            &self.config.name,
            AuditEventType::ContainerStart,
            format!(
                "command={:?} mode={:?} runtime={}",
                self.config.command,
                self.config.service_mode,
                if self.config.use_gvisor {
                    "gvisor"
                } else {
                    "native"
                }
            ),
        );

        // Auto-detect if we need rootless mode
        let is_root = nix::unistd::Uid::effective().is_root();
        let mut config = self.config.clone();

        if !is_root && config.user_ns_config.is_none() {
            info!("Not running as root, automatically enabling rootless mode");
            config.namespaces.user = true;
            config.user_ns_config = Some(crate::isolation::UserNamespaceConfig::rootless());
        }

        // Validate production mode invariants before anything else.
        config.validate_production_mode()?;
        Self::assert_kernel_lockdown(&config)?;

        Self::apply_network_mode_guards(&mut config, is_root)?;
        Self::apply_trust_level_guards(&mut config)?;
        config.validate_runtime_support()?;

        // Bridge networking requires root
        if matches!(config.network, NetworkMode::Bridge(_)) && !is_root {
            if config.service_mode == ServiceMode::Production {
                return Err(NucleusError::NetworkError(
                    "Production mode with bridge networking requires root (cannot silently \
                     degrade to no networking)"
                        .to_string(),
                ));
            }
            warn!("Bridge networking requires root, degrading to no networking");
            config.network = NetworkMode::None;
        }

        // Create state manager
        let state_mgr = ContainerStateManager::new()?;

        // Enforce name uniqueness among running containers
        if let Ok(all_states) = state_mgr.list_states() {
            if all_states.iter().any(|s| s.name == config.name) {
                return Err(NucleusError::ConfigError(format!(
                    "A container named '{}' already exists; use a different --name, \
                     or remove the stale state with 'nucleus rm'",
                    config.name
                )));
            }
        }

        // Try to create cgroup (optional for rootless mode)
        let cgroup_name = format!("nucleus-{}", config.id);
        let mut cgroup_opt = match Cgroup::create(&cgroup_name) {
            Ok(mut cgroup) => {
                // Try to set limits
                match cgroup.set_limits(&config.limits) {
                    Ok(_) => {
                        info!("Created cgroup with resource limits");
                        Some(cgroup)
                    }
                    Err(e) => {
                        if config.service_mode == ServiceMode::Production {
                            let _ = cgroup.cleanup();
                            return Err(NucleusError::CgroupError(format!(
                                "Production mode requires cgroup resource enforcement, but \
                                 applying limits failed: {}",
                                e
                            )));
                        }
                        warn!("Failed to set cgroup limits: {}", e);
                        // Cleanup the cgroup we created
                        let _ = cgroup.cleanup();
                        None
                    }
                }
            }
            Err(e) => {
                if config.service_mode == ServiceMode::Production {
                    return Err(NucleusError::CgroupError(format!(
                        "Production mode requires cgroup resource enforcement, but \
                         cgroup creation failed: {}",
                        e
                    )));
                }

                if config.user_ns_config.is_some() {
                    if config.limits.memory_bytes.is_some()
                        || config.limits.cpu_quota_us.is_some()
                        || config.limits.pids_max.is_some()
                    {
                        warn!(
                            "Running in rootless mode: requested resource limits cannot be \
                             enforced – cgroup creation requires root ({})",
                            e
                        );
                    } else {
                        debug!("Running in rootless mode without cgroup resource limits");
                    }
                } else {
                    warn!(
                        "Failed to create cgroup (running without resource limits): {}",
                        e
                    );
                }
                None
            }
        };

        // Resolve runsc path before fork, while still unprivileged.
        // After user-namespace unshare the child appears as UID 0, which blocks
        // PATH-based lookup as a security measure.
        let runsc_path = if config.use_gvisor {
            Some(GVisorRuntime::resolve_path().map_err(|e| {
                NucleusError::GVisorError(format!("Failed to resolve runsc path: {}", e))
            })?)
        } else {
            None
        };

        // Child notifies parent after namespaces are ready.
        let (ready_read, ready_write) = pipe().map_err(|e| {
            NucleusError::ExecError(format!("Failed to create namespace sync pipe: {}", e))
        })?;

        // Fork child process
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                drop(ready_write);
                info!("Forked child process: {}", child);

                let target_pid = Self::wait_for_namespace_ready(&ready_read, child)?;

                let cgroup_path = cgroup_opt
                    .as_ref()
                    .map(|_| format!("/sys/fs/cgroup/{}", cgroup_name));
                let cpu_millicores = config
                    .limits
                    .cpu_quota_us
                    .map(|quota| (quota * 1000) / config.limits.cpu_period_us);
                let mut state = ContainerState::new(
                    config.id.clone(),
                    config.name.clone(),
                    target_pid,
                    config.command.clone(),
                    config.limits.memory_bytes,
                    cpu_millicores,
                    config.use_gvisor,
                    config.user_ns_config.is_some(),
                    cgroup_path,
                );
                state.config_hash = config.config_hash;

                let mut bridge_net: Option<BridgeNetwork> = None;
                let mut child_waited = false;
                let mut trace_reader = Self::maybe_start_seccomp_trace_reader(&config, target_pid)?;
                let run_result: Result<i32> = (|| {
                    state_mgr.save_state(&state)?;

                    if let Some(ref mut cgroup) = cgroup_opt {
                        cgroup.attach_process(target_pid)?;
                    }

                    if let NetworkMode::Bridge(ref bridge_config) = config.network {
                        match BridgeNetwork::setup_with_id(target_pid, bridge_config, &config.id) {
                            Ok(net) => {
                                // Apply egress policy if configured
                                if let Some(ref egress) = config.egress_policy {
                                    if let Err(e) = net.apply_egress_policy(target_pid, egress) {
                                        if config.service_mode == ServiceMode::Production {
                                            return Err(NucleusError::NetworkError(format!(
                                                "Failed to apply egress policy: {}",
                                                e
                                            )));
                                        }
                                        warn!("Failed to apply egress policy: {}", e);
                                    }
                                }
                                bridge_net = Some(net);
                            }
                            Err(e) => {
                                if config.service_mode == ServiceMode::Production {
                                    return Err(e);
                                }
                                warn!("Failed to set up bridge networking: {}", e);
                            }
                        }
                    }

                    self.setup_signal_forwarding(Pid::from_raw(target_pid as i32))?;

                    // Run readiness probe before declaring service ready
                    if let Some(ref probe) = config.readiness_probe {
                        let notify_socket = if config.sd_notify {
                            std::env::var("NOTIFY_SOCKET").ok()
                        } else {
                            None
                        };
                        Self::run_readiness_probe(
                            target_pid,
                            &config.name,
                            probe,
                            config.user_ns_config.is_some(),
                            config.use_gvisor,
                            notify_socket.as_deref(),
                        )?;
                    }

                    // Start health check thread if configured
                    // BUG-18: Use an AtomicBool cancellation flag so the health
                    // check thread exits promptly when the container stops.
                    let cancel_flag = std::sync::Arc::new(
                        std::sync::atomic::AtomicBool::new(false),
                    );
                    let health_handle = if let Some(ref hc) = config.health_check {
                        if !hc.command.is_empty() {
                            let hc = hc.clone();
                            let pid = target_pid;
                            let container_name = config.name.clone();
                            let rootless = config.user_ns_config.is_some();
                            let using_gvisor = config.use_gvisor;
                            let cancel = cancel_flag.clone();
                            Some(std::thread::spawn(move || {
                                Self::health_check_loop(
                                    pid,
                                    &container_name,
                                    rootless,
                                    using_gvisor,
                                    &hc,
                                    &cancel,
                                );
                            }))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let exit_code = self.wait_for_child(child)?;

                    // Signal the health check thread to stop and wait for it
                    cancel_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    if let Some(handle) = health_handle {
                        let _ = handle.join();
                    }
                    child_waited = true;
                    Ok(exit_code)
                })();

                if let Some(net) = bridge_net {
                    if let Err(e) = net.cleanup() {
                        warn!("Failed to cleanup bridge networking: {}", e);
                    }
                }

                if !child_waited {
                    let _ = kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                }

                if let Some(reader) = trace_reader.take() {
                    reader.stop_and_flush();
                }

                if let Some(cgroup) = cgroup_opt {
                    if let Err(e) = cgroup.cleanup() {
                        warn!("Failed to cleanup cgroup: {}", e);
                    }
                }

                if config.use_gvisor {
                    if let Err(e) = Self::cleanup_gvisor_artifacts(&config.id) {
                        warn!(
                            "Failed to cleanup gVisor artifacts for {}: {}",
                            config.id, e
                        );
                    }
                }

                if let Err(e) = state_mgr.delete_state(&config.id) {
                    warn!("Failed to delete state for {}: {}", config.id, e);
                }

                match run_result {
                    Ok(exit_code) => {
                        audit(
                            &config.id,
                            &config.name,
                            AuditEventType::ContainerStop,
                            format!("exit_code={}", exit_code),
                        );
                        info!(
                            "Container {} ({}) exited with code {}",
                            config.name, config.id, exit_code
                        );
                        Ok(exit_code)
                    }
                    Err(e) => {
                        audit_error(
                            &config.id,
                            &config.name,
                            AuditEventType::ContainerStop,
                            format!("error={}", e),
                        );
                        Err(e)
                    }
                }
            }
            ForkResult::Child => {
                drop(ready_read);
                // Child process - set up container environment
                let temp_container = Container { config, runsc_path };
                match temp_container.setup_and_exec(Some(ready_write)) {
                    Ok(_) => {
                        unreachable!()
                    }
                    Err(e) => {
                        error!("Container setup failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    /// Set up container environment and exec target process
    ///
    /// This runs in the child process after fork.
    /// Tracks FilesystemState and SecurityState machines to enforce correct ordering.
    fn setup_and_exec(&self, ready_pipe: Option<OwnedFd>) -> Result<()> {
        let is_rootless = self.config.user_ns_config.is_some();
        let allow_degraded_security = Self::allow_degraded_security(&self.config);
        let context_manifest = if self.config.verify_context_integrity {
            self.config
                .context_dir
                .as_ref()
                .map(|dir| snapshot_context_dir(dir))
                .transpose()?
        } else {
            None
        };

        // Initialize state machines
        let mut fs_state = FilesystemState::Unmounted;
        let mut sec_state = SecurityState::Privileged;

        // gVisor is the runtime that should create the container's namespaces.
        // Running runsc after pre-unsharing our own namespaces breaks its gofer
        // re-exec path on some systems and duplicates the OCI namespace config.
        if self.config.use_gvisor {
            if let Some(fd) = ready_pipe {
                Self::notify_namespace_ready(&fd, std::process::id())?;
            }
            return self.setup_and_exec_gvisor();
        }

        // 1. Create namespaces in child and optionally configure user mapping.
        let mut namespace_mgr = NamespaceManager::new(self.config.namespaces.clone());
        if let Some(user_config) = &self.config.user_ns_config {
            namespace_mgr = namespace_mgr.with_user_mapping(user_config.clone());
        }
        namespace_mgr.unshare_namespaces()?;

        // CLONE_NEWPID only applies to children created after unshare().
        // Create a child that will become PID 1 in the new namespace and exec the workload.
        if self.config.namespaces.pid {
            match unsafe { fork() }? {
                ForkResult::Parent { child } => {
                    if let Some(fd) = ready_pipe {
                        Self::notify_namespace_ready(&fd, child.as_raw() as u32)?;
                    }
                    std::process::exit(Self::wait_for_pid_namespace_child(child));
                }
                ForkResult::Child => {
                    // Continue container setup as PID 1 in the new namespace.
                }
            }
        } else if let Some(fd) = ready_pipe {
            Self::notify_namespace_ready(&fd, std::process::id())?;
        }

        // 2. Ensure no_new_privs BEFORE any mount operations.
        // This prevents exploitation of setuid binaries on bind-mounted paths
        // even if a subsequent MS_NOSUID remount fails.
        self.enforce_no_new_privs()?;
        audit(
            &self.config.id,
            &self.config.name,
            AuditEventType::NoNewPrivsSet,
            "prctl(PR_SET_NO_NEW_PRIVS, 1) applied (early, before mounts)",
        );

        // 3. Set hostname if UTS namespace is enabled
        if let Some(hostname) = &self.config.hostname {
            namespace_mgr.set_hostname(hostname)?;
        }

        // 4. Mount tmpfs as container root
        // Filesystem: Unmounted -> Mounted
        let runtime_dir = Builder::new()
            .prefix("nucleus-runtime-")
            .tempdir_in("/tmp")
            .map_err(|e| {
                NucleusError::FilesystemError(format!("Failed to create runtime dir: {}", e))
            })?;
        let container_root = runtime_dir.path().to_path_buf();
        let mut tmpfs = TmpfsMount::new(&container_root, Some(1024 * 1024 * 1024)); // 1GB default
        tmpfs.mount()?;
        fs_state = fs_state.transition(FilesystemState::Mounted)?;

        // 4. Create minimal filesystem structure
        create_minimal_fs(&container_root)?;

        // 5. Create device nodes
        let dev_path = container_root.join("dev");
        create_dev_nodes(&dev_path, false)?;

        // 6. Populate context if provided
        // Filesystem: Mounted -> Populated
        if let Some(context_dir) = &self.config.context_dir {
            let context_dest = container_root.join("context");
            LazyContextPopulator::populate(&self.config.context_mode, context_dir, &context_dest)?;
            if let Some(expected) = &context_manifest {
                verify_context_manifest(expected, &context_dest)?;
            }
        }
        fs_state = fs_state.transition(FilesystemState::Populated)?;

        // 7. Mount runtime paths: either a pre-built rootfs or host bind mounts
        if let Some(ref rootfs_path) = self.config.rootfs_path {
            if self.config.verify_rootfs_attestation {
                verify_rootfs_attestation(rootfs_path)?;
            }
            bind_mount_rootfs(&container_root, rootfs_path)?;
        } else {
            bind_mount_host_paths(&container_root, is_rootless)?;
        }

        // 7b. Write resolv.conf for bridge networking.
        // When rootfs is mounted, /etc is read-only, so we bind-mount a writable
        // resolv.conf over the top (same technique as secrets).
        if let NetworkMode::Bridge(ref bridge_config) = self.config.network {
            if self.config.rootfs_path.is_some() {
                BridgeNetwork::bind_mount_resolv_conf(&container_root, &bridge_config.dns)?;
            } else {
                BridgeNetwork::write_resolv_conf(&container_root, &bridge_config.dns)?;
            }
        }

        // 7c. Mount secrets (in-memory tmpfs for production, bind-mount for agent mode)
        if self.config.service_mode == ServiceMode::Production {
            mount_secrets_inmemory(&container_root, &self.config.secrets)?;
        } else {
            mount_secrets(&container_root, &self.config.secrets)?;
        }

        // 8. Mount procfs (hidepid=2 in production mode to prevent PID enumeration)
        let proc_path = container_root.join("proc");
        let hide_pids = self.config.service_mode == ServiceMode::Production;
        mount_procfs(
            &proc_path,
            is_rootless,
            self.config.proc_readonly,
            hide_pids,
        )?;

        // 8b. Mask sensitive /proc paths to reduce kernel info leakage
        // SEC-06: In production mode, failures to mask critical paths are fatal.
        mask_proc_paths(&proc_path, self.config.service_mode == ServiceMode::Production)?;

        // 10. Switch root filesystem
        // Filesystem: Populated -> Pivoted
        switch_root(&container_root, self.config.allow_chroot_fallback)?;
        fs_state = fs_state.transition(FilesystemState::Pivoted)?;
        debug!("Filesystem state: {:?}", fs_state);

        // 10b. Audit mount flags to verify filesystem hardening invariants
        audit_mounts(self.config.service_mode == ServiceMode::Production)?;
        audit(
            &self.config.id,
            &self.config.name,
            AuditEventType::MountAuditPassed,
            "all mount flags verified",
        );

        // 11. Drop capabilities (from policy file or default drop-all)
        // Security: Privileged -> CapabilitiesDropped
        let mut cap_mgr = CapabilityManager::new();
        if let Some(ref policy_path) = self.config.caps_policy {
            let policy: crate::security::CapsPolicy = crate::security::load_toml_policy(
                policy_path,
                self.config.caps_policy_sha256.as_deref(),
            )?;
            policy.apply(&mut cap_mgr)?;
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::CapabilitiesDropped,
                format!("capability policy applied from {:?}", policy_path),
            );
        } else {
            cap_mgr.drop_all()?;
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::CapabilitiesDropped,
                "all capabilities dropped including bounding set",
            );
        }
        sec_state = sec_state.transition(SecurityState::CapabilitiesDropped)?;

        // 12b. RLIMIT backstop: defense-in-depth against fork bombs and fd exhaustion.
        // Must be applied BEFORE seccomp, since SYS_setrlimit is not in the allowlist.
        // SEC-05: In production mode, RLIMIT failures are fatal — a container
        // without resource limits is a privilege escalation vector.
        {
            let is_production = self.config.service_mode == ServiceMode::Production;

            let nproc_limit = self.config.limits.pids_max.unwrap_or(512);
            let rlim_nproc = libc::rlimit {
                rlim_cur: nproc_limit,
                rlim_max: nproc_limit,
            };
            // SAFETY: setrlimit is a standard POSIX call with no memory safety concerns.
            if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlim_nproc) } != 0 {
                let err = std::io::Error::last_os_error();
                if is_production {
                    return Err(NucleusError::SeccompError(format!(
                        "Failed to set RLIMIT_NPROC to {} in production mode: {}",
                        nproc_limit, err
                    )));
                }
                warn!("Failed to set RLIMIT_NPROC to {}: {}", nproc_limit, err);
            }

            let rlim_nofile = libc::rlimit {
                rlim_cur: 1024,
                rlim_max: 1024,
            };
            // SAFETY: setrlimit is a standard POSIX call with no memory safety concerns.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim_nofile) } != 0 {
                let err = std::io::Error::last_os_error();
                if is_production {
                    return Err(NucleusError::SeccompError(format!(
                        "Failed to set RLIMIT_NOFILE to 1024 in production mode: {}",
                        err
                    )));
                }
                warn!("Failed to set RLIMIT_NOFILE to 1024: {}", err);
            }

            // RLIMIT_MEMLOCK: prevent container from pinning excessive physical
            // memory via mlock(). Default 64KB matches unprivileged default, but
            // in a user namespace the container appears as UID 0 and may have a
            // higher inherited limit.
            let memlock_limit: u64 = 64 * 1024; // 64KB
            let rlim_memlock = libc::rlimit {
                rlim_cur: memlock_limit,
                rlim_max: memlock_limit,
            };
            // SAFETY: setrlimit is a standard POSIX call with no memory safety concerns.
            if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim_memlock) } != 0 {
                let err = std::io::Error::last_os_error();
                if is_production {
                    return Err(NucleusError::SeccompError(format!(
                        "Failed to set RLIMIT_MEMLOCK to {} in production mode: {}",
                        memlock_limit, err
                    )));
                }
                warn!("Failed to set RLIMIT_MEMLOCK to {}: {}", memlock_limit, err);
            }
        }

        // 13. Apply seccomp filter (trace, profile-from-file, or built-in allowlist)
        // Security: CapabilitiesDropped -> SeccompApplied
        use crate::container::config::SeccompMode;
        let mut seccomp_mgr = SeccompManager::new();
        let allow_network = !matches!(self.config.network, NetworkMode::None);
        let seccomp_applied = match self.config.seccomp_mode {
            SeccompMode::Trace => {
                audit(
                    &self.config.id,
                    &self.config.name,
                    AuditEventType::SeccompApplied,
                    "seccomp trace mode: allow-all + LOG",
                );
                seccomp_mgr.apply_trace_filter()?
            }
            SeccompMode::Enforce => {
                if let Some(ref profile_path) = self.config.seccomp_profile {
                    audit(
                        &self.config.id,
                        &self.config.name,
                        AuditEventType::SeccompProfileLoaded,
                        format!("path={:?}", profile_path),
                    );
                    seccomp_mgr.apply_profile_from_file(
                        profile_path,
                        self.config.seccomp_profile_sha256.as_deref(),
                        self.config.seccomp_log_denied,
                    )?
                } else {
                    seccomp_mgr.apply_filter_for_network_mode(
                        allow_network,
                        allow_degraded_security,
                        self.config.seccomp_log_denied,
                    )?
                }
            }
        };
        if seccomp_applied {
            sec_state = sec_state.transition(SecurityState::SeccompApplied)?;
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::SeccompApplied,
                format!("network={}", allow_network),
            );
        } else if !allow_degraded_security {
            return Err(NucleusError::SeccompError(
                "Seccomp filter is required but was not enforced".to_string(),
            ));
        } else {
            warn!("Seccomp not enforced; container is running with degraded hardening");
        }

        // 14. Apply Landlock policy (from policy file or default hardcoded rules)
        let landlock_applied = if let Some(ref policy_path) = self.config.landlock_policy {
            let policy: crate::security::LandlockPolicy = crate::security::load_toml_policy(
                policy_path,
                self.config.landlock_policy_sha256.as_deref(),
            )?;
            policy.apply(allow_degraded_security)?
        } else {
            let mut landlock_mgr = LandlockManager::new();
            landlock_mgr.assert_minimum_abi(self.config.service_mode == ServiceMode::Production)?;
            landlock_mgr.apply_container_policy_with_mode(allow_degraded_security)?
        };
        if seccomp_applied && landlock_applied {
            sec_state = sec_state.transition(SecurityState::LandlockApplied)?;
            if self.config.seccomp_mode == SeccompMode::Trace {
                warn!("Security state NOT locked: seccomp in trace mode (allow-all)");
            } else {
                sec_state = sec_state.transition(SecurityState::Locked)?;
            }
            audit(
                &self.config.id,
                &self.config.name,
                AuditEventType::LandlockApplied,
                if self.config.seccomp_mode == SeccompMode::Trace {
                    "landlock applied, but seccomp in trace mode — not locked".to_string()
                } else {
                    "security state locked: all hardening layers active".to_string()
                },
            );
        } else if !allow_degraded_security {
            return Err(NucleusError::LandlockError(
                "Landlock policy is required but was not enforced".to_string(),
            ));
        } else {
            warn!("Security state not locked; one or more hardening controls are inactive");
        }
        debug!("Security state: {:?}", sec_state);

        // 15. In production mode with PID namespace, run as a mini-init (PID 1)
        // that reaps zombies and forwards signals, rather than exec-ing directly.
        if self.config.service_mode == ServiceMode::Production && self.config.namespaces.pid {
            return self.run_as_init();
        }

        // 15b. Agent mode: exec target process directly
        self.exec_command()?;

        // Should never reach here
        Ok(())
    }

    /// Set up container with gVisor and exec
    fn setup_and_exec_gvisor(&self) -> Result<()> {
        info!("Using gVisor runtime");

        let gvisor = if let Some(ref path) = self.runsc_path {
            GVisorRuntime::with_path(path.clone())
        } else {
            GVisorRuntime::new().map_err(|e| {
                NucleusError::GVisorError(format!("Failed to initialize gVisor runtime: {}", e))
            })?
        };

        self.setup_and_exec_gvisor_oci(&gvisor)
    }

    /// Set up container with gVisor using OCI bundle format
    fn setup_and_exec_gvisor_oci(&self, gvisor: &GVisorRuntime) -> Result<()> {
        info!("Using gVisor with OCI bundle format");

        let mut oci_config =
            OciConfig::new(self.config.command.clone(), self.config.hostname.clone());
        let context_manifest = if self.config.verify_context_integrity {
            self.config
                .context_dir
                .as_ref()
                .map(|dir| snapshot_context_dir(dir))
                .transpose()?
        } else {
            None
        };

        oci_config = oci_config.with_resources(&self.config.limits);
        oci_config = oci_config.with_namespace_config(&self.config.namespaces);

        // Inject user-configured environment variables
        if !self.config.environment.is_empty() {
            oci_config = oci_config.with_env(&self.config.environment);
        }

        // Pass through sd_notify socket
        if self.config.sd_notify {
            oci_config = oci_config.with_sd_notify();
        }

        // Mount pre-built rootfs if provided
        if let Some(ref rootfs_path) = self.config.rootfs_path {
            if self.config.verify_rootfs_attestation {
                verify_rootfs_attestation(rootfs_path)?;
            }
            oci_config = oci_config.with_rootfs_binds(rootfs_path);
        } else {
            oci_config = oci_config.with_host_runtime_binds();
        }

        if let Some(context_dir) = &self.config.context_dir {
            if matches!(
                self.config.context_mode,
                crate::filesystem::ContextMode::BindMount
            ) {
                ContextPopulator::new(context_dir, "/context").validate_source_tree()?;
                oci_config = oci_config.with_context_bind(context_dir);
            }
        }

        if !self.config.secrets.is_empty() && self.config.service_mode == ServiceMode::Production {
            let secret_stage_dir = Self::gvisor_secret_stage_dir(&self.config.id);
            Self::mount_gvisor_secret_stage_tmpfs(&secret_stage_dir)?;
            let staged_secrets =
                Self::stage_gvisor_secret_files(&secret_stage_dir, &self.config.secrets)?;
            oci_config =
                oci_config.with_inmemory_secret_mounts(&secret_stage_dir, &staged_secrets)?;
        } else if !self.config.secrets.is_empty() {
            oci_config = oci_config.with_secret_mounts(&self.config.secrets);
        }

        if let Some(user_ns_config) = &self.config.user_ns_config {
            oci_config = oci_config.with_rootless_user_namespace(user_ns_config);
        }

        let artifact_dir = Self::gvisor_artifact_dir(&self.config.id);
        std::fs::create_dir_all(&artifact_dir).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create gVisor artifact dir {:?}: {}",
                artifact_dir, e
            ))
        })?;
        let bundle_path = Self::gvisor_bundle_path(&self.config.id);
        let oci_mounts = oci_config.mounts.clone();
        let bundle = OciBundle::new(bundle_path, oci_config);
        bundle.create()?;

        let rootfs = bundle.rootfs_path();
        create_minimal_fs(&rootfs)?;
        Self::prepare_oci_mountpoints(&rootfs, &oci_mounts)?;
        if let Some(context_dir) = &self.config.context_dir {
            if matches!(
                self.config.context_mode,
                crate::filesystem::ContextMode::Copy
            ) {
                let context_dest = rootfs.join("context");
                ContextPopulator::new(context_dir, &context_dest).populate()?;
                if let Some(expected) = &context_manifest {
                    verify_context_manifest(expected, &context_dest)?;
                }
            }
        }

        let dev_path = rootfs.join("dev");
        create_dev_nodes(&dev_path, false)?;

        // Write resolv.conf for bridge networking into the OCI rootfs
        if let NetworkMode::Bridge(ref bridge_config) = self.config.network {
            BridgeNetwork::write_resolv_conf(&rootfs, &bridge_config.dns)?;
        }

        // Select gVisor network mode based on container network config
        let gvisor_net = match &self.config.network {
            NetworkMode::None => GVisorNetworkMode::None,
            NetworkMode::Host => GVisorNetworkMode::Host,
            NetworkMode::Bridge(_) => GVisorNetworkMode::Sandbox,
        };

        let rootless_oci = self.config.user_ns_config.is_some();
        gvisor.exec_with_oci_bundle_network(
            &self.config.id,
            &bundle,
            gvisor_net,
            rootless_oci,
            self.config.gvisor_platform,
        )?;

        Ok(())
    }

    fn prepare_oci_mountpoints(rootfs: &std::path::Path, mounts: &[OciMount]) -> Result<()> {
        for mount in mounts {
            let normalized = crate::filesystem::normalize_container_destination(
                std::path::Path::new(&mount.destination),
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Invalid OCI mount destination {:?}: {}",
                    mount.destination, e
                ))
            })?;
            let relative = normalized.strip_prefix("/").map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to convert OCI mount destination {:?} into a rootfs-relative path: {}",
                    normalized, e
                ))
            })?;
            let target = rootfs.join(relative);
            if mount.mount_type == "bind" && std::path::Path::new(&mount.source).is_file() {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create OCI mount parent {:?}: {}",
                            parent, e
                        ))
                    })?;
                }
                if !target.exists() {
                    std::fs::File::create(&target).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create OCI mount target {:?}: {}",
                            target, e
                        ))
                    })?;
                }
            } else {
                std::fs::create_dir_all(&target).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create OCI mount target {:?}: {}",
                        target, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    fn gvisor_artifact_dir(container_id: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join("nucleus-gvisor")
            .join(container_id)
    }

    fn gvisor_bundle_path(container_id: &str) -> std::path::PathBuf {
        Self::gvisor_artifact_dir(container_id).join("bundle")
    }

    fn gvisor_secret_stage_dir(container_id: &str) -> std::path::PathBuf {
        Self::gvisor_artifact_dir(container_id).join("secrets-stage")
    }

    fn mount_gvisor_secret_stage_tmpfs(stage_dir: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(stage_dir).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create gVisor secret stage dir {:?}: {}",
                stage_dir, e
            ))
        })?;

        nix::mount::mount(
            Some("tmpfs"),
            stage_dir,
            Some("tmpfs"),
            nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV
                | nix::mount::MsFlags::MS_NOEXEC,
            Some("size=16m,mode=0700"),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to mount gVisor secret stage tmpfs at {:?}: {}",
                stage_dir, e
            ))
        })
    }

    fn stage_gvisor_secret_files(
        stage_dir: &std::path::Path,
        secrets: &[crate::container::SecretMount],
    ) -> Result<Vec<crate::container::SecretMount>> {
        let mut staged = Vec::with_capacity(secrets.len());

        for secret in secrets {
            if !secret.source.exists() {
                return Err(NucleusError::FilesystemError(format!(
                    "Secret source does not exist: {:?}",
                    secret.source
                )));
            }

            let staged_source = resolve_container_destination(stage_dir, &secret.dest)?;
            if let Some(parent) = staged_source.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create gVisor secret parent {:?}: {}",
                        parent, e
                    ))
                })?;
            }

            let mut content = std::fs::read(&secret.source).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to read secret {:?}: {}",
                    secret.source, e
                ))
            })?;
            std::fs::write(&staged_source, &content).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to write staged secret {:?}: {}",
                    staged_source, e
                ))
            })?;

            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &staged_source,
                    std::fs::Permissions::from_mode(secret.mode),
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to set permissions on staged secret {:?}: {}",
                        staged_source, e
                    ))
                })?;
            }

            zeroize::Zeroize::zeroize(&mut content);

            staged.push(crate::container::SecretMount {
                source: staged_source,
                dest: secret.dest.clone(),
                mode: secret.mode,
            });
        }

        Ok(staged)
    }

    fn cleanup_gvisor_artifacts(container_id: &str) -> Result<()> {
        let artifact_dir = Self::gvisor_artifact_dir(container_id);
        let secret_stage_dir = Self::gvisor_secret_stage_dir(container_id);

        if secret_stage_dir.exists() {
            match nix::mount::umount2(&secret_stage_dir, nix::mount::MntFlags::MNT_DETACH) {
                Ok(()) => {}
                Err(nix::errno::Errno::EINVAL) | Err(nix::errno::Errno::ENOENT) => {}
                Err(e) => {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to unmount gVisor secret stage {:?}: {}",
                        secret_stage_dir, e
                    )));
                }
            }
        }

        if artifact_dir.exists() {
            std::fs::remove_dir_all(&artifact_dir).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to remove gVisor artifact dir {:?}: {}",
                    artifact_dir, e
                ))
            })?;
        }

        Ok(())
    }

    /// Execute the target command
    fn exec_command(&self) -> Result<()> {
        if self.config.command.is_empty() {
            return Err(NucleusError::ExecError("No command specified".to_string()));
        }

        info!("Executing command: {:?}", self.config.command);

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
    fn run_as_init(&self) -> Result<()> {
        info!("Starting as PID 1 init supervisor (production mode)");
        audit(
            &self.config.id,
            &self.config.name,
            AuditEventType::InitSupervisorStarted,
            "PID 1 init supervisor for zombie reaping and signal forwarding",
        );

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
                std::thread::spawn(move || {
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

    fn enforce_no_new_privs(&self) -> Result<()> {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(NucleusError::ExecError(format!(
                "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn assert_kernel_lockdown(config: &ContainerConfig) -> Result<()> {
        let Some(required) = config.required_kernel_lockdown else {
            return Ok(());
        };

        let path = "/sys/kernel/security/lockdown";
        let content = std::fs::read_to_string(path).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Kernel lockdown assertion requested, but {} could not be read: {}",
                path, e
            ))
        })?;

        let active = Self::parse_active_lockdown_mode(&content).ok_or_else(|| {
            NucleusError::ConfigError(format!(
                "Kernel lockdown assertion requested, but active mode could not be parsed from {}",
                path
            ))
        })?;

        if required.accepts(active) {
            info!(
                required = required.as_str(),
                active = active.as_str(),
                "Kernel lockdown requirement satisfied"
            );
            Ok(())
        } else {
            Err(NucleusError::ConfigError(format!(
                "Kernel lockdown mode '{}' does not satisfy required mode '{}'",
                active.as_str(),
                required.as_str()
            )))
        }
    }

    fn parse_active_lockdown_mode(content: &str) -> Option<KernelLockdownMode> {
        let start = content.find('[')?;
        let end = content[start + 1..].find(']')?;
        match &content[start + 1..start + 1 + end] {
            "integrity" => Some(KernelLockdownMode::Integrity),
            "confidentiality" => Some(KernelLockdownMode::Confidentiality),
            _ => None,
        }
    }

    /// Forward selected signals to child process using sigwait (no async signal handlers).
    fn setup_signal_forwarding(&self, child: Pid) -> Result<()> {
        let mut set = SigSet::empty();
        for signal in [
            Signal::SIGTERM,
            Signal::SIGINT,
            Signal::SIGHUP,
            Signal::SIGQUIT,
            Signal::SIGUSR1,
            Signal::SIGUSR2,
        ] {
            set.add(signal);
        }

        pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&set), None).map_err(|e| {
            NucleusError::ExecError(format!("Failed to block forwarded signals: {}", e))
        })?;

        std::thread::spawn(move || {
            while let Ok(signal) = set.wait() {
                let _ = kill(child, signal);
            }
        });

        info!("Signal forwarding configured");
        Ok(())
    }

    /// Wait for child process to exit
    fn wait_for_child(&self, child: Pid) -> Result<i32> {
        loop {
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code)) => {
                    return Ok(code);
                }
                Ok(WaitStatus::Signaled(_, signal, _)) => {
                    info!("Child killed by signal: {:?}", signal);
                    return Ok(128 + signal as i32);
                }
                Err(nix::errno::Errno::EINTR) => {
                    continue;
                }
                Err(e) => {
                    return Err(NucleusError::ExecError(format!(
                        "Failed to wait for child: {}",
                        e
                    )));
                }
                _ => {
                    continue;
                }
            }
        }
    }

    fn wait_for_namespace_ready(ready_read: &OwnedFd, child: Pid) -> Result<u32> {
        let mut pid_buf = [0u8; 4];
        loop {
            match read(ready_read.as_raw_fd(), &mut pid_buf) {
                Err(nix::errno::Errno::EINTR) => continue,
                Ok(4) => return Ok(u32::from_ne_bytes(pid_buf)),
                Ok(0) => {
                    return Err(NucleusError::ExecError(format!(
                        "Child {} exited before namespace initialization",
                        child
                    )))
                }
                Ok(_) => {
                    return Err(NucleusError::ExecError(
                        "Invalid namespace sync payload from child".to_string(),
                    ))
                }
                Err(e) => {
                    return Err(NucleusError::ExecError(format!(
                        "Failed waiting for child namespace setup: {}",
                        e
                    )))
                }
            }
        }
    }

    fn notify_namespace_ready(fd: &OwnedFd, pid: u32) -> Result<()> {
        let payload = pid.to_ne_bytes();
        let mut written = 0;
        while written < payload.len() {
            let n = write(fd, &payload[written..]).map_err(|e| {
                NucleusError::ExecError(format!("Failed to notify namespace readiness: {}", e))
            })?;
            if n == 0 {
                return Err(NucleusError::ExecError(
                    "Failed to notify namespace readiness: short write".to_string(),
                ));
            }
            written += n;
        }
        Ok(())
    }

    fn wait_for_pid_namespace_child(child: Pid) -> i32 {
        loop {
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code)) => return code,
                Ok(WaitStatus::Signaled(_, signal, _)) => return 128 + signal as i32,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => return 1,
                _ => continue,
            }
        }
    }

    /// Run a readiness probe and, if sd_notify is active, send READY=1.
    fn run_readiness_probe(
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
            // Check that the container is still alive
            let proc_path = format!("/proc/{}", pid);
            if !std::path::Path::new(&proc_path).exists() {
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
    fn send_sd_notify(socket_path: &str, message: &str) -> Result<()> {
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
    fn health_check_loop(
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

            // Check if the container process is still alive
            let proc_path = format!("/proc/{}", pid);
            if !std::path::Path::new(&proc_path).exists() {
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
                    error!("Health check execution failed for {}: {}", container_name, e);
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                    return;
                }
            }

            if cancellable_sleep(hc.interval) {
                return;
            }
        }
    }

    fn allow_degraded_security(config: &ContainerConfig) -> bool {
        if std::env::var("NUCLEUS_ALLOW_DEGRADED_SECURITY")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
            && !config.allow_degraded_security
        {
            warn!(
                "Ignoring NUCLEUS_ALLOW_DEGRADED_SECURITY environment variable; use \
                 --allow-degraded-security for explicit opt-in"
            );
        }
        config.allow_degraded_security
    }

    fn apply_trust_level_guards(config: &mut ContainerConfig) -> Result<()> {
        match config.trust_level {
            TrustLevel::Trusted => Ok(()),
            TrustLevel::Untrusted => {
                // Untrusted workloads must never use host networking
                if matches!(config.network, NetworkMode::Host) {
                    return Err(NucleusError::ConfigError(
                        "Untrusted workloads cannot use host network mode. \
                         Set --trust-level trusted to override."
                            .to_string(),
                    ));
                }

                if !config.use_gvisor {
                    if GVisorRuntime::is_available() {
                        info!(
                            "Untrusted workload: auto-enabling gVisor runtime \
                             (runsc detected on PATH)"
                        );
                        config.use_gvisor = true;
                    } else if config.allow_degraded_security {
                        warn!(
                            "Untrusted workload without gVisor: running with \
                             degraded isolation (native kernel only). \
                             Install runsc for full protection."
                        );
                    } else {
                        return Err(NucleusError::ConfigError(
                            "Untrusted workloads require gVisor (runsc). \
                             Install runsc: https://gvisor.dev/docs/user_guide/install/ \
                             — or pass --allow-degraded-security to run with native \
                             kernel isolation only, or --trust-level trusted to skip \
                             this check."
                                .to_string(),
                        ));
                    }
                }

                Ok(())
            }
        }
    }

    fn apply_network_mode_guards(config: &mut ContainerConfig, _is_root: bool) -> Result<()> {
        if let NetworkMode::Host = &config.network {
            if !config.allow_host_network {
                return Err(NucleusError::NetworkError(
                    "Host network mode requires explicit opt-in: pass --allow-host-network"
                        .to_string(),
                ));
            }
            warn!(
                "Host network mode enabled: container shares host network namespace and can \
                 access localhost services, scan LAN-reachable endpoints, and bypass network \
                 namespace isolation"
            );
            info!("Host network mode: skipping network namespace");
            config.namespaces.net = false;
        }
        Ok(())
    }

    fn maybe_start_seccomp_trace_reader(
        config: &ContainerConfig,
        target_pid: u32,
    ) -> Result<Option<SeccompTraceReader>> {
        if config.seccomp_mode != crate::container::config::SeccompMode::Trace {
            return Ok(None);
        }

        let log_path = config.seccomp_trace_log.as_ref().ok_or_else(|| {
            NucleusError::ConfigError(
                "Seccomp trace mode requires --seccomp-log / seccomp_trace_log".to_string(),
            )
        })?;

        let mut reader = SeccompTraceReader::new(target_pid, log_path);
        reader.start_recording()?;
        Ok(Some(reader))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkMode;

    #[test]
    fn test_container_config() {
        let config = ContainerConfig::new(None, vec!["/bin/sh".to_string()]);
        assert!(!config.id.is_empty());
        assert_eq!(config.command, vec!["/bin/sh"]);
        assert!(config.use_gvisor);
    }

    #[test]
    fn test_container_config_with_name() {
        let config =
            ContainerConfig::new(Some("mycontainer".to_string()), vec!["/bin/sh".to_string()]);
        assert_eq!(config.name, "mycontainer");
        assert!(!config.id.is_empty());
        assert_ne!(config.id, config.name);
    }

    #[test]
    fn test_allow_degraded_security_requires_explicit_config() {
        let strict = ContainerConfig::new(None, vec!["/bin/sh".to_string()]);
        assert!(!Container::allow_degraded_security(&strict));

        let relaxed = strict.clone().with_allow_degraded_security(true);
        assert!(Container::allow_degraded_security(&relaxed));
    }

    #[test]
    fn test_env_var_cannot_force_degraded_security_without_explicit_opt_in() {
        let prev = std::env::var_os("NUCLEUS_ALLOW_DEGRADED_SECURITY");
        std::env::set_var("NUCLEUS_ALLOW_DEGRADED_SECURITY", "1");

        let strict = ContainerConfig::new(None, vec!["/bin/sh".to_string()]);
        assert!(!Container::allow_degraded_security(&strict));

        let explicit = strict.with_allow_degraded_security(true);
        assert!(Container::allow_degraded_security(&explicit));

        match prev {
            Some(v) => std::env::set_var("NUCLEUS_ALLOW_DEGRADED_SECURITY", v),
            None => std::env::remove_var("NUCLEUS_ALLOW_DEGRADED_SECURITY"),
        }
    }

    #[test]
    fn test_host_network_requires_explicit_opt_in() {
        let mut config = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_network(NetworkMode::Host)
            .with_allow_host_network(false);
        let err = Container::apply_network_mode_guards(&mut config, true).unwrap_err();
        assert!(matches!(err, NucleusError::NetworkError(_)));
    }

    #[test]
    fn test_host_network_opt_in_disables_net_namespace() {
        let mut config = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_network(NetworkMode::Host)
            .with_allow_host_network(true);
        assert!(config.namespaces.net);
        Container::apply_network_mode_guards(&mut config, true).unwrap();
        assert!(!config.namespaces.net);
    }

    #[test]
    fn test_non_host_network_does_not_require_host_opt_in() {
        let mut config = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_network(NetworkMode::None)
            .with_allow_host_network(false);
        assert!(config.namespaces.net);
        Container::apply_network_mode_guards(&mut config, true).unwrap();
        assert!(config.namespaces.net);
    }

    #[test]
    fn test_parse_kernel_lockdown_mode() {
        assert_eq!(
            Container::parse_active_lockdown_mode("none [integrity] confidentiality"),
            Some(KernelLockdownMode::Integrity)
        );
        assert_eq!(
            Container::parse_active_lockdown_mode("none integrity [confidentiality]"),
            Some(KernelLockdownMode::Confidentiality)
        );
        assert_eq!(
            Container::parse_active_lockdown_mode("[none] integrity"),
            None
        );
    }

    #[test]
    fn test_stage_gvisor_secret_files_rewrites_sources_under_stage_dir() {
        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("source-secret");
        std::fs::write(&source, "supersecret").unwrap();

        let staged = Container::stage_gvisor_secret_files(
            &temp.path().join("stage"),
            &[crate::container::SecretMount {
                source: source.clone(),
                dest: std::path::PathBuf::from("/etc/app/secret.txt"),
                mode: 0o400,
            }],
        )
        .unwrap();

        assert_eq!(staged.len(), 1);
        assert!(staged[0].source.starts_with(temp.path().join("stage")));
        assert_eq!(
            std::fs::read_to_string(&staged[0].source).unwrap(),
            "supersecret"
        );
    }

    #[test]
    fn test_cleanup_gvisor_artifacts_removes_artifact_dir() {
        let artifact_dir = Container::gvisor_artifact_dir("cleanup-test");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(artifact_dir.join("config.json"), "{}").unwrap();

        Container::cleanup_gvisor_artifacts("cleanup-test").unwrap();
        assert!(!artifact_dir.exists());
    }

    #[test]
    fn test_health_check_loop_supports_cancellation() {
        // BUG-18: health_check_loop must accept an AtomicBool cancel flag
        // and check it between iterations for prompt shutdown.
        let source = include_str!("runtime.rs");
        let fn_start = source.find("fn health_check_loop").unwrap();
        let fn_body = &source[fn_start..fn_start + 2500];
        assert!(
            fn_body.contains("AtomicBool") && fn_body.contains("cancel"),
            "health_check_loop must accept an AtomicBool cancellation flag"
        );
        // Must also check cancellation during sleep
        assert!(
            fn_body.contains("cancellable_sleep") || fn_body.contains("cancel.load"),
            "health_check_loop must check cancellation during sleep intervals"
        );
    }

    #[test]
    fn test_runtime_probes_do_not_spawn_host_nsenter() {
        let source = include_str!("runtime.rs");

        let readiness_start = source.find("fn run_readiness_probe").unwrap();
        let readiness_body = &source[readiness_start..readiness_start + 2500];
        assert!(
            !readiness_body.contains("Command::new(&nsenter_bin)"),
            "readiness probes must not execute via host nsenter"
        );

        let health_start = source.find("fn health_check_loop").unwrap();
        let health_body = &source[health_start..health_start + 2200];
        assert!(
            !health_body.contains("Command::new(&nsenter_bin)"),
            "health checks must not execute via host nsenter"
        );
    }

    #[test]
    fn test_oci_mount_strip_prefix_no_expect() {
        // BUG-08: prepare_oci_mountpoints must not use expect() - use ? instead
        let source = include_str!("runtime.rs");
        let fn_start = source.find("fn prepare_oci_mountpoints").unwrap();
        let fn_body = &source[fn_start..fn_start + 600];
        assert!(
            !fn_body.contains(".expect("),
            "prepare_oci_mountpoints must not use expect() — return Err instead"
        );
    }

    #[test]
    fn test_notify_namespace_ready_validates_write_length() {
        // BUG-02: notify_namespace_ready must validate that all bytes were written
        let source = include_str!("runtime.rs");
        let fn_start = source.find("fn notify_namespace_ready").unwrap();
        let fn_body = &source[fn_start..fn_start + 500];
        // Must check the return value of write() for partial writes
        assert!(
            fn_body.contains("written") || fn_body.contains("4") || fn_body.contains("payload.len()"),
            "notify_namespace_ready must validate complete write of all 4 bytes"
        );
    }

    #[test]
    fn test_rlimit_failures_fatal_in_production() {
        // SEC-05: RLIMIT failures must be fatal in production mode
        let source = include_str!("runtime.rs");
        let rlimit_start = source.find("12b. RLIMIT backstop").unwrap();
        let rlimit_section = &source[rlimit_start..rlimit_start + 2000];
        assert!(
            rlimit_section.contains("is_production")
                && rlimit_section.contains("return Err"),
            "RLIMIT failures must return Err in production mode"
        );
    }

    #[test]
    fn test_tcp_readiness_probe_uses_portable_check() {
        // BUG-14: TCP readiness probe must not use /dev/tcp (bash-only)
        let source = include_str!("runtime.rs");
        let probe_fn = source.find("TcpPort(port)").unwrap();
        let probe_body = &source[probe_fn..probe_fn + 500];
        assert!(
            !probe_body.contains("/dev/tcp"),
            "TCP readiness probe must not use /dev/tcp (bash-specific, fails on dash/ash)"
        );
    }
}
