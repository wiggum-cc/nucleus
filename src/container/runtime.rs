use crate::audit::{audit, audit_error, AuditEventType};
use crate::container::{
    ContainerConfig, ContainerState, ContainerStateManager, ContainerStateParams, OciStatus,
    ServiceMode,
};
use crate::error::{NucleusError, Result, StateTransition};
use crate::filesystem::{
    audit_mounts, bind_mount_host_paths, bind_mount_rootfs, create_dev_nodes, create_minimal_fs,
    mask_proc_paths, mount_procfs, mount_secrets, mount_secrets_inmemory, mount_volumes,
    snapshot_context_dir, switch_root, verify_context_manifest, verify_rootfs_attestation,
    FilesystemState, LazyContextPopulator, TmpfsMount,
};
use crate::isolation::NamespaceManager;
use crate::network::{BridgeNetwork, NetworkMode};
use crate::resources::Cgroup;
use crate::security::{
    CapabilityManager, GVisorRuntime, LandlockManager, OciContainerState, OciHooks, SeccompManager,
    SeccompTraceReader, SecurityState,
};
use nix::sys::signal::{kill, Signal};
use nix::sys::signal::{pthread_sigmask, SigSet, SigmaskHow};
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, pipe, read, write, ForkResult, Pid};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
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
    pub(super) config: ContainerConfig,
    /// Pre-resolved runsc path, resolved before fork so that user-namespace
    /// UID changes don't block PATH-based lookup.
    pub(super) runsc_path: Option<String>,
}

/// Handle returned by `Container::create()` representing a container whose
/// child process has been forked and is blocked on the exec FIFO, waiting for
/// `start()` to release it.
pub struct CreatedContainer {
    pub(super) config: ContainerConfig,
    pub(super) state_mgr: ContainerStateManager,
    pub(super) state: ContainerState,
    pub(super) child: Pid,
    pub(super) cgroup_opt: Option<Cgroup>,
    pub(super) bridge_net: Option<BridgeNetwork>,
    pub(super) trace_reader: Option<SeccompTraceReader>,
    pub(super) exec_fifo_path: Option<PathBuf>,
    pub(super) _lifecycle_span: tracing::Span,
}

impl Container {
    pub fn new(config: ContainerConfig) -> Self {
        Self {
            config,
            runsc_path: None,
        }
    }

    /// Run the container (convenience wrapper: create + start)
    pub fn run(&self) -> Result<i32> {
        self.create_internal(false)?.start()
    }

    /// Create phase: fork the child, set up cgroup/bridge, leave child blocked
    /// on the exec FIFO. Returns a `CreatedContainer` whose `start()` method
    /// releases the child process.
    pub fn create(&self) -> Result<CreatedContainer> {
        self.create_internal(true)
    }

    fn create_internal(&self, defer_exec_until_start: bool) -> Result<CreatedContainer> {
        let lifecycle_span = info_span!(
            "container.lifecycle",
            container.id = %self.config.id,
            container.name = %self.config.name,
            runtime = if self.config.use_gvisor { "gvisor" } else { "native" }
        );
        let _enter = lifecycle_span.enter();

        info!(
            "Creating container: {} (ID: {})",
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

        // Log console-socket acceptance (OCI interface; PTY forwarding is a future enhancement)
        if let Some(ref socket_path) = config.console_socket {
            warn!(
                "Console socket {} accepted but terminal forwarding is not yet implemented",
                socket_path.display()
            );
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
                     or remove the stale state with 'nucleus delete'",
                    config.name
                )));
            }
        }

        // Create exec FIFO only for the two-phase create/start lifecycle.
        // `run()` starts immediately and avoids this cross-root-path sync.
        let exec_fifo = if defer_exec_until_start {
            let exec_fifo = state_mgr.exec_fifo_path(&config.id)?;
            nix::unistd::mkfifo(&exec_fifo, Mode::S_IRUSR | Mode::S_IWUSR).map_err(|e| {
                NucleusError::ExecError(format!(
                    "Failed to create exec FIFO {:?}: {}",
                    exec_fifo, e
                ))
            })?;
            Some(exec_fifo)
        } else {
            None
        };

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

                // Use a closure so that on any error we kill the child process
                // instead of leaving it orphaned and blocked on the exec FIFO.
                let parent_setup = || -> Result<CreatedContainer> {
                    let target_pid = Self::wait_for_namespace_ready(&ready_read, child)?;

                    let cgroup_path = cgroup_opt
                        .as_ref()
                        .map(|_| format!("/sys/fs/cgroup/{}", cgroup_name));
                    let cpu_millicores = config
                        .limits
                        .cpu_quota_us
                        .map(|quota| {
                            quota.saturating_mul(1000) / config.limits.cpu_period_us
                        });
                    let mut state = ContainerState::new(ContainerStateParams {
                        id: config.id.clone(),
                        name: config.name.clone(),
                        pid: target_pid,
                        command: config.command.clone(),
                        memory_limit: config.limits.memory_bytes,
                        cpu_limit: cpu_millicores,
                        using_gvisor: config.use_gvisor,
                        rootless: config.user_ns_config.is_some(),
                        cgroup_path,
                        process_uid: config.process_identity.uid,
                        process_gid: config.process_identity.gid,
                        additional_gids: config.process_identity.additional_gids.clone(),
                    });
                    state.config_hash = config.config_hash;
                    state.bundle_path =
                        config.rootfs_path.as_ref().map(|p| p.display().to_string());

                    let mut bridge_net: Option<BridgeNetwork> = None;
                    let trace_reader =
                        Self::maybe_start_seccomp_trace_reader(&config, target_pid)?;

                    // Transition: Creating -> Created
                    state.status = OciStatus::Created;
                    state_mgr.save_state(&state)?;

                    // Write PID file (OCI --pid-file)
                    if let Some(ref pid_path) = config.pid_file {
                        std::fs::write(pid_path, target_pid.to_string()).map_err(|e| {
                            NucleusError::ConfigError(format!(
                                "Failed to write pid-file '{}': {}",
                                pid_path.display(),
                                e
                            ))
                        })?;
                        info!("Wrote PID {} to {}", target_pid, pid_path.display());
                    }

                    if let Some(ref mut cgroup) = cgroup_opt {
                        cgroup.attach_process(target_pid)?;
                    }

                    if let NetworkMode::Bridge(ref bridge_config) = config.network {
                        match BridgeNetwork::setup_with_id(
                            target_pid,
                            bridge_config,
                            &config.id,
                        ) {
                            Ok(net) => {
                                if let Some(ref egress) = config.egress_policy {
                                    if let Err(e) =
                                        net.apply_egress_policy(target_pid, egress)
                                    {
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

                    info!(
                        "Container {} created (child pid {}), waiting for start",
                        config.id, target_pid
                    );

                    Ok(CreatedContainer {
                        config,
                        state_mgr,
                        state,
                        child,
                        cgroup_opt,
                        bridge_net,
                        trace_reader,
                        exec_fifo_path: exec_fifo,
                        _lifecycle_span: lifecycle_span.clone(),
                    })
                };

                parent_setup().map_err(|e| {
                    // Kill the child so it doesn't remain orphaned and blocked
                    // on the exec FIFO.
                    let _ = kill(child, Signal::SIGKILL);
                    let _ = waitpid(child, None);
                    e
                })
            }
            ForkResult::Child => {
                drop(ready_read);
                let temp_container = Container { config, runsc_path };
                match temp_container.setup_and_exec(Some(ready_write), exec_fifo) {
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        error!("Container setup failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    /// Trigger a previously-created container to start by opening its exec FIFO.
    /// Used by the CLI `start` command.
    pub fn trigger_start(container_id: &str) -> Result<()> {
        let state_mgr = ContainerStateManager::new()?;
        let fifo_path = state_mgr.exec_fifo_path(container_id)?;
        if !fifo_path.exists() {
            return Err(NucleusError::ConfigError(format!(
                "No exec FIFO found for container {}; is it in 'created' state?",
                container_id
            )));
        }

        // Opening the FIFO for reading unblocks the child's open-for-write.
        let file = std::fs::File::open(&fifo_path)
            .map_err(|e| NucleusError::ExecError(format!("Failed to open exec FIFO: {}", e)))?;
        let mut buf = [0u8; 1];
        std::io::Read::read(&mut &file, &mut buf)
            .map_err(|e| NucleusError::ExecError(format!("Failed to read exec FIFO: {}", e)))?;
        drop(file);

        let _ = std::fs::remove_file(&fifo_path);

        // Update state to Running
        let mut state = state_mgr.resolve_container(container_id)?;
        state.status = OciStatus::Running;
        state_mgr.save_state(&state)?;

        Ok(())
    }

    /// Set up container environment and exec target process
    ///
    /// This runs in the child process after fork.
    /// Tracks FilesystemState and SecurityState machines to enforce correct ordering.
    fn setup_and_exec(
        &self,
        ready_pipe: Option<OwnedFd>,
        exec_fifo: Option<PathBuf>,
    ) -> Result<()> {
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

        // Namespace: Unshared -> Entered (process is now inside all namespaces)
        namespace_mgr.enter()?;

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

        // 7b. Mount persistent or ephemeral volumes over the base filesystem.
        mount_volumes(&container_root, &self.config.volumes)?;

        // 7c. Write resolv.conf for bridge networking.
        // When rootfs is mounted, /etc is read-only, so we bind-mount a writable
        // resolv.conf over the top (same technique as secrets).
        if let NetworkMode::Bridge(ref bridge_config) = self.config.network {
            if self.config.rootfs_path.is_some() {
                BridgeNetwork::bind_mount_resolv_conf(&container_root, &bridge_config.dns)?;
            } else {
                BridgeNetwork::write_resolv_conf(&container_root, &bridge_config.dns)?;
            }
        }

        // 7d. Mount secrets (in-memory tmpfs for production, bind-mount for agent mode)
        if self.config.service_mode == ServiceMode::Production {
            mount_secrets_inmemory(
                &container_root,
                &self.config.secrets,
                &self.config.process_identity,
            )?;
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
        mask_proc_paths(
            &proc_path,
            self.config.service_mode == ServiceMode::Production,
        )?;

        // 9c. Run createRuntime hooks (after namespaces created, before pivot_root)
        if let Some(ref hooks) = self.config.hooks {
            if !hooks.create_runtime.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: self.config.id.clone(),
                    status: OciStatus::Creating,
                    pid: std::process::id(),
                    bundle: String::new(),
                };
                OciHooks::run_hooks(&hooks.create_runtime, &hook_state, "createRuntime")?;
            }
        }

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

        // 10c. Run createContainer hooks (after pivot_root, before start)
        if let Some(ref hooks) = self.config.hooks {
            if !hooks.create_container.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: self.config.id.clone(),
                    status: OciStatus::Created,
                    pid: std::process::id(),
                    bundle: String::new(),
                };
                OciHooks::run_hooks(&hooks.create_container, &hook_state, "createContainer")?;
            }
        }

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

        // 12c. Verify that namespace-creating capabilities are truly gone before
        // installing seccomp. clone3 is allowed without argument filtering, so this
        // is the sole guard against namespace escape via clone3.
        CapabilityManager::verify_no_namespace_caps(
            self.config.service_mode == ServiceMode::Production,
        )?;

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

        // 14c. Block on exec FIFO until start() opens it for reading.
        // This implements the OCI two-phase create/start: all container setup
        // is complete, but the user process doesn't exec until explicitly started.
        if let Some(ref fifo_path) = exec_fifo {
            debug!("Waiting on exec FIFO {:?} for start signal", fifo_path);
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(fifo_path)
                .map_err(|e| {
                    NucleusError::ExecError(format!("Failed to open exec FIFO for writing: {}", e))
                })?;
            std::io::Write::write_all(&mut &file, &[0u8]).map_err(|e| {
                NucleusError::ExecError(format!("Failed to write exec FIFO sync byte: {}", e))
            })?;
            drop(file);
            debug!("Exec FIFO released, proceeding to exec");
        }

        // 14d. Run startContainer hooks (after start signal, before user process exec)
        if let Some(ref hooks) = self.config.hooks {
            if !hooks.start_container.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: self.config.id.clone(),
                    status: OciStatus::Running,
                    pid: std::process::id(),
                    bundle: String::new(),
                };
                OciHooks::run_hooks(&hooks.start_container, &hook_state, "startContainer")?;
            }
        }

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

    /// Forward selected signals to child process using sigwait (no async signal handlers).
    ///
    /// Returns a stop flag and join handle. Set the flag to `true` and join
    /// the handle to cleanly shut down the forwarding thread.
    pub(super) fn setup_signal_forwarding_static(
        child: Pid,
    ) -> Result<(Arc<AtomicBool>, JoinHandle<()>)> {
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

        let unblock_set = set;
        pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&unblock_set), None).map_err(|e| {
            NucleusError::ExecError(format!("Failed to block forwarded signals: {}", e))
        })?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let handle = std::thread::Builder::new()
            .name("sig-forward".to_string())
            .spawn(move || {
                // The thread owns unblock_set and uses it for sigwait.
                loop {
                    if let Ok(signal) = unblock_set.wait() {
                        // Check the stop flag *after* waking so that the
                        // wake-up signal (SIGUSR1) is not forwarded to the
                        // child during shutdown.
                        if stop_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        let _ = kill(child, signal);
                    }
                }
            })
            .map_err(|e| {
                // Restore the signal mask so the caller isn't left with
                // signals permanently blocked.
                let mut restore = SigSet::empty();
                for signal in [
                    Signal::SIGTERM,
                    Signal::SIGINT,
                    Signal::SIGHUP,
                    Signal::SIGQUIT,
                    Signal::SIGUSR1,
                    Signal::SIGUSR2,
                ] {
                    restore.add(signal);
                }
                let _ = pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&restore), None);
                NucleusError::ExecError(format!("Failed to spawn signal thread: {}", e))
            })?;

        info!("Signal forwarding configured");
        Ok((stop, handle))
    }

    /// Wait for child process to exit
    pub(super) fn wait_for_child_static(child: Pid) -> Result<i32> {
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
            match read(ready_read, &mut pid_buf) {
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
}

impl CreatedContainer {
    /// Start phase: release the child via the exec FIFO, transition to Running,
    /// then wait for the child to exit with full lifecycle management.
    pub fn start(mut self) -> Result<i32> {
        let config = &self.config;
        let _enter = self._lifecycle_span.enter();

        // Open the exec FIFO for reading — this unblocks the child's
        // blocking open-for-write, allowing it to proceed to exec.
        if let Some(exec_fifo_path) = &self.exec_fifo_path {
            let file = std::fs::File::open(exec_fifo_path).map_err(|e| {
                NucleusError::ExecError(format!("Failed to open exec FIFO for reading: {}", e))
            })?;
            let mut buf = [0u8; 1];
            let read = std::io::Read::read(&mut &file, &mut buf).map_err(|e| {
                NucleusError::ExecError(format!("Failed to read exec FIFO sync byte: {}", e))
            })?;
            if read != 1 {
                return Err(NucleusError::ExecError(
                    "Exec FIFO closed before start signal was delivered".to_string(),
                ));
            }
            let _ = std::fs::remove_file(exec_fifo_path);
        }

        // Transition: Created -> Running
        self.state.status = OciStatus::Running;
        self.state_mgr.save_state(&self.state)?;

        let target_pid = self.state.pid;
        let child = self.child;

        let (sig_stop, sig_handle) =
            Container::setup_signal_forwarding_static(Pid::from_raw(target_pid as i32))?;

        // Guard ensures signal thread is stopped on any exit path (including early ? returns).
        let mut sig_guard = SignalThreadGuard {
            stop: Some(sig_stop),
            handle: Some(sig_handle),
        };

        // Run readiness probe before declaring service ready
        if let Some(ref probe) = config.readiness_probe {
            let notify_socket = if config.sd_notify {
                std::env::var("NOTIFY_SOCKET").ok()
            } else {
                None
            };
            Container::run_readiness_probe(
                target_pid,
                &config.name,
                probe,
                config.user_ns_config.is_some(),
                config.use_gvisor,
                &config.process_identity,
                notify_socket.as_deref(),
            )?;
        }

        // Start health check thread if configured
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let health_handle = if let Some(ref hc) = config.health_check {
            if !hc.command.is_empty() {
                let hc = hc.clone();
                let pid = target_pid;
                let container_name = config.name.clone();
                let rootless = config.user_ns_config.is_some();
                let using_gvisor = config.use_gvisor;
                let process_identity = config.process_identity.clone();
                let cancel = cancel_flag.clone();
                Some(std::thread::spawn(move || {
                    Container::health_check_loop(
                        pid,
                        &container_name,
                        rootless,
                        using_gvisor,
                        &hc,
                        &process_identity,
                        &cancel,
                    );
                }))
            } else {
                None
            }
        } else {
            None
        };

        // Guard ensures health check thread is cancelled on any exit path.
        let mut health_guard = HealthThreadGuard {
            cancel: Some(cancel_flag),
            handle: health_handle,
        };

        // Run poststart hooks (after user process started, in parent)
        if let Some(ref hooks) = config.hooks {
            if !hooks.poststart.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: config.id.clone(),
                    status: OciStatus::Running,
                    pid: target_pid,
                    bundle: String::new(),
                };
                OciHooks::run_hooks(&hooks.poststart, &hook_state, "poststart")?;
            }
        }

        let mut child_waited = false;
        let run_result: Result<i32> = (|| {
            let exit_code = Container::wait_for_child_static(child)?;

            // Transition: Running -> Stopped
            self.state.status = OciStatus::Stopped;
            let _ = self.state_mgr.save_state(&self.state);

            child_waited = true;
            Ok(exit_code)
        })();

        // Explicitly stop threads (guards would do this on drop too, but
        // explicit teardown keeps ordering visible).
        health_guard.stop();
        sig_guard.stop();

        // Run poststop hooks (best-effort)
        if let Some(ref hooks) = config.hooks {
            if !hooks.poststop.is_empty() {
                let hook_state = OciContainerState {
                    oci_version: "1.0.2".to_string(),
                    id: config.id.clone(),
                    status: OciStatus::Stopped,
                    pid: 0,
                    bundle: String::new(),
                };
                OciHooks::run_hooks_best_effort(&hooks.poststop, &hook_state, "poststop");
            }
        }

        if let Some(net) = self.bridge_net.take() {
            if let Err(e) = net.cleanup() {
                warn!("Failed to cleanup bridge networking: {}", e);
            }
        }

        if !child_waited {
            let _ = kill(child, Signal::SIGKILL);
            let _ = waitpid(child, None);
        }

        if let Some(reader) = self.trace_reader.take() {
            reader.stop_and_flush();
        }

        if let Some(cgroup) = self.cgroup_opt.take() {
            if let Err(e) = cgroup.cleanup() {
                warn!("Failed to cleanup cgroup: {}", e);
            }
        }

        if config.use_gvisor {
            if let Err(e) = Container::cleanup_gvisor_artifacts(&config.id) {
                warn!(
                    "Failed to cleanup gVisor artifacts for {}: {}",
                    config.id, e
                );
            }
        }

        if let Err(e) = self.state_mgr.delete_state(&config.id) {
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
}

/// RAII guard that stops the signal-forwarding thread on drop.
struct SignalThreadGuard {
    stop: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
}

impl SignalThreadGuard {
    fn stop(&mut self) {
        if let Some(flag) = self.stop.take() {
            flag.store(true, Ordering::Relaxed);
            // Unblock the sigwait() call so the thread can observe the stop flag.
            let _ = kill(Pid::this(), Signal::SIGUSR1);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SignalThreadGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// RAII guard that cancels the health-check thread on drop.
struct HealthThreadGuard {
    cancel: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
}

impl HealthThreadGuard {
    fn stop(&mut self) {
        if let Some(flag) = self.cancel.take() {
            flag.store(true, Ordering::Relaxed);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for HealthThreadGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::KernelLockdownMode;
    use crate::network::NetworkMode;

    #[test]
    fn test_container_config() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert!(!config.id.is_empty());
        assert_eq!(config.command, vec!["/bin/sh"]);
        assert!(config.use_gvisor);
    }

    #[test]
    fn test_run_uses_immediate_start_path() {
        let source = include_str!("runtime.rs");
        let fn_start = source.find("pub fn run(&self) -> Result<i32>").unwrap();
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
        let run_body = &after[..fn_end];
        assert!(
            run_body.contains("create_internal(false)"),
            "run() must bypass deferred exec FIFO startup to avoid cross-root deadlocks"
        );
        assert!(
            !run_body.contains("self.create()?.start()"),
            "run() must not route through create()+start()"
        );
    }

    #[test]
    fn test_container_config_with_name() {
        let config =
            ContainerConfig::try_new(Some("mycontainer".to_string()), vec!["/bin/sh".to_string()])
                .unwrap();
        assert_eq!(config.name, "mycontainer");
        assert!(!config.id.is_empty());
        assert_ne!(config.id, config.name);
    }

    #[test]
    fn test_allow_degraded_security_requires_explicit_config() {
        let strict = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        assert!(!Container::allow_degraded_security(&strict));

        let relaxed = strict.clone().with_allow_degraded_security(true);
        assert!(Container::allow_degraded_security(&relaxed));
    }

    #[test]
    fn test_env_var_cannot_force_degraded_security_without_explicit_opt_in() {
        let prev = std::env::var_os("NUCLEUS_ALLOW_DEGRADED_SECURITY");
        std::env::set_var("NUCLEUS_ALLOW_DEGRADED_SECURITY", "1");

        let strict = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
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
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::Host)
            .with_allow_host_network(false);
        let err = Container::apply_network_mode_guards(&mut config, true).unwrap_err();
        assert!(matches!(err, NucleusError::NetworkError(_)));
    }

    #[test]
    fn test_host_network_opt_in_disables_net_namespace() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
            .with_network(NetworkMode::Host)
            .with_allow_host_network(true);
        assert!(config.namespaces.net);
        Container::apply_network_mode_guards(&mut config, true).unwrap();
        assert!(!config.namespaces.net);
    }

    #[test]
    fn test_non_host_network_does_not_require_host_opt_in() {
        let mut config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()])
            .unwrap()
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
            &crate::container::ProcessIdentity::root(),
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
        // Function lives in health.rs after the runtime split.
        let source = include_str!("health.rs");
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
        // Both functions live in health.rs after the runtime split.
        let source = include_str!("health.rs");

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
        // Function lives in gvisor_setup.rs after the runtime split.
        let source = include_str!("gvisor_setup.rs");
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
            fn_body.contains("written")
                || fn_body.contains("4")
                || fn_body.contains("payload.len()"),
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
            rlimit_section.contains("is_production") && rlimit_section.contains("return Err"),
            "RLIMIT failures must return Err in production mode"
        );
    }

    #[test]
    fn test_tcp_readiness_probe_uses_portable_check() {
        // BUG-14: TCP readiness probe must not use /dev/tcp (bash-only)
        // Function lives in health.rs after the runtime split.
        let source = include_str!("health.rs");
        let probe_fn = source.find("TcpPort(port)").unwrap();
        let probe_body = &source[probe_fn..probe_fn + 500];
        assert!(
            !probe_body.contains("/dev/tcp"),
            "TCP readiness probe must not use /dev/tcp (bash-specific, fails on dash/ash)"
        );
    }
}
