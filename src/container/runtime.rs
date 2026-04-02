use crate::container::{
    ContainerConfig, ContainerState, ContainerStateManager, ServiceMode, TrustLevel,
};
use crate::error::{NucleusError, Result};
use crate::filesystem::{
    bind_mount_host_paths, bind_mount_rootfs, create_dev_nodes, create_minimal_fs, mask_proc_paths,
    mount_procfs, mount_secrets, switch_root, ContextPopulator, FilesystemState,
    LazyContextPopulator, TmpfsMount,
};
use crate::isolation::NamespaceManager;
use crate::network::{BridgeNetwork, NetworkMode};
use crate::resources::Cgroup;
use crate::security::{
    CapabilityManager, GVisorNetworkMode, GVisorRuntime, LandlockManager, OciBundle, OciConfig,
    SeccompManager, SecurityState,
};
use nix::sys::signal::{kill, Signal};
use nix::sys::signal::{pthread_sigmask, SigSet, SigmaskHow};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, pipe, read, write, ForkResult, Pid};
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use tempfile::Builder;
use tracing::{debug, error, info, warn};

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
}

impl Container {
    pub fn new(config: ContainerConfig) -> Self {
        Self { config }
    }

    /// Run the container
    ///
    /// This orchestrates all components according to the formal specifications
    pub fn run(&self) -> Result<i32> {
        info!(
            "Starting container: {} (ID: {})",
            self.config.name, self.config.id
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

        Self::apply_network_mode_guards(&mut config, is_root)?;
        Self::apply_trust_level_guards(&mut config)?;

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
                let state = ContainerState::new(
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

                let mut bridge_net: Option<BridgeNetwork> = None;
                let mut child_waited = false;
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
                            notify_socket.as_deref(),
                        )?;
                    }

                    // Start health check thread if configured
                    if let Some(ref hc) = config.health_check {
                        if !hc.command.is_empty() {
                            let hc = hc.clone();
                            let pid = target_pid;
                            let container_name = config.name.clone();
                            std::thread::spawn(move || {
                                Self::health_check_loop(pid, &container_name, &hc);
                            });
                        }
                    }

                    let exit_code = self.wait_for_child(child)?;
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

                if let Some(cgroup) = cgroup_opt {
                    if let Err(e) = cgroup.cleanup() {
                        warn!("Failed to cleanup cgroup: {}", e);
                    }
                }

                if let Err(e) = state_mgr.delete_state(&config.id) {
                    warn!("Failed to delete state for {}: {}", config.id, e);
                }

                match run_result {
                    Ok(exit_code) => {
                        info!(
                            "Container {} ({}) exited with code {}",
                            config.name, config.id, exit_code
                        );
                        Ok(exit_code)
                    }
                    Err(e) => Err(e),
                }
            }
            ForkResult::Child => {
                drop(ready_read);
                // Child process - set up container environment
                let temp_container = Container { config };
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

        // Initialize state machines
        let mut fs_state = FilesystemState::Unmounted;
        let mut sec_state = SecurityState::Privileged;

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

        // 2. Set hostname if UTS namespace is enabled
        if let Some(hostname) = &self.config.hostname {
            namespace_mgr.set_hostname(hostname)?;
        }

        // gVisor flow uses OCI/runsc instead of native mount/isolation path.
        if self.config.use_gvisor {
            return self.setup_and_exec_gvisor();
        }

        // 3. Mount tmpfs as container root
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
        }
        fs_state = fs_state.transition(FilesystemState::Populated)?;

        // 7. Mount runtime paths: either a pre-built rootfs or host bind mounts
        if let Some(ref rootfs_path) = self.config.rootfs_path {
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

        // 7c. Mount secrets
        mount_secrets(&container_root, &self.config.secrets)?;

        // 8. Mount procfs
        let proc_path = container_root.join("proc");
        mount_procfs(&proc_path, is_rootless, self.config.proc_readonly)?;

        // 8b. Mask sensitive /proc paths to reduce kernel info leakage
        mask_proc_paths(&proc_path)?;

        // 10. Switch root filesystem
        // Filesystem: Populated -> Pivoted
        switch_root(&container_root, self.config.allow_chroot_fallback)?;
        fs_state = fs_state.transition(FilesystemState::Pivoted)?;
        debug!("Filesystem state: {:?}", fs_state);

        // 11. Ensure no_new_privs before applying additional hardening.
        self.enforce_no_new_privs()?;

        // 12. Drop capabilities
        // Security: Privileged -> CapabilitiesDropped
        let mut cap_mgr = CapabilityManager::new();
        cap_mgr.drop_all()?;
        sec_state = sec_state.transition(SecurityState::CapabilitiesDropped)?;

        // 12b. RLIMIT backstop: defense-in-depth against fork bombs and fd exhaustion.
        // Must be applied BEFORE seccomp, since SYS_setrlimit is not in the allowlist.
        {
            let nproc_limit = self.config.limits.pids_max.unwrap_or(512);
            let rlim_nproc = libc::rlimit {
                rlim_cur: nproc_limit,
                rlim_max: nproc_limit,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlim_nproc) } != 0 {
                warn!(
                    "Failed to set RLIMIT_NPROC to {}: {}",
                    nproc_limit,
                    std::io::Error::last_os_error()
                );
            }

            let rlim_nofile = libc::rlimit {
                rlim_cur: 1024,
                rlim_max: 1024,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim_nofile) } != 0 {
                warn!(
                    "Failed to set RLIMIT_NOFILE to 1024: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // 13. Apply seccomp filter
        // Security: CapabilitiesDropped -> SeccompApplied
        let mut seccomp_mgr = SeccompManager::new();
        let allow_network = !matches!(self.config.network, NetworkMode::None);
        let seccomp_applied =
            seccomp_mgr.apply_filter_for_network_mode(allow_network, allow_degraded_security)?;
        if seccomp_applied {
            sec_state = sec_state.transition(SecurityState::SeccompApplied)?;
        } else if !allow_degraded_security {
            return Err(NucleusError::SeccompError(
                "Seccomp filter is required but was not enforced".to_string(),
            ));
        } else {
            warn!("Seccomp not enforced; container is running with degraded hardening");
        }

        // 14. Apply Landlock filesystem policy
        let mut landlock_mgr = LandlockManager::new();
        let landlock_applied =
            landlock_mgr.apply_container_policy_with_mode(allow_degraded_security)?;
        if seccomp_applied && landlock_applied {
            sec_state = sec_state.transition(SecurityState::LandlockApplied)?;
            sec_state = sec_state.transition(SecurityState::Locked)?;
        } else if !allow_degraded_security {
            return Err(NucleusError::LandlockError(
                "Landlock policy is required but was not enforced".to_string(),
            ));
        } else {
            warn!("Security state not locked; one or more hardening controls are inactive");
        }
        debug!("Security state: {:?}", sec_state);

        // 15. Exec target process
        self.exec_command()?;

        // Should never reach here
        Ok(())
    }

    /// Set up container with gVisor and exec
    fn setup_and_exec_gvisor(&self) -> Result<()> {
        info!("Using gVisor runtime");

        let gvisor = GVisorRuntime::new().map_err(|e| {
            NucleusError::GVisorError(format!("Failed to initialize gVisor runtime: {}", e))
        })?;

        self.setup_and_exec_gvisor_oci(&gvisor)
    }

    /// Set up container with gVisor using OCI bundle format
    fn setup_and_exec_gvisor_oci(&self, gvisor: &GVisorRuntime) -> Result<()> {
        info!("Using gVisor with OCI bundle format");

        let mut oci_config =
            OciConfig::new(self.config.command.clone(), self.config.hostname.clone());

        oci_config = oci_config.with_resources(&self.config.limits);

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
            oci_config = oci_config.with_rootfs_binds(rootfs_path);
        }

        // Mount secrets into OCI bundle
        if !self.config.secrets.is_empty() {
            oci_config = oci_config.with_secret_mounts(&self.config.secrets);
        }

        if self.config.user_ns_config.is_some() {
            oci_config = oci_config.with_user_namespace();
        }

        let bundle_dir = Builder::new()
            .prefix("nucleus-oci-")
            .tempdir_in("/tmp")
            .map_err(|e| {
                NucleusError::FilesystemError(format!("Failed to create OCI bundle dir: {}", e))
            })?;
        let bundle_path = bundle_dir.path().to_path_buf();
        let bundle = OciBundle::new(bundle_path, oci_config);
        bundle.create()?;

        let rootfs = bundle.rootfs_path();
        create_minimal_fs(&rootfs)?;

        let dev_path = rootfs.join("dev");
        create_dev_nodes(&dev_path, false)?;

        if let Some(context_dir) = &self.config.context_dir {
            let context_dest = rootfs.join("context");
            let populator = ContextPopulator::new(context_dir, &context_dest);
            populator.populate()?;
        }

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

        gvisor.exec_with_oci_bundle_network(&self.config.id, &bundle, gvisor_net)?;

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
                NucleusError::ExecError(format!("Invalid environment variable {}={}: {}", key, value, e))
            })?);
        }

        nix::unistd::execve(&program, &args, &env)?;

        Ok(())
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
                Ok(0) => return Err(NucleusError::ExecError(format!(
                    "Child {} exited before namespace initialization",
                    child
                ))),
                Ok(_) => return Err(NucleusError::ExecError(
                    "Invalid namespace sync payload from child".to_string(),
                )),
                Err(e) => return Err(NucleusError::ExecError(format!(
                    "Failed waiting for child namespace setup: {}",
                    e
                ))),
            }
        }
    }

    fn notify_namespace_ready(fd: &OwnedFd, pid: u32) -> Result<()> {
        let payload = pid.to_ne_bytes();
        write(fd, &payload).map_err(|e| {
            NucleusError::ExecError(format!("Failed to notify namespace readiness: {}", e))
        })?;
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

    /// Resolve nsenter to an absolute path when running as root.
    fn resolve_nsenter() -> String {
        if nix::unistd::Uid::effective().is_root() {
            for path in &["/usr/bin/nsenter", "/usr/sbin/nsenter", "/bin/nsenter"] {
                if std::path::Path::new(path).exists() {
                    return path.to_string();
                }
            }
        }
        "nsenter".to_string()
    }

    /// Run a readiness probe and, if sd_notify is active, send READY=1.
    fn run_readiness_probe(
        pid: u32,
        container_name: &str,
        probe: &crate::container::ReadinessProbe,
        notify_socket: Option<&str>,
    ) -> Result<()> {
        use crate::container::ReadinessProbe;
        use std::process::Command;

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

            let nsenter_bin = Self::resolve_nsenter();
            let ready = match probe {
                ReadinessProbe::Exec { command } => {
                    let pid_str = pid.to_string();
                    let mut cmd = Command::new(&nsenter_bin);
                    cmd.arg("-t").arg(&pid_str).arg("-m").arg("-p").arg("-n");
                    for arg in command {
                        cmd.arg(arg);
                    }
                    cmd.stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                }
                ReadinessProbe::TcpPort(port) => {
                    // Probe TCP connectivity via the container's network namespace
                    let pid_str = pid.to_string();
                    Command::new(&nsenter_bin)
                        .args(["-t", &pid_str, "-n", "--", "sh", "-c"])
                        .arg(format!(
                            "cat < /dev/tcp/127.0.0.1/{} > /dev/null 2>&1 || \
                             exec 3<>/dev/tcp/127.0.0.1/{} 2>/dev/null",
                            port, port
                        ))
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                }
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
        hc: &crate::container::HealthCheck,
    ) {
        use std::process::Command;

        // Wait for start_period before beginning checks
        std::thread::sleep(hc.start_period);

        let mut consecutive_failures: u32 = 0;
        let nsenter_bin = Self::resolve_nsenter();

        loop {
            // Check if the container process is still alive
            let proc_path = format!("/proc/{}", pid);
            if !std::path::Path::new(&proc_path).exists() {
                debug!("Health check: container process {} gone, stopping", pid);
                return;
            }

            let pid_str = pid.to_string();
            let mut cmd = Command::new(&nsenter_bin);
            cmd.arg("-t").arg(&pid_str).arg("-m").arg("-p").arg("-n");
            for arg in &hc.command {
                cmd.arg(arg);
            }

            let result = cmd
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .and_then(|mut child| {
                    let timeout = hc.timeout;
                    let start = std::time::Instant::now();
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => return Ok(status),
                            Ok(None) => {
                                if start.elapsed() >= timeout {
                                    let _ = child.kill();
                                    let _ = child.wait();
                                    warn!(
                                        "Health check timed out after {:?} for {}",
                                        timeout, container_name
                                    );
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::TimedOut,
                                        "health check timed out",
                                    ));
                                }
                                std::thread::sleep(std::time::Duration::from_millis(100));
                            }
                            Err(e) => return Err(e),
                        }
                    }
                });

            match result {
                Ok(status) if status.success() => {
                    if consecutive_failures > 0 {
                        info!(
                            "Health check passed for {} after {} failures",
                            container_name, consecutive_failures
                        );
                    }
                    consecutive_failures = 0;
                }
                _ => {
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
                        let _ = kill(
                            Pid::from_raw(pid as i32),
                            Signal::SIGTERM,
                        );
                        return;
                    }
                }
            }

            std::thread::sleep(hc.interval);
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
        assert!(!config.use_gvisor);
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
}
