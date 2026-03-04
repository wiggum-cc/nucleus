use crate::container::{ContainerConfig, ContainerState, ContainerStateManager};
use crate::error::{NucleusError, Result};
use crate::filesystem::{
    bind_mount_host_paths, create_dev_nodes, create_minimal_fs, mount_procfs, switch_root,
    ContextPopulator, FilesystemState, LazyContextPopulator, TmpfsMount,
};
use crate::isolation::NamespaceManager;
use crate::network::{BridgeNetwork, NetworkMode};
use crate::resources::Cgroup;
use crate::security::{
    CapabilityManager, GVisorRuntime, LandlockManager, OciBundle, OciConfig, SeccompManager,
    SecurityState,
};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;
use std::sync::atomic::{AtomicI32, Ordering};
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

        // Adjust namespace config for network mode
        if let NetworkMode::Host = &config.network {
            info!("Host network mode: skipping network namespace");
            config.namespaces.net = false;
        }

        // Bridge networking requires root
        if let NetworkMode::Bridge(_) = &config.network {
            if !is_root {
                warn!("Bridge networking requires root, degrading to no networking");
                config.network = NetworkMode::None;
            }
        }

        // Create state manager
        let state_mgr = ContainerStateManager::new()?;

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
                        warn!("Failed to set cgroup limits: {}", e);
                        // Cleanup the cgroup we created
                        let _ = cgroup.cleanup();
                        None
                    }
                }
            }
            Err(e) => {
                if config.user_ns_config.is_some() {
                    if config.limits.memory_bytes.is_some()
                        || config.limits.cpu_quota_us.is_some()
                        || config.limits.pids_max.is_some()
                    {
                        warn!(
                            "Running in rootless mode: requested resource limits cannot be \
                             enforced — cgroup creation requires root ({})",
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

        // Create namespace manager
        let mut namespace_mgr = NamespaceManager::new(config.namespaces.clone());

        // Configure user namespace mapping if provided
        if let Some(user_config) = &config.user_ns_config {
            namespace_mgr = namespace_mgr.with_user_mapping(user_config.clone());
        }

        // Unshare namespaces in parent process
        namespace_mgr.unshare_namespaces()?;

        // Fork child process
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                info!("Forked child process: {}", child);

                // Save container state
                let cgroup_path = cgroup_opt
                    .as_ref()
                    .map(|_| format!("/sys/fs/cgroup/{}", cgroup_name));

                // Convert cpu_quota_us to millicores for storage
                let cpu_millicores = config.limits.cpu_quota_us.map(|quota| {
                    (quota * 1000) / config.limits.cpu_period_us
                });
                let state = ContainerState::new(
                    config.id.clone(),
                    config.name.clone(),
                    child.as_raw() as u32,
                    config.command.clone(),
                    config.limits.memory_bytes,
                    cpu_millicores,
                    config.use_gvisor,
                    config.user_ns_config.is_some(),
                    cgroup_path,
                );
                state_mgr.save_state(&state)?;

                // Attach child to cgroup if we have one
                if let Some(ref mut cgroup) = cgroup_opt {
                    cgroup.attach_process(child.as_raw() as u32)?;
                }

                // Set up bridge networking in parent (needs host netns)
                let bridge_net = if let NetworkMode::Bridge(ref bridge_config) = config.network {
                    match BridgeNetwork::setup(child.as_raw() as u32, bridge_config) {
                        Ok(net) => Some(net),
                        Err(e) => {
                            warn!("Failed to set up bridge networking: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                // Set up signal handling
                self.setup_signal_handlers(child)?;

                // Wait for child to exit
                let exit_code = self.wait_for_child(child)?;

                // Cleanup bridge networking
                if let Some(net) = bridge_net {
                    if let Err(e) = net.cleanup() {
                        warn!("Failed to cleanup bridge networking: {}", e);
                    }
                }

                // Cleanup cgroup if we have one
                if let Some(cgroup) = cgroup_opt {
                    cgroup.cleanup()?;
                }

                // Delete container state
                state_mgr.delete_state(&config.id)?;

                info!(
                    "Container {} ({}) exited with code {}",
                    config.name, config.id, exit_code
                );

                Ok(exit_code)
            }
            ForkResult::Child => {
                // Child process - set up container environment
                let temp_container = Container { config };
                match temp_container.setup_and_exec() {
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
    fn setup_and_exec(&self) -> Result<()> {
        // Check if we should use gVisor
        if self.config.use_gvisor {
            return self.setup_and_exec_gvisor();
        }
        let is_rootless = self.config.user_ns_config.is_some();

        // Initialize state machines
        let mut fs_state = FilesystemState::Unmounted;
        let mut sec_state = SecurityState::Privileged;

        // 1. Set hostname if UTS namespace is enabled
        let namespace_mgr = NamespaceManager::new(self.config.namespaces.clone());
        if let Some(hostname) = &self.config.hostname {
            namespace_mgr.set_hostname(hostname)?;
        }

        // 2. Mount tmpfs as container root
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

        // 3. Create minimal filesystem structure
        create_minimal_fs(&container_root)?;

        // 4. Create device nodes
        let dev_path = container_root.join("dev");
        create_dev_nodes(&dev_path)?;

        // 5. Populate context if provided
        // Filesystem: Mounted -> Populated
        if let Some(context_dir) = &self.config.context_dir {
            let context_dest = container_root.join("context");
            LazyContextPopulator::populate(
                &self.config.context_mode,
                context_dir,
                &context_dest,
            )?;
        }
        fs_state = fs_state.transition(FilesystemState::Populated)?;

        // 6. Bind mount host paths (for accessing host binaries)
        bind_mount_host_paths(&container_root, is_rootless)?;

        // 7. Mount procfs
        let proc_path = container_root.join("proc");
        mount_procfs(&proc_path, is_rootless)?;

        // 8. Write resolv.conf for bridge networking (before pivot_root)
        if let NetworkMode::Bridge(ref bridge_config) = self.config.network {
            BridgeNetwork::write_resolv_conf(&container_root, &bridge_config.dns)?;
        }

        // 9. Switch root filesystem
        // Filesystem: Populated -> Pivoted
        switch_root(&container_root, is_rootless)?;
        fs_state = fs_state.transition(FilesystemState::Pivoted)?;
        debug!("Filesystem state: {:?}", fs_state);

        // 10. Drop capabilities
        // Security: Privileged -> CapabilitiesDropped
        let mut cap_mgr = CapabilityManager::new();
        cap_mgr.drop_all()?;
        sec_state = sec_state.transition(SecurityState::CapabilitiesDropped)?;

        // 11. Apply seccomp filter
        // Security: CapabilitiesDropped -> SeccompApplied
        let mut seccomp_mgr = SeccompManager::new();
        seccomp_mgr.apply_minimal_filter_with_mode(is_rootless)?;
        sec_state = sec_state.transition(SecurityState::SeccompApplied)?;

        // 12. Apply Landlock filesystem policy
        // Security: SeccompApplied -> LandlockApplied
        let mut landlock_mgr = LandlockManager::new();
        landlock_mgr.apply_container_policy_with_mode(is_rootless)?;
        sec_state = sec_state.transition(SecurityState::LandlockApplied)?;

        // Security: LandlockApplied -> Locked
        sec_state = sec_state.transition(SecurityState::Locked)?;
        debug!("Security state: {:?}", sec_state);

        // 13. Exec target process
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

        if !self.config.use_oci_bundle {
            info!("Security hardening enabled: forcing gVisor OCI bundle mode");
        }
        self.setup_and_exec_gvisor_oci(&gvisor)
    }

    /// Set up container with gVisor using OCI bundle format
    fn setup_and_exec_gvisor_oci(&self, gvisor: &GVisorRuntime) -> Result<()> {
        info!("Using gVisor with OCI bundle format");

        let mut oci_config =
            OciConfig::new(self.config.command.clone(), self.config.hostname.clone());

        oci_config = oci_config.with_resources(&self.config.limits);

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
        create_dev_nodes(&dev_path)?;

        if let Some(context_dir) = &self.config.context_dir {
            let context_dest = rootfs.join("context");
            let populator = ContextPopulator::new(context_dir, &context_dest);
            populator.populate()?;
        }

        gvisor.exec_with_oci_bundle(&self.config.id, &bundle)?;

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

        nix::unistd::execve::<std::ffi::CString, std::ffi::CString>(&program, &args, &[])?;

        Ok(())
    }

    /// Set up signal handlers to forward signals to child process
    fn setup_signal_handlers(&self, child: Pid) -> Result<()> {
        use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet};

        static CHILD_PID: AtomicI32 = AtomicI32::new(0);
        CHILD_PID.store(child.as_raw(), Ordering::SeqCst);

        extern "C" fn forward_signal(sig: i32) {
            let child_pid = CHILD_PID.load(Ordering::SeqCst);
            if child_pid > 0 {
                let pid = Pid::from_raw(child_pid);
                let signal = Signal::try_from(sig).ok();
                if let Some(signal) = signal {
                    let _ = kill(pid, signal);
                }
            }
        }

        let handler = SigHandler::Handler(forward_signal);
        let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());

        unsafe {
            for (signal, name) in [
                (Signal::SIGTERM, "SIGTERM"),
                (Signal::SIGINT, "SIGINT"),
                (Signal::SIGHUP, "SIGHUP"),
                (Signal::SIGQUIT, "SIGQUIT"),
                (Signal::SIGUSR1, "SIGUSR1"),
                (Signal::SIGUSR2, "SIGUSR2"),
            ] {
                sigaction(signal, &action).map_err(|e| {
                    NucleusError::ExecError(format!("Failed to set {} handler: {}", name, e))
                })?;
            }
        }

        info!("Signal handlers configured");

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_config() {
        let config = ContainerConfig::new(None, vec!["/bin/sh".to_string()]);
        assert!(!config.id.is_empty());
        assert_eq!(config.command, vec!["/bin/sh"]);
        assert!(!config.use_gvisor);
    }

    #[test]
    fn test_container_config_with_name() {
        let config = ContainerConfig::new(Some("mycontainer".to_string()), vec!["/bin/sh".to_string()]);
        assert_eq!(config.name, "mycontainer");
        assert!(!config.id.is_empty());
        assert_ne!(config.id, config.name);
    }
}
