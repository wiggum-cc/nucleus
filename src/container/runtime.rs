use crate::container::ContainerConfig;
use crate::error::{NucleusError, Result};
use crate::filesystem::{ContextPopulator, TmpfsMount, create_minimal_fs, create_dev_nodes, mount_procfs, switch_root};
use crate::isolation::NamespaceManager;
use crate::resources::Cgroup;
use crate::security::{CapabilityManager, GVisorRuntime, SeccompManager};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};
use tracing::{error, info, warn};

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
        info!("Starting container: {}", self.config.name);

        // Create cgroup
        let cgroup_name = format!("nucleus-{}", self.config.name);
        let mut cgroup = Cgroup::create(&cgroup_name)?;
        cgroup.set_limits(&self.config.limits)?;

        // Create namespace manager
        let mut namespace_mgr = NamespaceManager::new(self.config.namespaces.clone());

        // Unshare namespaces in parent process
        namespace_mgr.unshare_namespaces()?;

        // Fork child process
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                info!("Forked child process: {}", child);

                // Attach child to cgroup
                cgroup.attach_process(child.as_raw() as u32)?;

                // Set up signal handling
                self.setup_signal_handlers(child)?;

                // Wait for child to exit
                let exit_code = self.wait_for_child(child)?;

                // Cleanup cgroup
                cgroup.cleanup()?;

                info!("Container {} exited with code {}", self.config.name, exit_code);

                Ok(exit_code)
            }
            ForkResult::Child => {
                // Child process - set up container environment
                match self.setup_and_exec() {
                    Ok(_) => {
                        // exec should not return
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
    /// This runs in the child process after fork
    fn setup_and_exec(&self) -> Result<()> {
        // Check if we should use gVisor
        if self.config.use_gvisor {
            return self.setup_and_exec_gvisor();
        }

        // Native execution path
        // 1. Set hostname if UTS namespace is enabled
        let namespace_mgr = NamespaceManager::new(self.config.namespaces.clone());
        if let Some(hostname) = &self.config.hostname {
            namespace_mgr.set_hostname(hostname)?;
        }

        // 2. Mount tmpfs as container root
        let container_root = PathBuf::from("/tmp").join(format!("nucleus-{}", self.config.name));
        let mut tmpfs = TmpfsMount::new(&container_root, Some(1024 * 1024 * 1024)); // 1GB default
        tmpfs.mount()?;

        // 3. Create minimal filesystem structure
        create_minimal_fs(&container_root)?;

        // 4. Create device nodes
        let dev_path = container_root.join("dev");
        create_dev_nodes(&dev_path)?;

        // 5. Populate context if provided
        if let Some(context_dir) = &self.config.context_dir {
            let context_dest = container_root.join("context");
            let populator = ContextPopulator::new(context_dir, &context_dest);
            populator.populate()?;
        }

        // 6. Mount procfs
        let proc_path = container_root.join("proc");
        mount_procfs(&proc_path)?;

        // 7. Switch root filesystem
        switch_root(&container_root)?;

        // 8. Drop capabilities
        let mut cap_mgr = CapabilityManager::new();
        cap_mgr.drop_all()?;

        // 9. Apply seccomp filter
        let mut seccomp_mgr = SeccompManager::new();
        seccomp_mgr.apply_minimal_filter()?;

        // 10. Exec target process
        self.exec_command()?;

        // Should never reach here
        Ok(())
    }

    /// Set up container with gVisor and exec
    ///
    /// This implements the gVisor execution path
    fn setup_and_exec_gvisor(&self) -> Result<()> {
        info!("Using gVisor runtime");

        // Create gVisor runtime
        let gvisor = GVisorRuntime::new().map_err(|e| {
            warn!("Failed to initialize gVisor, falling back to native: {}", e);
            e
        })?;

        // Create root directory for runsc
        let container_root = PathBuf::from("/tmp").join(format!("nucleus-gvisor-{}", self.config.name));

        // For gVisor, we prepare a simpler environment
        // runsc handles most of the isolation internally
        std::fs::create_dir_all(&container_root)?;

        // Populate context if provided
        if let Some(context_dir) = &self.config.context_dir {
            let context_dest = container_root.join("context");
            let populator = ContextPopulator::new(context_dir, &context_dest);
            populator.populate()?;
        }

        // Execute with gVisor
        // This will replace the current process with runsc
        gvisor.exec_with_gvisor(&self.config.name, &container_root, &self.config.command)?;

        // Should never reach here
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

        // execve - this replaces the current process
        nix::unistd::execve::<std::ffi::CString, std::ffi::CString>(&program, &args, &[])?;

        // Should never reach here
        Ok(())
    }

    /// Set up signal handlers to forward signals to child process
    fn setup_signal_handlers(&self, child: Pid) -> Result<()> {
        use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet};

        // Store child PID in static for signal handler access
        static CHILD_PID: AtomicI32 = AtomicI32::new(0);
        CHILD_PID.store(child.as_raw(), Ordering::SeqCst);

        // Signal handler that forwards signals to child
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

        // Set up handlers for SIGTERM and SIGINT
        unsafe {
            sigaction(Signal::SIGTERM, &action).map_err(|e| {
                NucleusError::ExecError(format!("Failed to set SIGTERM handler: {}", e))
            })?;

            sigaction(Signal::SIGINT, &action).map_err(|e| {
                NucleusError::ExecError(format!("Failed to set SIGINT handler: {}", e))
            })?;
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
                    // Interrupted by signal, continue waiting
                    continue;
                }
                Err(e) => {
                    return Err(NucleusError::ExecError(format!(
                        "Failed to wait for child: {}",
                        e
                    )));
                }
                _ => {
                    // Continue waiting for other status changes
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
        let config = ContainerConfig::new("test".to_string(), vec!["/bin/sh".to_string()]);
        assert_eq!(config.name, "test");
        assert_eq!(config.command, vec!["/bin/sh"]);
        assert!(!config.use_gvisor);
    }

    // Note: Testing actual container execution requires root privileges
    // These are tested in integration tests
}
