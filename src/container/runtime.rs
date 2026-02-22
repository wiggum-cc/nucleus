use crate::container::ContainerConfig;
use crate::error::{NucleusError, Result};
use crate::filesystem::{ContextPopulator, TmpfsMount, create_minimal_fs, mount_procfs, switch_root};
use crate::isolation::NamespaceManager;
use crate::resources::Cgroup;
use crate::security::{CapabilityManager, SeccompManager};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;
use std::path::PathBuf;
use tracing::{error, info};

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
        // 1. Mount tmpfs as container root
        let container_root = PathBuf::from("/tmp").join(format!("nucleus-{}", self.config.name));
        let mut tmpfs = TmpfsMount::new(&container_root, Some(1024 * 1024 * 1024)); // 1GB default
        tmpfs.mount()?;

        // 2. Create minimal filesystem structure
        create_minimal_fs(&container_root)?;

        // 3. Populate context if provided
        if let Some(context_dir) = &self.config.context_dir {
            let context_dest = container_root.join("context");
            let populator = ContextPopulator::new(context_dir, &context_dest);
            populator.populate()?;
        }

        // 4. Mount procfs
        let proc_path = container_root.join("proc");
        mount_procfs(&proc_path)?;

        // 5. Switch root filesystem
        switch_root(&container_root)?;

        // 6. Drop capabilities
        let mut cap_mgr = CapabilityManager::new();
        cap_mgr.drop_all()?;

        // 7. Apply seccomp filter
        let mut seccomp_mgr = SeccompManager::new();
        seccomp_mgr.apply_minimal_filter()?;

        // 8. Exec target process
        self.exec_command()?;

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

    /// Wait for child process to exit
    fn wait_for_child(&self, child: Pid) -> Result<i32> {
        loop {
            match waitpid(child, None)? {
                WaitStatus::Exited(_, code) => {
                    return Ok(code);
                }
                WaitStatus::Signaled(_, signal, _) => {
                    info!("Child killed by signal: {:?}", signal);
                    return Ok(128 + signal as i32);
                }
                _ => {
                    // Continue waiting
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
