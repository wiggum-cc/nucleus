use crate::container::ContainerState;
use crate::error::{NucleusError, Result};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use tracing::info;

/// Attach to a running container by entering its namespaces
pub struct ContainerAttach;

impl ContainerAttach {
    /// Attach to a running container and execute a command
    ///
    /// Opens namespace FDs from /proc/<pid>/ns/*, forks, calls setns(2) for each,
    /// then execve the command. Parent waits with waitpid.
    pub fn attach(state: &ContainerState, command: Vec<String>) -> Result<i32> {
        if !state.is_running() {
            return Err(NucleusError::AttachError(format!(
                "Container {} is not running",
                state.id
            )));
        }

        // Validate caller owns the container (or is root)
        let current_uid = nix::unistd::Uid::effective().as_raw();
        if current_uid != 0 && current_uid != state.creator_uid {
            return Err(NucleusError::AttachError(format!(
                "Permission denied: container {} owned by UID {}, caller is UID {}",
                state.id, state.creator_uid, current_uid
            )));
        }

        let pid = state.pid;
        info!("Attaching to container {} (PID {})", state.id, pid);

        // Open namespace file descriptors
        let ns_types = ["pid", "mnt", "net", "uts", "ipc"];
        let mut ns_fds: Vec<(String, File)> = Vec::new();

        for ns in &ns_types {
            let ns_path = format!("/proc/{}/ns/{}", pid, ns);
            match File::open(&ns_path) {
                Ok(f) => ns_fds.push((ns.to_string(), f)),
                Err(e) => {
                    // Some namespaces may not be available
                    info!("Skipping namespace {}: {}", ns, e);
                }
            }
        }

        if ns_fds.is_empty() {
            return Err(NucleusError::AttachError(
                "Could not open any namespace FDs".to_string(),
            ));
        }

        // Fork child
        match unsafe { fork() }
            .map_err(|e| NucleusError::AttachError(format!("Fork failed: {}", e)))?
        {
            ForkResult::Parent { child } => {
                // Parent: wait for child
                Self::wait_for_child(child)
            }
            ForkResult::Child => {
                // Child: enter namespaces and exec
                match Self::enter_and_exec(&ns_fds, &command) {
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        eprintln!("Attach failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    fn enter_and_exec(ns_fds: &[(String, File)], command: &[String]) -> Result<()> {
        if command.is_empty() {
            return Err(NucleusError::AttachError(
                "No command specified for attach".to_string(),
            ));
        }

        // Enter each namespace via setns(2)
        for (ns_name, fd) in ns_fds {
            let raw_fd = fd.as_raw_fd();
            let ret = unsafe { libc::setns(raw_fd, 0) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(NucleusError::AttachError(format!(
                    "setns({}) failed: {}",
                    ns_name, err
                )));
            }
            info!("Entered {} namespace", ns_name);
        }

        // Change to root directory of the namespace
        let _ = nix::unistd::chdir("/");

        // Exec the command
        let program = CString::new(command[0].as_str())
            .map_err(|e| NucleusError::AttachError(format!("Invalid program name: {}", e)))?;

        let args: std::result::Result<Vec<CString>, _> = command
            .iter()
            .map(|arg| CString::new(arg.as_str()))
            .collect();
        let args =
            args.map_err(|e| NucleusError::AttachError(format!("Invalid argument: {}", e)))?;

        nix::unistd::execve::<CString, CString>(&program, &args, &[])
            .map_err(|e| NucleusError::AttachError(format!("execve failed: {}", e)))?;

        Ok(())
    }

    fn wait_for_child(child: Pid) -> Result<i32> {
        loop {
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code)) => return Ok(code),
                Ok(WaitStatus::Signaled(_, signal, _)) => return Ok(128 + signal as i32),
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    return Err(NucleusError::AttachError(format!("waitpid failed: {}", e)));
                }
                _ => continue,
            }
        }
    }
}
