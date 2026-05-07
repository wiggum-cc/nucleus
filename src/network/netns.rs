//! Network namespace helpers replacing external `nsenter` usage.
//!
//! * [`in_netns`] – enter a netns via `setns()` in a scoped thread to run
//!   native Rust code (e.g. netlink operations) inside a container's network
//!   namespace.
//! * [`exec_in_netns`] – fork+setns+exec a program (e.g. `iptables`) inside
//!   a container's network namespace using `Command::pre_exec`.

use crate::error::{NucleusError, Result};
use nix::unistd::{setresgid, setresuid, Gid, Uid};
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Run a closure inside the network namespace of `pid`.
///
/// Spawns a scoped thread that calls `setns(CLONE_NEWNET)` before invoking `f`.
/// The thread joins before this function returns, so `f` may borrow from the
/// caller's stack.
pub fn in_netns<F, R>(pid: u32, f: F) -> Result<R>
where
    F: FnOnce() -> Result<R> + Send,
    R: Send,
{
    let ns_path = format!("/proc/{}/ns/net", pid);
    let ns_file = std::fs::File::open(&ns_path).map_err(|e| {
        NucleusError::NetworkError(format!("failed to open netns for PID {}: {}", pid, e))
    })?;

    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                nix::sched::setns(&ns_file, nix::sched::CloneFlags::CLONE_NEWNET).map_err(|e| {
                    NucleusError::NetworkError(format!("setns(CLONE_NEWNET): {}", e))
                })?;
                f()
            })
            .join()
            .map_err(|_| NucleusError::NetworkError("netns worker thread panicked".to_string()))?
    })
}

/// Execute a program inside the network namespace of `pid`.
///
/// Uses `Command::pre_exec` to call `setns(CLONE_NEWNET)` in the child
/// process after fork, before exec. This is the replacement for
/// `nsenter -t <pid> -n <program> <args...>`.
///
/// `program` should be an absolute path (e.g. from `resolve_bin`).
pub fn exec_in_netns(pid: u32, program: &str, args: &[&str]) -> Result<()> {
    exec_in_namespaces(pid, false, program, None, args)
}

pub(crate) fn exec_in_netns_with_arg0(
    pid: u32,
    program: &str,
    arg0: &str,
    args: &[&str],
) -> Result<()> {
    exec_in_namespaces(pid, false, program, Some(arg0), args)
}

/// Execute a program inside the user+network namespaces of `pid`.
///
/// For rootless containers, network administration inside the target netns
/// requires first joining the target user namespace, matching the ordering used
/// by `nsenter -U -n`.
pub fn exec_in_user_netns(pid: u32, program: &str, args: &[&str]) -> Result<()> {
    exec_in_namespaces(pid, true, program, None, args)
}

pub(crate) fn exec_in_user_netns_with_arg0(
    pid: u32,
    program: &str,
    arg0: &str,
    args: &[&str],
) -> Result<()> {
    exec_in_namespaces(pid, true, program, Some(arg0), args)
}

fn exec_in_namespaces(
    pid: u32,
    enter_userns: bool,
    program: &str,
    arg0: Option<&str>,
    args: &[&str],
) -> Result<()> {
    let userns_file = if enter_userns {
        let userns_path = format!("/proc/{}/ns/user", pid);
        Some(std::fs::File::open(&userns_path).map_err(|e| {
            NucleusError::NetworkError(format!("failed to open userns for PID {}: {}", pid, e))
        })?)
    } else {
        None
    };

    let ns_path = format!("/proc/{}/ns/net", pid);
    let ns_file = std::fs::File::open(&ns_path).map_err(|e| {
        NucleusError::NetworkError(format!("failed to open netns for PID {}: {}", pid, e))
    })?;

    // SAFETY: The pre_exec closure runs after fork() in the child process.
    // setns() is a single syscall and is async-signal-safe.  ns_file is a
    // valid open fd inherited by the child.
    let mut command = Command::new(program);
    if let Some(arg0) = arg0 {
        command.arg0(arg0);
    }

    let output = unsafe {
        command
            .args(args)
            .pre_exec(move || {
                if let Some(ref userns) = userns_file {
                    nix::sched::setns(userns, nix::sched::CloneFlags::CLONE_NEWUSER)
                        .map_err(std::io::Error::other)?;
                    setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0))
                        .map_err(std::io::Error::other)?;
                    setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0))
                        .map_err(std::io::Error::other)?;
                }
                nix::sched::setns(&ns_file, nix::sched::CloneFlags::CLONE_NEWNET)
                    .map_err(std::io::Error::other)
            })
            .output()
    }
    .map_err(|e| {
        NucleusError::NetworkError(format!("exec {} in netns({}): {}", program, pid, e))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NucleusError::NetworkError(format!(
            "{} {:?} failed in netns({}): {}",
            program,
            args,
            pid,
            stderr.trim()
        )));
    }

    Ok(())
}
