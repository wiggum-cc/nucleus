//! Seccomp profile generator: create minimal profiles from trace data.
//!
//! Reads NDJSON trace files produced by `--seccomp-mode trace` and
//! generates a minimal OCI-format seccomp profile containing only
//! the syscalls actually used by the workload.

use crate::error::{NucleusError, Result};
use crate::security::seccomp_trace::TraceRecord;
use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::path::Path;
use tracing::info;

/// OCI-format seccomp profile (subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeccompProfile {
    /// Default action for unlisted syscalls.
    pub default_action: String,

    /// Target architectures.
    #[serde(default)]
    pub architectures: Vec<String>,

    /// Syscall groups with their action.
    #[serde(default)]
    pub syscalls: Vec<SeccompSyscallGroup>,
}

/// A group of syscalls sharing the same action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompSyscallGroup {
    /// Syscall names.
    pub names: Vec<String>,

    /// Action: typically "SCMP_ACT_ALLOW".
    pub action: String,

    /// Optional argument filters (not generated, but preserved).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<SeccompArgFilter>,
}

/// Argument-level filter for a syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompArgFilter {
    /// Argument index (0-5).
    pub index: u32,
    /// Comparison operator.
    pub op: String,
    /// Comparison value.
    pub value: u64,
}

/// Return the OCI seccomp architecture constant for the current target.
///
/// Detected at compile time via `cfg!(target_arch)` so generated profiles
/// always match the binary's architecture.
fn native_scmp_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "SCMP_ARCH_X86_64"
    } else if cfg!(target_arch = "aarch64") {
        "SCMP_ARCH_AARCH64"
    } else if cfg!(target_arch = "x86") {
        "SCMP_ARCH_X86"
    } else if cfg!(target_arch = "arm") {
        "SCMP_ARCH_ARM"
    } else if cfg!(target_arch = "riscv64") {
        "SCMP_ARCH_RISCV64"
    } else if cfg!(target_arch = "s390x") {
        "SCMP_ARCH_S390X"
    } else {
        "SCMP_ARCH_NATIVE"
    }
}

/// Generate a minimal seccomp profile from a trace file.
///
/// Reads NDJSON records, collects unique syscalls, and produces
/// an OCI-format JSON profile that allows exactly those syscalls.
pub fn generate_from_trace(trace_path: &Path) -> Result<SeccompProfile> {
    let file = std::fs::File::open(trace_path).map_err(|e| {
        NucleusError::ConfigError(format!("Failed to open trace file {:?}: {}", trace_path, e))
    })?;

    let reader = std::io::BufReader::new(file);
    let mut syscall_names: Vec<String> = Vec::new();

    for line in reader.lines() {
        let line = line
            .map_err(|e| NucleusError::ConfigError(format!("Failed to read trace line: {}", e)))?;

        if line.trim().is_empty() {
            continue;
        }

        let record: TraceRecord = serde_json::from_str(&line).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to parse trace record: {}: line='{}'",
                e, line
            ))
        })?;

        let name = record.name.unwrap_or_else(|| {
            syscall_number_to_name(record.syscall)
                .map(String::from)
                .unwrap_or_else(|| format!("__NR_{}", record.syscall))
        });

        if !syscall_names.contains(&name) {
            syscall_names.push(name);
        }
    }

    syscall_names.sort();

    info!(
        "Generated seccomp profile with {} syscalls from {:?}",
        syscall_names.len(),
        trace_path
    );

    Ok(SeccompProfile {
        default_action: "SCMP_ACT_KILL_PROCESS".to_string(),
        architectures: vec![native_scmp_arch().to_string()],
        syscalls: vec![SeccompSyscallGroup {
            names: syscall_names,
            action: "SCMP_ACT_ALLOW".to_string(),
            args: vec![],
        }],
    })
}

/// Map a syscall number back to its name (inverse of syscall_name_to_number).
pub fn syscall_number_to_name(nr: i64) -> Option<&'static str> {
    SYSCALL_TABLE
        .iter()
        .find(|&&(_, n)| n == nr)
        .map(|&(name, _)| name)
}

/// (name, number) pairs for all mapped syscalls.
static SYSCALL_TABLE: &[(&str, i64)] = &[
    ("read", libc::SYS_read),
    ("write", libc::SYS_write),
    ("open", libc::SYS_open),
    ("openat", libc::SYS_openat),
    ("close", libc::SYS_close),
    ("stat", libc::SYS_stat),
    ("fstat", libc::SYS_fstat),
    ("lstat", libc::SYS_lstat),
    ("lseek", libc::SYS_lseek),
    ("access", libc::SYS_access),
    ("fcntl", libc::SYS_fcntl),
    ("readv", libc::SYS_readv),
    ("writev", libc::SYS_writev),
    ("pread64", libc::SYS_pread64),
    ("pwrite64", libc::SYS_pwrite64),
    ("readlink", libc::SYS_readlink),
    ("readlinkat", libc::SYS_readlinkat),
    ("newfstatat", libc::SYS_newfstatat),
    ("statx", libc::SYS_statx),
    ("faccessat", libc::SYS_faccessat),
    ("faccessat2", libc::SYS_faccessat2),
    ("dup", libc::SYS_dup),
    ("dup2", libc::SYS_dup2),
    ("dup3", libc::SYS_dup3),
    ("pipe", libc::SYS_pipe),
    ("pipe2", libc::SYS_pipe2),
    ("unlink", libc::SYS_unlink),
    ("unlinkat", libc::SYS_unlinkat),
    ("rename", libc::SYS_rename),
    ("renameat", libc::SYS_renameat),
    ("renameat2", libc::SYS_renameat2),
    ("link", libc::SYS_link),
    ("linkat", libc::SYS_linkat),
    ("symlink", libc::SYS_symlink),
    ("symlinkat", libc::SYS_symlinkat),
    ("chmod", libc::SYS_chmod),
    ("fchmod", libc::SYS_fchmod),
    ("fchmodat", libc::SYS_fchmodat),
    ("truncate", libc::SYS_truncate),
    ("ftruncate", libc::SYS_ftruncate),
    ("fallocate", libc::SYS_fallocate),
    ("fadvise64", libc::SYS_fadvise64),
    ("fsync", libc::SYS_fsync),
    ("fdatasync", libc::SYS_fdatasync),
    ("flock", libc::SYS_flock),
    ("sendfile", libc::SYS_sendfile),
    ("copy_file_range", libc::SYS_copy_file_range),
    ("splice", libc::SYS_splice),
    ("tee", libc::SYS_tee),
    ("mmap", libc::SYS_mmap),
    ("munmap", libc::SYS_munmap),
    ("mprotect", libc::SYS_mprotect),
    ("brk", libc::SYS_brk),
    ("mremap", libc::SYS_mremap),
    ("madvise", libc::SYS_madvise),
    ("msync", libc::SYS_msync),
    ("mlock", libc::SYS_mlock),
    ("munlock", libc::SYS_munlock),
    ("fork", libc::SYS_fork),
    ("clone", libc::SYS_clone),
    ("clone3", libc::SYS_clone3),
    ("execve", libc::SYS_execve),
    ("execveat", libc::SYS_execveat),
    ("wait4", libc::SYS_wait4),
    ("waitid", libc::SYS_waitid),
    ("exit", libc::SYS_exit),
    ("exit_group", libc::SYS_exit_group),
    ("getpid", libc::SYS_getpid),
    ("gettid", libc::SYS_gettid),
    ("getuid", libc::SYS_getuid),
    ("getgid", libc::SYS_getgid),
    ("geteuid", libc::SYS_geteuid),
    ("getegid", libc::SYS_getegid),
    ("getppid", libc::SYS_getppid),
    ("getpgrp", libc::SYS_getpgrp),
    ("setsid", libc::SYS_setsid),
    ("getgroups", libc::SYS_getgroups),
    ("rt_sigaction", libc::SYS_rt_sigaction),
    ("rt_sigprocmask", libc::SYS_rt_sigprocmask),
    ("rt_sigreturn", libc::SYS_rt_sigreturn),
    ("rt_sigsuspend", libc::SYS_rt_sigsuspend),
    ("sigaltstack", libc::SYS_sigaltstack),
    ("kill", libc::SYS_kill),
    ("tgkill", libc::SYS_tgkill),
    ("clock_gettime", libc::SYS_clock_gettime),
    ("clock_getres", libc::SYS_clock_getres),
    ("clock_nanosleep", libc::SYS_clock_nanosleep),
    ("gettimeofday", libc::SYS_gettimeofday),
    ("nanosleep", libc::SYS_nanosleep),
    ("getcwd", libc::SYS_getcwd),
    ("chdir", libc::SYS_chdir),
    ("fchdir", libc::SYS_fchdir),
    ("mkdir", libc::SYS_mkdir),
    ("mkdirat", libc::SYS_mkdirat),
    ("rmdir", libc::SYS_rmdir),
    ("getdents", libc::SYS_getdents),
    ("getdents64", libc::SYS_getdents64),
    ("socket", libc::SYS_socket),
    ("connect", libc::SYS_connect),
    ("sendto", libc::SYS_sendto),
    ("recvfrom", libc::SYS_recvfrom),
    ("sendmsg", libc::SYS_sendmsg),
    ("recvmsg", libc::SYS_recvmsg),
    ("shutdown", libc::SYS_shutdown),
    ("bind", libc::SYS_bind),
    ("listen", libc::SYS_listen),
    ("accept", libc::SYS_accept),
    ("accept4", libc::SYS_accept4),
    ("setsockopt", libc::SYS_setsockopt),
    ("getsockopt", libc::SYS_getsockopt),
    ("getsockname", libc::SYS_getsockname),
    ("getpeername", libc::SYS_getpeername),
    ("socketpair", libc::SYS_socketpair),
    ("poll", libc::SYS_poll),
    ("ppoll", libc::SYS_ppoll),
    ("select", libc::SYS_select),
    ("pselect6", libc::SYS_pselect6),
    ("epoll_create", libc::SYS_epoll_create),
    ("epoll_create1", libc::SYS_epoll_create1),
    ("epoll_ctl", libc::SYS_epoll_ctl),
    ("epoll_wait", libc::SYS_epoll_wait),
    ("epoll_pwait", libc::SYS_epoll_pwait),
    ("eventfd", libc::SYS_eventfd),
    ("eventfd2", libc::SYS_eventfd2),
    ("signalfd", libc::SYS_signalfd),
    ("signalfd4", libc::SYS_signalfd4),
    ("timerfd_create", libc::SYS_timerfd_create),
    ("timerfd_settime", libc::SYS_timerfd_settime),
    ("timerfd_gettime", libc::SYS_timerfd_gettime),
    ("uname", libc::SYS_uname),
    ("getrandom", libc::SYS_getrandom),
    ("futex", libc::SYS_futex),
    ("set_tid_address", libc::SYS_set_tid_address),
    ("set_robust_list", libc::SYS_set_robust_list),
    ("get_robust_list", libc::SYS_get_robust_list),
    ("arch_prctl", libc::SYS_arch_prctl),
    ("sysinfo", libc::SYS_sysinfo),
    ("umask", libc::SYS_umask),
    ("getrlimit", libc::SYS_getrlimit),
    ("prlimit64", libc::SYS_prlimit64),
    ("getrusage", libc::SYS_getrusage),
    ("times", libc::SYS_times),
    ("sched_yield", libc::SYS_sched_yield),
    ("sched_getaffinity", libc::SYS_sched_getaffinity),
    ("getcpu", libc::SYS_getcpu),
    ("rseq", libc::SYS_rseq),
    ("close_range", libc::SYS_close_range),
    ("memfd_create", libc::SYS_memfd_create),
    ("ioctl", libc::SYS_ioctl),
    ("prctl", libc::SYS_prctl),
    ("landlock_create_ruleset", libc::SYS_landlock_create_ruleset),
    ("landlock_add_rule", libc::SYS_landlock_add_rule),
    ("landlock_restrict_self", libc::SYS_landlock_restrict_self),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_number_to_name() {
        assert_eq!(syscall_number_to_name(libc::SYS_read), Some("read"));
        assert_eq!(syscall_number_to_name(libc::SYS_write), Some("write"));
        assert_eq!(syscall_number_to_name(libc::SYS_openat), Some("openat"));
        assert_eq!(syscall_number_to_name(99999), None);
    }

    #[test]
    fn test_generate_from_trace() {
        let dir = tempfile::tempdir().unwrap();
        let trace_path = dir.path().join("trace.ndjson");

        // Write test trace data
        std::fs::write(
            &trace_path,
            r#"{"syscall":0,"name":"read","count":10}
{"syscall":1,"name":"write","count":5}
{"syscall":257,"name":"openat","count":3}
"#,
        )
        .unwrap();

        let profile = generate_from_trace(&trace_path).unwrap();
        assert_eq!(profile.default_action, "SCMP_ACT_KILL_PROCESS");
        assert_eq!(profile.syscalls.len(), 1);

        let names = &profile.syscalls[0].names;
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"read".to_string()));
        assert!(names.contains(&"write".to_string()));
        assert!(names.contains(&"openat".to_string()));
    }

    #[test]
    fn test_profile_serialization() {
        let profile = SeccompProfile {
            default_action: "SCMP_ACT_KILL_PROCESS".to_string(),
            architectures: vec!["SCMP_ARCH_X86_64".to_string()],
            syscalls: vec![SeccompSyscallGroup {
                names: vec!["read".to_string(), "write".to_string()],
                action: "SCMP_ACT_ALLOW".to_string(),
                args: vec![],
            }],
        };

        let json = serde_json::to_string_pretty(&profile).unwrap();
        assert!(json.contains("\"defaultAction\""));
        assert!(json.contains("SCMP_ACT_KILL_PROCESS"));
        assert!(json.contains("\"read\""));

        // Roundtrip
        let parsed: SeccompProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.syscalls[0].names.len(), 2);
    }

    #[test]
    fn test_native_scmp_arch_matches_target() {
        let arch = native_scmp_arch();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, "SCMP_ARCH_X86_64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, "SCMP_ARCH_AARCH64");
        // Always starts with SCMP_ARCH_
        assert!(arch.starts_with("SCMP_ARCH_"));
    }

    #[test]
    fn test_generated_profile_uses_native_arch() {
        let dir = tempfile::tempdir().unwrap();
        let trace_path = dir.path().join("trace.ndjson");
        std::fs::write(
            &trace_path,
            r#"{"syscall":0,"name":"read","count":1}
"#,
        )
        .unwrap();

        let profile = generate_from_trace(&trace_path).unwrap();
        assert_eq!(profile.architectures.len(), 1);
        assert_eq!(profile.architectures[0], native_scmp_arch());
    }
}
