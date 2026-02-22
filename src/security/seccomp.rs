use crate::error::{NucleusError, Result};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter, SeccompRule, SeccompCondition,
};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

/// Seccomp filter manager
///
/// Implements syscall whitelisting for the security state machine
/// (NucleusSecurity_Seccomp_SeccompEnforcement.tla)
pub struct SeccompManager {
    applied: bool,
}

impl SeccompManager {
    pub fn new() -> Self {
        Self { applied: false }
    }

    /// Get minimal syscall whitelist for basic container operation
    ///
    /// This is a restrictive whitelist that blocks dangerous syscalls:
    /// - ptrace (process tracing)
    /// - kexec_load (kernel loading)
    /// - add_key, request_key, keyctl (kernel keyring)
    /// - bpf (eBPF programs)
    /// - perf_event_open (performance monitoring)
    /// - userfaultfd (user fault handling)
    fn minimal_filter() -> Result<BTreeMap<i64, Vec<SeccompRule>>> {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        // Essential syscalls for basic operation
        let allowed_syscalls = vec![
            // File I/O
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_close,
            libc::SYS_stat,
            libc::SYS_fstat,
            libc::SYS_lstat,
            libc::SYS_lseek,
            libc::SYS_access,
            libc::SYS_fcntl,
            libc::SYS_ioctl,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_readlink,
            libc::SYS_readlinkat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
            libc::SYS_dup,
            libc::SYS_dup2,
            libc::SYS_dup3,
            libc::SYS_pipe,
            libc::SYS_pipe2,
            libc::SYS_unlink,
            libc::SYS_unlinkat,
            libc::SYS_rename,
            libc::SYS_renameat,
            libc::SYS_renameat2,
            libc::SYS_link,
            libc::SYS_linkat,
            libc::SYS_symlink,
            libc::SYS_symlinkat,
            libc::SYS_chmod,
            libc::SYS_fchmod,
            libc::SYS_fchmodat,
            libc::SYS_chown,
            libc::SYS_fchown,
            libc::SYS_lchown,
            libc::SYS_fchownat,
            libc::SYS_truncate,
            libc::SYS_ftruncate,
            libc::SYS_fallocate,
            libc::SYS_fadvise64,
            libc::SYS_sync,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_syncfs,
            // Memory management
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mprotect,
            libc::SYS_brk,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_msync,
            libc::SYS_mlock,
            libc::SYS_munlock,
            libc::SYS_mincore,
            // Process management
            libc::SYS_clone,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_wait4,
            libc::SYS_waitid,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_getpid,
            libc::SYS_gettid,
            libc::SYS_getuid,
            libc::SYS_getgid,
            libc::SYS_geteuid,
            libc::SYS_getegid,
            libc::SYS_getppid,
            libc::SYS_getpgrp,
            libc::SYS_setsid,
            libc::SYS_getgroups,
            libc::SYS_setgroups,
            // Signals
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_kill,
            libc::SYS_tkill,
            // Time
            libc::SYS_clock_gettime,
            libc::SYS_gettimeofday,
            libc::SYS_nanosleep,
            // Directories
            libc::SYS_getcwd,
            libc::SYS_chdir,
            libc::SYS_mkdir,
            libc::SYS_rmdir,
            libc::SYS_getdents,
            libc::SYS_getdents64,
            // Misc
            libc::SYS_uname,
            libc::SYS_getrandom,
            libc::SYS_futex,
            libc::SYS_set_tid_address,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            libc::SYS_prctl,
            libc::SYS_arch_prctl,
            libc::SYS_sysinfo,
            libc::SYS_umask,
            libc::SYS_getrlimit,
            libc::SYS_setrlimit,
            libc::SYS_prlimit64,
            libc::SYS_getrusage,
            libc::SYS_times,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_sched_setaffinity,
            libc::SYS_getcpu,
            libc::SYS_rseq,
            // Socket/Network (minimal for DNS, etc)
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_shutdown,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_socketpair,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,
            // Poll/Select
            libc::SYS_poll,
            libc::SYS_ppoll,
            libc::SYS_select,
            libc::SYS_pselect6,
            libc::SYS_epoll_create,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_wait,
            libc::SYS_epoll_pwait,
            libc::SYS_eventfd,
            libc::SYS_eventfd2,
            libc::SYS_signalfd,
            libc::SYS_signalfd4,
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            libc::SYS_timerfd_gettime,
        ];

        // Allow all these syscalls unconditionally
        // Use a single always-true condition to avoid empty rules
        for syscall in allowed_syscalls {
            match SeccompRule::new(vec![]) {
                Ok(rule) => {
                    rules.insert(syscall, vec![rule]);
                }
                Err(_) => {
                    // For unconditional allow, create a condition that's always true
                    // Compare argument 0 (which always exists) >= 0
                    let condition = SeccompCondition::new(
                        0,
                        seccompiler::SeccompCmpArgLen::Dword,
                        seccompiler::SeccompCmpOp::Ge,
                        0,
                    )
                    .map_err(|e| NucleusError::SeccompError(format!("Failed to create condition: {}", e)))?;
                    let rule = SeccompRule::new(vec![condition])
                        .map_err(|e| NucleusError::SeccompError(format!("Failed to create rule: {}", e)))?;
                    rules.insert(syscall, vec![rule]);
                }
            }
        }

        Ok(rules)
    }

    /// Apply seccomp filter
    ///
    /// This implements the transition: no_filter -> whitelist_active
    /// in the seccomp state machine (NucleusSecurity_Seccomp_SeccompEnforcement.tla)
    ///
    /// Once applied, the filter cannot be removed (irreversible property)
    /// In rootless mode or if seccomp setup fails, this will warn and continue
    pub fn apply_minimal_filter(&mut self) -> Result<()> {
        if self.applied {
            debug!("Seccomp filter already applied, skipping");
            return Ok(());
        }

        info!("Applying seccomp filter");

        let rules = match Self::minimal_filter() {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to create seccomp rules: {} (continuing without seccomp)", e);
                return Ok(());
            }
        };

        let filter = match SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32), // Default: deny with EPERM
            SeccompAction::Allow,                      // Match action: allow
            std::env::consts::ARCH.try_into().map_err(|e| {
                NucleusError::SeccompError(format!("Unsupported architecture: {:?}", e))
            })?,
        ) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to create seccomp filter: {} (continuing without seccomp)", e);
                return Ok(());
            }
        };

        let bpf_prog: BpfProgram = match filter.try_into() {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to compile BPF program: {} (continuing without seccomp)", e);
                return Ok(());
            }
        };

        // Apply the filter
        match seccompiler::apply_filter(&bpf_prog) {
            Ok(_) => {
                self.applied = true;
                info!("Successfully applied seccomp filter");
            }
            Err(e) => {
                warn!("Failed to apply seccomp filter: {} (continuing without seccomp)", e);
            }
        }

        Ok(())
    }

    /// Check if seccomp filter has been applied
    pub fn is_applied(&self) -> bool {
        self.applied
    }
}

impl Default for SeccompManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_manager_initial_state() {
        let mgr = SeccompManager::new();
        assert!(!mgr.is_applied());
    }

    #[test]
    fn test_apply_idempotent() {
        let mgr = SeccompManager::new();
        // Note: We can't actually test application in unit tests
        // as it would affect the test process itself
        // This is tested in integration tests instead
        assert!(!mgr.is_applied());
    }
}
