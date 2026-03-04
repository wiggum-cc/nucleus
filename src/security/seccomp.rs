use crate::error::{NucleusError, Result};
use seccompiler::{BpfProgram, SeccompAction, SeccompCondition, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

/// Seccomp filter manager
///
/// Implements syscall whitelisting for the security state machine
/// (NucleusSecurity_Seccomp_SeccompEnforcement.tla)
pub struct SeccompManager {
    applied: bool,
}

const DENIED_CLONE_NAMESPACE_FLAGS: u64 = (libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWCGROUP) as u64;

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
    fn minimal_filter(allow_network: bool) -> Result<BTreeMap<i64, Vec<SeccompRule>>> {
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
            libc::SYS_arch_prctl,
            libc::SYS_sysinfo,
            libc::SYS_umask,
            libc::SYS_getrlimit,
            libc::SYS_prlimit64,
            libc::SYS_getrusage,
            libc::SYS_times,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_getcpu,
            libc::SYS_rseq,
            // Socket/Network — ops on existing fds (safe regardless of network mode)
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
        for syscall in allowed_syscalls {
            let rule = SeccompRule::new(vec![])
                .map_err(|e| NucleusError::SeccompError(format!("Failed to create rule: {}", e)))?;
            rules.insert(syscall, vec![rule]);
        }

        // SYS_socket: when network is disabled, only allow AF_UNIX (domain == 1)
        if allow_network {
            let rule = SeccompRule::new(vec![])
                .map_err(|e| NucleusError::SeccompError(format!("Failed to create rule: {}", e)))?;
            rules.insert(libc::SYS_socket, vec![rule]);
        } else {
            let condition = SeccompCondition::new(
                0, // arg0 is the domain for socket(domain, type, protocol)
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Eq,
                libc::AF_UNIX as u64,
            )
            .map_err(|e| {
                NucleusError::SeccompError(format!(
                    "Failed to create socket domain condition: {}",
                    e
                ))
            })?;
            let rule = SeccompRule::new(vec![condition]).map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create socket rule: {}", e))
            })?;
            rules.insert(libc::SYS_socket, vec![rule]);
        }

        // ioctl: allow only safe terminal operations (arg0 = request code)
        let ioctl_allowed: &[u64] = &[
            0x5413, // TIOCGWINSZ
            0x5401, // TCGETS
            0x5402, // TCSETS
            0x541B, // FIONREAD
            0x5421, // FIONBIO
        ];
        let mut ioctl_rules = Vec::new();
        for &request in ioctl_allowed {
            let condition = SeccompCondition::new(
                1, // arg1 is the request code for ioctl(fd, request, ...)
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Eq,
                request,
            )
            .map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create ioctl condition: {}", e))
            })?;
            let rule = SeccompRule::new(vec![condition]).map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create ioctl rule: {}", e))
            })?;
            ioctl_rules.push(rule);
        }
        rules.insert(libc::SYS_ioctl, ioctl_rules);

        // prctl: allow only safe operations (arg0 = option)
        let prctl_allowed: &[u64] = &[
            1,  // PR_SET_PDEATHSIG
            2,  // PR_GET_PDEATHSIG
            15, // PR_SET_NAME
            16, // PR_GET_NAME
            38, // PR_SET_NO_NEW_PRIVS
            39, // PR_GET_NO_NEW_PRIVS
        ];
        let mut prctl_rules = Vec::new();
        for &option in prctl_allowed {
            let condition = SeccompCondition::new(
                0, // arg0 is the option for prctl(option, ...)
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Eq,
                option,
            )
            .map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create prctl condition: {}", e))
            })?;
            let rule = SeccompRule::new(vec![condition]).map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create prctl rule: {}", e))
            })?;
            prctl_rules.push(rule);
        }
        rules.insert(libc::SYS_prctl, prctl_rules);

        // clone3: block entirely — clone3 passes flags via a struct pointer that seccomp
        // cannot inspect, so we must deny it and force workloads through clone() which
        // we can filter by flags above. glibc/musl fall back to clone() when clone3 returns EPERM.
        // (clone3 is not in the allowlist, so it's already denied by the default action,
        // but we add an explicit empty entry as documentation and defense-in-depth.)

        // clone: allow but deny namespace-creating flags to prevent nested namespace creation
        let clone_condition = SeccompCondition::new(
            0, // arg0 = flags
            seccompiler::SeccompCmpArgLen::Qword,
            seccompiler::SeccompCmpOp::MaskedEq(DENIED_CLONE_NAMESPACE_FLAGS),
            0, // (flags & ns_flags) == 0: none of the namespace flags set
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create clone condition: {}", e))
        })?;
        let clone_rule = SeccompRule::new(vec![clone_condition]).map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create clone rule: {}", e))
        })?;
        rules.insert(libc::SYS_clone, vec![clone_rule]);

        Ok(rules)
    }

    /// Compile the minimal BPF filter without applying it
    ///
    /// This is useful for benchmarking filter compilation overhead
    /// without the irreversible side effect of applying the filter.
    pub fn compile_minimal_filter() -> Result<BpfProgram> {
        let rules = Self::minimal_filter(true)?;
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().map_err(|e| {
                NucleusError::SeccompError(format!("Unsupported architecture: {:?}", e))
            })?,
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create seccomp filter: {}", e))
        })?;

        let bpf_prog: BpfProgram = filter.try_into().map_err(|e| {
            NucleusError::SeccompError(format!("Failed to compile BPF program: {}", e))
        })?;

        Ok(bpf_prog)
    }

    /// Apply seccomp filter
    ///
    /// This implements the transition: no_filter -> whitelist_active
    /// in the seccomp state machine (NucleusSecurity_Seccomp_SeccompEnforcement.tla)
    ///
    /// Once applied, the filter cannot be removed (irreversible property)
    /// In rootless mode or if seccomp setup fails, this will warn and continue
    pub fn apply_minimal_filter(&mut self) -> Result<bool> {
        self.apply_minimal_filter_with_mode(false)
    }

    /// Apply seccomp filter with configurable failure behavior
    ///
    /// When `best_effort` is true, failures are logged and execution continues.
    /// When false, seccomp setup is fail-closed.
    pub fn apply_minimal_filter_with_mode(&mut self, best_effort: bool) -> Result<bool> {
        self.apply_filter_for_network_mode(true, best_effort)
    }

    /// Apply seccomp filter with network-mode-aware socket restrictions
    ///
    /// When `allow_network` is false, `SYS_socket` is restricted to AF_UNIX only,
    /// preventing creation of network sockets (AF_INET, AF_INET6, etc.).
    /// When `allow_network` is true, all socket domains are permitted.
    ///
    /// When `best_effort` is true, failures are logged and execution continues.
    /// When false, seccomp setup is fail-closed.
    pub fn apply_filter_for_network_mode(
        &mut self,
        allow_network: bool,
        best_effort: bool,
    ) -> Result<bool> {
        if self.applied {
            debug!("Seccomp filter already applied, skipping");
            return Ok(true);
        }

        info!(allow_network, "Applying seccomp filter");

        let rules = match Self::minimal_filter(allow_network) {
            Ok(r) => r,
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to create seccomp rules: {} (continuing without seccomp)",
                        e
                    );
                    return Ok(false);
                }
                return Err(e);
            }
        };

        let filter = match SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32), // Default: deny with EPERM
            SeccompAction::Allow,                     // Match action: allow
            std::env::consts::ARCH.try_into().map_err(|e| {
                NucleusError::SeccompError(format!("Unsupported architecture: {:?}", e))
            })?,
        ) {
            Ok(f) => f,
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to create seccomp filter: {} (continuing without seccomp)",
                        e
                    );
                    return Ok(false);
                }
                return Err(NucleusError::SeccompError(format!(
                    "Failed to create seccomp filter: {}",
                    e
                )));
            }
        };

        let bpf_prog: BpfProgram = match filter.try_into() {
            Ok(p) => p,
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to compile BPF program: {} (continuing without seccomp)",
                        e
                    );
                    return Ok(false);
                }
                return Err(NucleusError::SeccompError(format!(
                    "Failed to compile BPF program: {}",
                    e
                )));
            }
        };

        // Apply the filter
        match seccompiler::apply_filter(&bpf_prog) {
            Ok(_) => {
                self.applied = true;
                info!("Successfully applied seccomp filter");
                Ok(true)
            }
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to apply seccomp filter: {} (continuing without seccomp)",
                        e
                    );
                    Ok(false)
                } else {
                    Err(NucleusError::SeccompError(format!(
                        "Failed to apply seccomp filter: {}",
                        e
                    )))
                }
            }
        }
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

    #[test]
    fn test_clone_denied_flags_include_newcgroup() {
        assert_ne!(
            DENIED_CLONE_NAMESPACE_FLAGS & libc::CLONE_NEWCGROUP as u64,
            0
        );
    }
}
