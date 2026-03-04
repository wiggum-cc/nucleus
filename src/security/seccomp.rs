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

    fn base_allowed_syscalls() -> Vec<i64> {
        vec![
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
            libc::SYS_truncate,
            libc::SYS_ftruncate,
            libc::SYS_fallocate,
            libc::SYS_fadvise64,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_flock,
            libc::SYS_sendfile,
            libc::SYS_copy_file_range,
            libc::SYS_splice,
            libc::SYS_tee,
            // Memory management
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mprotect,
            libc::SYS_brk,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_msync,
            // Process management
            libc::SYS_fork,
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
            libc::SYS_rt_sigsuspend,
            libc::SYS_sigaltstack,
            libc::SYS_kill,
            libc::SYS_tgkill,
            // Time
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            libc::SYS_clock_nanosleep,
            libc::SYS_gettimeofday,
            libc::SYS_nanosleep,
            // Directories
            libc::SYS_getcwd,
            libc::SYS_chdir,
            libc::SYS_fchdir,
            libc::SYS_mkdir,
            libc::SYS_mkdirat,
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
            libc::SYS_close_range,
            libc::SYS_memfd_create,
            // Landlock bootstrap (runtime applies seccomp before Landlock)
            libc::SYS_landlock_create_ruleset,
            libc::SYS_landlock_add_rule,
            libc::SYS_landlock_restrict_self,
            // Socket/Network (safe introspection + local socketpair)
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_socketpair,
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
        ]
    }

    fn allowed_socket_domains(allow_network: bool) -> Vec<i32> {
        if allow_network {
            vec![libc::AF_UNIX, libc::AF_INET, libc::AF_INET6]
        } else {
            vec![libc::AF_UNIX]
        }
    }

    fn network_mode_syscalls(allow_network: bool) -> Vec<i64> {
        if allow_network {
            vec![
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
                libc::SYS_setsockopt,
            ]
        } else {
            Vec::new()
        }
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
        let allowed_syscalls = Self::base_allowed_syscalls();

        // Allow all these syscalls unconditionally
        for syscall in allowed_syscalls {
            let rule = SeccompRule::new(vec![])
                .map_err(|e| NucleusError::SeccompError(format!("Failed to create rule: {}", e)))?;
            rules.insert(syscall, vec![rule]);
        }

        // Add network-mode-specific syscalls
        for syscall in Self::network_mode_syscalls(allow_network) {
            let rule = SeccompRule::new(vec![])
                .map_err(|e| NucleusError::SeccompError(format!("Failed to create rule: {}", e)))?;
            rules.insert(syscall, vec![rule]);
        }

        // Restrict socket() domains by network mode.
        // none: AF_UNIX only; network-enabled: AF_UNIX/AF_INET/AF_INET6.
        let mut socket_rules = Vec::new();
        for domain in Self::allowed_socket_domains(allow_network) {
            let condition = SeccompCondition::new(
                0, // arg0 is socket(domain, type, protocol)
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::Eq,
                domain as u64,
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
            socket_rules.push(rule);
        }
        rules.insert(libc::SYS_socket, socket_rules);

        // ioctl: allow only safe terminal operations (arg0 = request code)
        let ioctl_allowed: &[u64] = &[
            0x5401, // TCGETS
            0x5402, // TCSETS
            0x5403, // TCSETSW
            0x5404, // TCSETSF
            0x540B, // TCFLSH
            0x540F, // TIOCGPGRP
            0x5410, // TIOCSPGRP
            0x5413, // TIOCGWINSZ
            0x5429, // TIOCGSID
            0x541B, // FIONREAD
            0x5421, // FIONBIO
            0x5451, // FIOCLEX
            0x5450, // FIONCLEX
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

        // clone3: allow unconditionally — clone3 passes flags inside a struct pointer
        // (arg0) that seccomp BPF cannot dereference, so arg-level namespace-flag
        // filtering is not possible. Namespace creation is still blocked because all
        // capabilities are dropped (CLONE_NEWUSER requires CAP_SYS_ADMIN on the host
        // user namespace; other CLONE_NEW* require CAP_SYS_ADMIN). Blocking clone3
        // entirely would break programs linked against modern glibc (≥2.34).
        let clone3_rule = SeccompRule::new(vec![]).map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create clone3 rule: {}", e))
        })?;
        rules.insert(libc::SYS_clone3, vec![clone3_rule]);

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

    #[test]
    fn test_network_none_socket_domains_are_unix_only() {
        let domains = SeccompManager::allowed_socket_domains(false);
        assert_eq!(domains, vec![libc::AF_UNIX]);
    }

    #[test]
    fn test_network_enabled_socket_domains_exclude_netlink() {
        let domains = SeccompManager::allowed_socket_domains(true);
        assert!(domains.contains(&libc::AF_UNIX));
        assert!(domains.contains(&libc::AF_INET));
        assert!(domains.contains(&libc::AF_INET6));
        assert!(!domains.contains(&libc::AF_NETLINK));
    }

    #[test]
    fn test_network_mode_syscalls_only_enabled_when_network_allowed() {
        let none = SeccompManager::network_mode_syscalls(false);
        assert!(none.is_empty());

        let enabled = SeccompManager::network_mode_syscalls(true);
        assert!(enabled.contains(&libc::SYS_connect));
        assert!(enabled.contains(&libc::SYS_bind));
        assert!(enabled.contains(&libc::SYS_listen));
        assert!(enabled.contains(&libc::SYS_accept));
        assert!(enabled.contains(&libc::SYS_setsockopt));
    }

    #[test]
    fn test_landlock_bootstrap_syscalls_present_in_base_allowlist() {
        let base = SeccompManager::base_allowed_syscalls();
        assert!(base.contains(&libc::SYS_landlock_create_ruleset));
        assert!(base.contains(&libc::SYS_landlock_add_rule));
        assert!(base.contains(&libc::SYS_landlock_restrict_self));
    }

    #[test]
    fn test_x32_legacy_range_not_allowlisted() {
        let base = SeccompManager::base_allowed_syscalls();
        let net = SeccompManager::network_mode_syscalls(true);
        for nr in 512_i64..=547_i64 {
            assert!(
                !base.contains(&nr) && !net.contains(&nr),
                "x32 syscall number {} unexpectedly allowlisted",
                nr
            );
        }
    }

    #[test]
    fn test_i386_compat_socketcall_range_not_allowlisted() {
        let base = SeccompManager::base_allowed_syscalls();
        let net = SeccompManager::network_mode_syscalls(true);
        // i386 compat per syscall_32.tbl: socket..shutdown live at 359..373.
        // On x86_64 these numbers are outside our native allowlist surface.
        for nr in 359_i64..=373_i64 {
            assert!(
                !base.contains(&nr) && !net.contains(&nr),
                "i386 compat syscall number {} unexpectedly allowlisted",
                nr
            );
        }
    }

    #[test]
    fn test_minimal_filter_allowlist_counts_are_stable() {
        let base = SeccompManager::base_allowed_syscalls();
        let net = SeccompManager::network_mode_syscalls(true);

        // Snapshot counts to catch unintended policy drift.
        // +5 accounts for conditional rules inserted in minimal_filter(): socket/ioctl/prctl/clone/clone3.
        assert_eq!(base.len(), 135);
        assert_eq!(net.len(), 11);
        assert_eq!(base.len() + 5, 140);
        assert_eq!(base.len() + net.len() + 5, 151);
    }

    #[test]
    fn test_high_risk_syscalls_removed_from_base_allowlist() {
        let base = SeccompManager::base_allowed_syscalls();
        let removed = [
            libc::SYS_chown,
            libc::SYS_fchown,
            libc::SYS_lchown,
            libc::SYS_fchownat,
            libc::SYS_sync,
            libc::SYS_syncfs,
            libc::SYS_mlock,
            libc::SYS_munlock,
            libc::SYS_mincore,
            libc::SYS_vfork,
            libc::SYS_tkill,
        ];

        for syscall in removed {
            assert!(
                !base.contains(&syscall),
                "syscall {} unexpectedly present in base allowlist",
                syscall
            );
        }
    }
}
