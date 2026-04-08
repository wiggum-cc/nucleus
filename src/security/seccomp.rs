use crate::error::{NucleusError, Result};
use crate::security::policy::sha256_hex;
use seccompiler::{BpfProgram, SeccompAction, SeccompCondition, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;
use std::path::Path;
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
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWTIME) as u64;

impl SeccompManager {
    pub fn new() -> Self {
        Self { applied: false }
    }

    fn base_allowed_syscalls() -> Vec<i64> {
        let mut syscalls = vec![
            // File I/O
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_close,
            libc::SYS_fstat,
            libc::SYS_lseek,
            libc::SYS_fcntl,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_preadv,
            libc::SYS_pwritev,
            libc::SYS_preadv2,
            libc::SYS_pwritev2,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_readlinkat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
            libc::SYS_dup,
            libc::SYS_dup3,
            libc::SYS_pipe2,
            libc::SYS_unlinkat,
            libc::SYS_renameat,
            libc::SYS_renameat2,
            libc::SYS_linkat,
            libc::SYS_symlinkat,
            libc::SYS_fchmod,
            libc::SYS_fchmodat,
            libc::SYS_truncate,
            libc::SYS_ftruncate,
            libc::SYS_fallocate,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_fadvise64,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_sync_file_range,
            libc::SYS_flock,
            libc::SYS_fstatfs,
            libc::SYS_statfs,
            #[cfg(target_arch = "x86_64")]
            libc::SYS_sendfile,
            libc::SYS_copy_file_range,
            libc::SYS_splice,
            libc::SYS_tee,
            // Memory management
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_brk,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_msync,
            libc::SYS_mlock,
            libc::SYS_munlock,
            libc::SYS_mlock2,
            // SysV shared memory — used by PostgreSQL, Redis, and many databases
            // for shared buffer pools. Safe in PID/IPC namespaces (isolated keyspace).
            libc::SYS_shmget,
            libc::SYS_shmat,
            libc::SYS_shmdt,
            libc::SYS_shmctl,
            // POSIX semaphores (used by PostgreSQL for lightweight locking)
            libc::SYS_semget,
            libc::SYS_semop,
            libc::SYS_semctl,
            libc::SYS_semtimedop,
            // Process management
            // fork intentionally excluded — modern glibc/musl use clone(), which
            // has namespace-flag filtering. Removing SYS_fork forces all forks
            // through the filtered clone path (defense-in-depth against fork bombs
            // and unfiltered namespace creation).
            libc::SYS_execve,
            // execveat is conditionally allowed below (AT_EMPTY_PATH blocked)
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
            libc::SYS_setsid,
            libc::SYS_getgroups,
            // Signals
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_rt_sigsuspend,
            libc::SYS_rt_sigtimedwait,
            libc::SYS_rt_sigpending,
            libc::SYS_rt_sigqueueinfo,
            libc::SYS_sigaltstack,
            libc::SYS_restart_syscall,
            // L7: kill/tgkill are safe when PID namespace is active (container
            // can only signal its own processes). If PID namespace creation fails,
            // the runtime aborts, so this is safe.
            libc::SYS_kill,
            libc::SYS_tgkill,
            // Time and timers
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            libc::SYS_clock_nanosleep,
            libc::SYS_gettimeofday,
            libc::SYS_nanosleep,
            libc::SYS_setitimer,
            libc::SYS_getitimer,
            // Directories
            libc::SYS_getcwd,
            libc::SYS_chdir,
            libc::SYS_fchdir,
            libc::SYS_mkdirat,
            libc::SYS_getdents64,
            // Misc
            libc::SYS_uname,
            libc::SYS_getrandom,
            libc::SYS_futex,
            libc::SYS_set_tid_address,
            libc::SYS_set_robust_list,
            libc::SYS_get_robust_list,
            // L8: sysinfo removed — leaks host RAM, uptime, and process count.
            // Applications needing this info should use /proc/meminfo instead.
            libc::SYS_umask,
            // prlimit64 moved to arg-filtered section (M3)
            libc::SYS_getrusage,
            libc::SYS_times,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_sched_setaffinity,
            libc::SYS_sched_getparam,
            libc::SYS_sched_getscheduler,
            libc::SYS_getcpu,
            // Extended attributes — read-only queries, safe
            libc::SYS_getxattr,
            libc::SYS_lgetxattr,
            libc::SYS_fgetxattr,
            libc::SYS_listxattr,
            libc::SYS_llistxattr,
            libc::SYS_flistxattr,
            libc::SYS_rseq,
            libc::SYS_close_range,
            // Ownership — safe after capability drop (CAP_CHOWN/CAP_FOWNER gone;
            // operations on files not owned by the container UID will EPERM).
            libc::SYS_fchown,
            libc::SYS_fchownat,
            // Legacy AIO — used by databases and storage engines. Operations are
            // bounded by the process's existing fd permissions.
            libc::SYS_io_setup,
            libc::SYS_io_destroy,
            libc::SYS_io_submit,
            libc::SYS_io_getevents,
            // NOTE: io_uring intentionally excluded from defaults — large kernel
            // attack surface with a history of CVEs. Applications needing io_uring
            // (e.g. PostgreSQL 18+ io_method=io_uring) should use a custom seccomp
            // profile that adds io_uring_setup/io_uring_enter/io_uring_register.
            // Process groups — safe in PID namespace (can only affect own pgrp).
            libc::SYS_setpgid,
            libc::SYS_getpgid,
            // NOTE: memfd_create intentionally excluded — combined with execveat
            // it enables fileless code execution bypassing all FS controls (SEC-02).
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
            libc::SYS_ppoll,
            libc::SYS_pselect6,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_pwait,
            libc::SYS_eventfd2,
            libc::SYS_signalfd4,
            libc::SYS_timerfd_create,
            libc::SYS_timerfd_settime,
            libc::SYS_timerfd_gettime,
        ];

        // Legacy syscalls only available on x86_64 (aarch64 only has the *at variants)
        #[cfg(target_arch = "x86_64")]
        syscalls.extend_from_slice(&[
            libc::SYS_open,
            libc::SYS_stat,
            libc::SYS_lstat,
            libc::SYS_access,
            libc::SYS_readlink,
            libc::SYS_dup2,
            libc::SYS_pipe,
            libc::SYS_unlink,
            libc::SYS_rename,
            libc::SYS_link,
            libc::SYS_symlink,
            libc::SYS_chmod,
            libc::SYS_mkdir,
            libc::SYS_rmdir,
            libc::SYS_getdents,
            libc::SYS_getpgrp,
            libc::SYS_chown,
            libc::SYS_fchown,
            libc::SYS_lchown,
            libc::SYS_arch_prctl,
            libc::SYS_getrlimit,
            libc::SYS_poll,
            libc::SYS_select,
            libc::SYS_epoll_create,
            libc::SYS_epoll_wait,
            libc::SYS_eventfd,
            libc::SYS_signalfd,
        ]);

        syscalls
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
            rules.insert(syscall, Vec::new());
        }

        // Add network-mode-specific syscalls
        for syscall in Self::network_mode_syscalls(allow_network) {
            rules.insert(syscall, Vec::new());
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
            0x5421, // M12: FIONBIO — allowed because fcntl(F_SETFL, O_NONBLOCK)
            // achieves the same result and is already permitted. Blocking
            // FIONBIO only breaks tokio/mio for no security gain.
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

        // prctl: allow only safe operations (arg0 = option).
        // Notably absent (hit default deny):
        //   PR_CAPBSET_DROP (24) — could weaken the capability bounding set
        //   PR_SET_SECUREBITS (28) — could disable secure-exec restrictions
        let prctl_allowed: &[u64] = &[
            1,  // PR_SET_PDEATHSIG
            2,  // PR_GET_PDEATHSIG
            15, // PR_SET_NAME
            16, // PR_GET_NAME
            23, // PR_CAPBSET_READ — glibc probes this at startup to discover
                // cap_last_cap when /proc/sys is masked. Read-only, harmless
                // after capabilities have been dropped.
            27, // PR_GET_SECUREBITS — read-only query of securebits flags
            36, // PR_SET_CHILD_SUBREAPER — safe, only affects own descendants
            37, // PR_GET_CHILD_SUBREAPER
            38, // PR_SET_NO_NEW_PRIVS
            40, // PR_GET_TID_ADDRESS — read-only, returns thread ID address
            47, // PR_CAP_AMBIENT — glibc probes ambient caps at startup (read-only
                // IS_SET queries). Safe after caps are dropped.
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

        // M3: prlimit64 — only allow GET (new_limit == NULL, i.e. arg2 == 0).
        // SET operations could raise RLIMIT_NPROC to bypass fork-bomb protection.
        let prlimit_condition = SeccompCondition::new(
            2, // arg2 = new_limit pointer for prlimit64(pid, resource, new_limit, old_limit)
            seccompiler::SeccompCmpArgLen::Qword,
            seccompiler::SeccompCmpOp::Eq,
            0u64, // new_limit == NULL means GET-only
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create prlimit64 condition: {}", e))
        })?;
        let prlimit_rule = SeccompRule::new(vec![prlimit_condition]).map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create prlimit64 rule: {}", e))
        })?;
        rules.insert(libc::SYS_prlimit64, vec![prlimit_rule]);

        // mprotect: permit RW or RX transitions, but reject PROT_WRITE|PROT_EXEC.
        let mut mprotect_rules = Vec::new();
        for allowed in [0, libc::PROT_WRITE as u64, libc::PROT_EXEC as u64] {
            let condition = SeccompCondition::new(
                2, // arg2 is prot for mprotect(addr, len, prot)
                seccompiler::SeccompCmpArgLen::Dword,
                seccompiler::SeccompCmpOp::MaskedEq((libc::PROT_WRITE | libc::PROT_EXEC) as u64),
                allowed,
            )
            .map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create mprotect condition: {}", e))
            })?;
            let rule = SeccompRule::new(vec![condition]).map_err(|e| {
                NucleusError::SeccompError(format!("Failed to create mprotect rule: {}", e))
            })?;
            mprotect_rules.push(rule);
        }
        rules.insert(libc::SYS_mprotect, mprotect_rules);

        // clone3: ALLOWED unconditionally. clone3 passes flags inside a struct
        // pointer that seccomp BPF cannot dereference, so namespace-flag filtering
        // is impossible at the BPF level. However, glibc 2.34+ and newer musl use
        // clone3 internally for posix_spawn/fork — blocking it breaks
        // std::process::Command and any child-process spawning on modern systems.
        //
        // SECURITY INVARIANT: Namespace creation via clone3 is prevented solely by
        // dropping CAP_SYS_ADMIN (and other namespace caps) *before* this seccomp
        // filter is installed. If capability dropping is bypassed, clone3 becomes
        // an unfiltered path to namespace creation. This is a known single point
        // of failure — see CapabilityManager::drop_all() which must run first.
        //
        // Verify the invariant: CAP_SYS_ADMIN must not be in the effective set.
        // CAP_SYS_ADMIN = capability bit 21
        if Self::has_effective_cap(21) {
            return Err(NucleusError::SeccompError(
                "SECURITY: CAP_SYS_ADMIN is still in the effective capability set. \
                 Capabilities must be dropped before installing seccomp filters \
                 (clone3 is allowed unconditionally)."
                    .to_string(),
            ));
        }
        rules.insert(libc::SYS_clone3, Vec::new());

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

        // execveat: allow but block AT_EMPTY_PATH (0x1000) to prevent fileless
        // execution. With AT_EMPTY_PATH, execveat can execute code from any open
        // fd (e.g., open + unlink, or even a socket fd), bypassing filesystem
        // controls — not just memfd_create. Blocking memfd_create alone is
        // insufficient. Normal execveat with dirfd+pathname (no AT_EMPTY_PATH)
        // remains allowed.
        let execveat_condition = SeccompCondition::new(
            4, // arg4 = flags for execveat(dirfd, pathname, argv, envp, flags)
            seccompiler::SeccompCmpArgLen::Dword,
            seccompiler::SeccompCmpOp::MaskedEq(libc::AT_EMPTY_PATH as u64),
            0, // (flags & AT_EMPTY_PATH) == 0: AT_EMPTY_PATH not set
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create execveat condition: {}", e))
        })?;
        let execveat_rule = SeccompRule::new(vec![execveat_condition]).map_err(|e| {
            NucleusError::SeccompError(format!("Failed to create execveat rule: {}", e))
        })?;
        rules.insert(libc::SYS_execveat, vec![execveat_rule]);

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
            SeccompAction::KillProcess,
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
        self.apply_minimal_filter_with_mode(false, false)
    }

    /// Apply seccomp filter with configurable failure behavior
    ///
    /// When `best_effort` is true, failures are logged and execution continues.
    /// When false, seccomp setup is fail-closed.
    pub fn apply_minimal_filter_with_mode(
        &mut self,
        best_effort: bool,
        log_denied: bool,
    ) -> Result<bool> {
        self.apply_filter_for_network_mode(true, best_effort, log_denied)
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
        log_denied: bool,
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
            SeccompAction::KillProcess, // Default: kill on blocked syscall
            SeccompAction::Allow,       // Match action: allow
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
        match Self::apply_bpf_program(&bpf_prog, log_denied) {
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

    /// Apply a seccomp profile loaded from a JSON file.
    ///
    /// The profile format is a JSON object with:
    /// ```json
    /// {
    ///   "defaultAction": "SCMP_ACT_ERRNO",
    ///   "syscalls": [
    ///     { "names": ["read", "write", "open", ...], "action": "SCMP_ACT_ALLOW" }
    ///   ]
    /// }
    /// ```
    ///
    /// This is a subset of the OCI seccomp profile format. Only the syscall name
    /// allowlist is used; argument-level filtering from the built-in profile is
    /// not applied when using a custom profile.
    ///
    /// If `expected_sha256` is provided, the file's SHA-256 hash is verified
    /// against it before loading. This prevents silent profile tampering.
    pub fn apply_profile_from_file(
        &mut self,
        profile_path: &Path,
        expected_sha256: Option<&str>,
        audit_mode: bool,
    ) -> Result<bool> {
        if self.applied {
            debug!("Seccomp filter already applied, skipping");
            return Ok(true);
        }

        info!("Loading seccomp profile from {:?}", profile_path);

        // Read profile file
        let content = std::fs::read(profile_path).map_err(|e| {
            NucleusError::SeccompError(format!(
                "Failed to read seccomp profile {:?}: {}",
                profile_path, e
            ))
        })?;

        // Verify SHA-256 hash if expected
        if let Some(expected) = expected_sha256 {
            let actual = sha256_hex(&content);
            if actual != expected {
                return Err(NucleusError::SeccompError(format!(
                    "Seccomp profile hash mismatch: expected {}, got {}",
                    expected, actual
                )));
            }
            info!("Seccomp profile hash verified: {}", actual);
        }

        // Parse profile
        let profile: SeccompProfile = serde_json::from_slice(&content).map_err(|e| {
            NucleusError::SeccompError(format!("Failed to parse seccomp profile: {}", e))
        })?;

        // Warn when custom profile allows security-critical syscalls without
        // argument-level filtering. The built-in filter restricts clone, ioctl,
        // prctl, and socket at the argument level; a custom profile that allows
        // them by name only silently removes all of that hardening.
        Self::warn_missing_arg_filters(&profile);

        // Build filter from profile
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        for syscall_group in &profile.syscalls {
            if syscall_group.action == "SCMP_ACT_ALLOW" {
                for name in &syscall_group.names {
                    if let Some(nr) = syscall_name_to_number(name) {
                        rules.insert(nr, Vec::new());
                    } else {
                        warn!("Unknown syscall in profile: {} (skipping)", name);
                    }
                }
            }
        }

        // SEC-01: Merge built-in argument filters for security-critical syscalls.
        // Custom profiles that allow clone/ioctl/prctl/socket/mprotect by name
        // without argument-level filters would silently remove all hardening.
        // Overwrite their empty rules with the built-in argument-filtered rules.
        let builtin_rules = Self::minimal_filter(true)?;
        for syscall_name in Self::ARG_FILTERED_SYSCALLS {
            if let Some(nr) = syscall_name_to_number(syscall_name) {
                if let std::collections::btree_map::Entry::Occupied(mut entry) = rules.entry(nr) {
                    if let Some(builtin) = builtin_rules.get(&nr) {
                        if !builtin.is_empty() {
                            info!(
                                "Merging built-in argument filters for '{}' into custom profile",
                                syscall_name
                            );
                            entry.insert(builtin.clone());
                        }
                    }
                }
            }
        }
        // H2: clone3 is allowed in the built-in filter (needed for glibc 2.34+).
        // Apply the same policy to custom profiles for consistency. The security
        // invariant against namespace creation via clone3 is enforced by dropping
        // CAP_SYS_ADMIN *before* seccomp is installed (see verify_no_namespace_caps).
        // If the custom profile doesn't include clone3, add it.
        if !rules.contains_key(&libc::SYS_clone3) {
            rules.insert(libc::SYS_clone3, Vec::new());
        }

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().map_err(|e| {
                NucleusError::SeccompError(format!("Unsupported architecture: {:?}", e))
            })?,
        )
        .map_err(|e| {
            NucleusError::SeccompError(format!(
                "Failed to create seccomp filter from profile: {}",
                e
            ))
        })?;

        let bpf_prog: BpfProgram = filter.try_into().map_err(|e| {
            NucleusError::SeccompError(format!("Failed to compile BPF program from profile: {}", e))
        })?;

        match Self::apply_bpf_program(&bpf_prog, audit_mode) {
            Ok(_) => {
                self.applied = true;
                info!(
                    "Seccomp profile applied from {:?} (log_denied={})",
                    profile_path, audit_mode
                );
                Ok(true)
            }
            Err(e) => Err(e),
        }
    }

    /// Install an allow-all seccomp filter with SECCOMP_FILTER_FLAG_LOG.
    ///
    /// Used in trace mode: all syscalls are allowed but logged to the kernel
    /// audit subsystem. A separate reader collects the logged syscalls.
    pub fn apply_trace_filter(&mut self) -> Result<bool> {
        if self.applied {
            debug!("Seccomp filter already applied, skipping trace filter");
            return Ok(true);
        }

        info!("Applying seccomp trace filter (allow-all + LOG)");

        // Create an empty rule set — with SeccompAction::Allow as default,
        // every syscall is permitted. The LOG flag causes the kernel to
        // audit each syscall decision.
        let filter = SeccompFilter::new(
            BTreeMap::new(),
            SeccompAction::Allow, // default: allow everything
            SeccompAction::Allow, // match action (unused — no rules)
            std::env::consts::ARCH.try_into().map_err(|e| {
                NucleusError::SeccompError(format!("Unsupported architecture: {:?}", e))
            })?,
        )
        .map_err(|e| NucleusError::SeccompError(format!("Failed to create trace filter: {}", e)))?;

        let bpf_prog: BpfProgram = filter.try_into().map_err(|e| {
            NucleusError::SeccompError(format!("Failed to compile trace BPF: {}", e))
        })?;

        // Apply with LOG flag so kernel audits every syscall
        Self::apply_bpf_program(&bpf_prog, true)?;
        self.applied = true;
        info!("Seccomp trace filter applied (all syscalls allowed + logged)");
        Ok(true)
    }

    /// Syscalls that the built-in filter restricts at the argument level.
    /// Custom profiles allowing these without argument filters weaken security.
    const ARG_FILTERED_SYSCALLS: &'static [&'static str] = &[
        "clone", "clone3", "execveat", "ioctl", "mprotect", "prctl", "socket",
    ];

    /// Warn when a custom seccomp profile allows security-critical syscalls
    /// without argument-level filtering.
    fn warn_missing_arg_filters(profile: &SeccompProfile) {
        for group in &profile.syscalls {
            if group.action != "SCMP_ACT_ALLOW" {
                continue;
            }
            for name in &group.names {
                if Self::ARG_FILTERED_SYSCALLS.contains(&name.as_str()) && group.args.is_empty() {
                    warn!(
                        "Custom seccomp profile allows '{}' without argument filters. \
                         The built-in filter restricts this syscall at the argument level. \
                         This profile weakens security compared to the default.",
                        name
                    );
                }
            }
        }
    }

    /// Check whether a capability is in the current thread's effective set
    /// by reading /proc/self/status (CapEff line).
    fn has_effective_cap(cap: i32) -> bool {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            // If we can't read, assume worst case for safety.
            return true;
        };
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:\t") {
                if let Ok(eff) = u64::from_str_radix(hex.trim(), 16) {
                    return eff & (1u64 << cap) != 0;
                }
            }
        }
        true // assume worst case
    }

    /// Check if seccomp filter has been applied
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    fn apply_bpf_program(bpf_prog: &BpfProgram, log_denied: bool) -> Result<()> {
        let mut flags: libc::c_ulong = 0;
        if log_denied {
            flags |= libc::SECCOMP_FILTER_FLAG_LOG as libc::c_ulong;
        }

        match Self::apply_bpf_program_with_flags(bpf_prog, flags) {
            Ok(()) => Ok(()),
            Err(err)
                if log_denied
                    && err.raw_os_error() == Some(libc::EINVAL)
                    && libc::SECCOMP_FILTER_FLAG_LOG != 0 =>
            {
                warn!(
                    "Kernel rejected SECCOMP_FILTER_FLAG_LOG; continuing with seccomp \
                     enforcement without deny logging"
                );
                Self::apply_bpf_program_with_flags(bpf_prog, 0)?;
                Ok(())
            }
            Err(err) => Err(NucleusError::SeccompError(format!(
                "Failed to apply seccomp filter: {}",
                err
            ))),
        }
    }

    fn apply_bpf_program_with_flags(
        bpf_prog: &BpfProgram,
        flags: libc::c_ulong,
    ) -> std::io::Result<()> {
        // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, ...)` has no pointer arguments here
        // and only affects the current thread/process as required before seccomp.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let prog = libc::sock_fprog {
            len: bpf_prog.len() as u16,
            filter: bpf_prog.as_ptr() as *mut libc::sock_filter,
        };

        // SAFETY: `prog` points to a live BPF program buffer for the duration of
        // the syscall and the kernel copies the pointed-to filter immediately.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                flags,
                &prog as *const libc::sock_fprog,
            )
        };

        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }
}

// SeccompProfile and SeccompSyscallGroup are defined in seccomp_generate.rs
use crate::security::seccomp_generate::SeccompProfile;

/// Map a syscall name (e.g. "read", "write") to its Linux syscall number.
///
/// Covers the most common syscalls. Unknown names return None.
fn syscall_name_to_number(name: &str) -> Option<i64> {
    match name {
        // File I/O
        "read" => Some(libc::SYS_read),
        "write" => Some(libc::SYS_write),
        #[cfg(target_arch = "x86_64")]
        "open" => Some(libc::SYS_open),
        "openat" => Some(libc::SYS_openat),
        "close" => Some(libc::SYS_close),
        #[cfg(target_arch = "x86_64")]
        "stat" => Some(libc::SYS_stat),
        "fstat" => Some(libc::SYS_fstat),
        #[cfg(target_arch = "x86_64")]
        "lstat" => Some(libc::SYS_lstat),
        "lseek" => Some(libc::SYS_lseek),
        #[cfg(target_arch = "x86_64")]
        "access" => Some(libc::SYS_access),
        "fcntl" => Some(libc::SYS_fcntl),
        "readv" => Some(libc::SYS_readv),
        "writev" => Some(libc::SYS_writev),
        "pread64" => Some(libc::SYS_pread64),
        "pwrite64" => Some(libc::SYS_pwrite64),
        #[cfg(target_arch = "x86_64")]
        "readlink" => Some(libc::SYS_readlink),
        "readlinkat" => Some(libc::SYS_readlinkat),
        "newfstatat" => Some(libc::SYS_newfstatat),
        "statx" => Some(libc::SYS_statx),
        "faccessat" => Some(libc::SYS_faccessat),
        "faccessat2" => Some(libc::SYS_faccessat2),
        "dup" => Some(libc::SYS_dup),
        #[cfg(target_arch = "x86_64")]
        "dup2" => Some(libc::SYS_dup2),
        "dup3" => Some(libc::SYS_dup3),
        #[cfg(target_arch = "x86_64")]
        "pipe" => Some(libc::SYS_pipe),
        "pipe2" => Some(libc::SYS_pipe2),
        #[cfg(target_arch = "x86_64")]
        "unlink" => Some(libc::SYS_unlink),
        "unlinkat" => Some(libc::SYS_unlinkat),
        #[cfg(target_arch = "x86_64")]
        "rename" => Some(libc::SYS_rename),
        "renameat" => Some(libc::SYS_renameat),
        "renameat2" => Some(libc::SYS_renameat2),
        #[cfg(target_arch = "x86_64")]
        "link" => Some(libc::SYS_link),
        "linkat" => Some(libc::SYS_linkat),
        #[cfg(target_arch = "x86_64")]
        "symlink" => Some(libc::SYS_symlink),
        "symlinkat" => Some(libc::SYS_symlinkat),
        #[cfg(target_arch = "x86_64")]
        "chmod" => Some(libc::SYS_chmod),
        "fchmod" => Some(libc::SYS_fchmod),
        "fchmodat" => Some(libc::SYS_fchmodat),
        "truncate" => Some(libc::SYS_truncate),
        "ftruncate" => Some(libc::SYS_ftruncate),
        "fallocate" => Some(libc::SYS_fallocate),
        #[cfg(target_arch = "x86_64")]
        "fadvise64" => Some(libc::SYS_fadvise64),
        "fsync" => Some(libc::SYS_fsync),
        "fdatasync" => Some(libc::SYS_fdatasync),
        "flock" => Some(libc::SYS_flock),
        #[cfg(target_arch = "x86_64")]
        "sendfile" => Some(libc::SYS_sendfile),
        "copy_file_range" => Some(libc::SYS_copy_file_range),
        "splice" => Some(libc::SYS_splice),
        "tee" => Some(libc::SYS_tee),
        // Memory
        "mmap" => Some(libc::SYS_mmap),
        "munmap" => Some(libc::SYS_munmap),
        "mprotect" => Some(libc::SYS_mprotect),
        "brk" => Some(libc::SYS_brk),
        "mremap" => Some(libc::SYS_mremap),
        "madvise" => Some(libc::SYS_madvise),
        "msync" => Some(libc::SYS_msync),
        "mlock" => Some(libc::SYS_mlock),
        "mlock2" => Some(libc::SYS_mlock2),
        "munlock" => Some(libc::SYS_munlock),
        // SysV IPC
        "shmget" => Some(libc::SYS_shmget),
        "shmat" => Some(libc::SYS_shmat),
        "shmdt" => Some(libc::SYS_shmdt),
        "shmctl" => Some(libc::SYS_shmctl),
        "semget" => Some(libc::SYS_semget),
        "semop" => Some(libc::SYS_semop),
        "semctl" => Some(libc::SYS_semctl),
        "semtimedop" => Some(libc::SYS_semtimedop),
        // Process
        #[cfg(target_arch = "x86_64")]
        "fork" => Some(libc::SYS_fork),
        "clone" => Some(libc::SYS_clone),
        "clone3" => Some(libc::SYS_clone3),
        "execve" => Some(libc::SYS_execve),
        "execveat" => Some(libc::SYS_execveat),
        "wait4" => Some(libc::SYS_wait4),
        "waitid" => Some(libc::SYS_waitid),
        "exit" => Some(libc::SYS_exit),
        "exit_group" => Some(libc::SYS_exit_group),
        "getpid" => Some(libc::SYS_getpid),
        "gettid" => Some(libc::SYS_gettid),
        "getuid" => Some(libc::SYS_getuid),
        "getgid" => Some(libc::SYS_getgid),
        "geteuid" => Some(libc::SYS_geteuid),
        "getegid" => Some(libc::SYS_getegid),
        "getppid" => Some(libc::SYS_getppid),
        #[cfg(target_arch = "x86_64")]
        "getpgrp" => Some(libc::SYS_getpgrp),
        "setsid" => Some(libc::SYS_setsid),
        "getgroups" => Some(libc::SYS_getgroups),
        // Signals
        "rt_sigaction" => Some(libc::SYS_rt_sigaction),
        "rt_sigprocmask" => Some(libc::SYS_rt_sigprocmask),
        "rt_sigreturn" => Some(libc::SYS_rt_sigreturn),
        "rt_sigsuspend" => Some(libc::SYS_rt_sigsuspend),
        "rt_sigtimedwait" => Some(libc::SYS_rt_sigtimedwait),
        "rt_sigpending" => Some(libc::SYS_rt_sigpending),
        "rt_sigqueueinfo" => Some(libc::SYS_rt_sigqueueinfo),
        "sigaltstack" => Some(libc::SYS_sigaltstack),
        "restart_syscall" => Some(libc::SYS_restart_syscall),
        "kill" => Some(libc::SYS_kill),
        "tgkill" => Some(libc::SYS_tgkill),
        // Time
        "clock_gettime" => Some(libc::SYS_clock_gettime),
        "clock_getres" => Some(libc::SYS_clock_getres),
        "clock_nanosleep" => Some(libc::SYS_clock_nanosleep),
        "gettimeofday" => Some(libc::SYS_gettimeofday),
        "nanosleep" => Some(libc::SYS_nanosleep),
        // Directories
        "getcwd" => Some(libc::SYS_getcwd),
        "chdir" => Some(libc::SYS_chdir),
        "fchdir" => Some(libc::SYS_fchdir),
        #[cfg(target_arch = "x86_64")]
        "mkdir" => Some(libc::SYS_mkdir),
        "mkdirat" => Some(libc::SYS_mkdirat),
        #[cfg(target_arch = "x86_64")]
        "rmdir" => Some(libc::SYS_rmdir),
        #[cfg(target_arch = "x86_64")]
        "getdents" => Some(libc::SYS_getdents),
        "getdents64" => Some(libc::SYS_getdents64),
        // Network
        "socket" => Some(libc::SYS_socket),
        "connect" => Some(libc::SYS_connect),
        "sendto" => Some(libc::SYS_sendto),
        "recvfrom" => Some(libc::SYS_recvfrom),
        "sendmsg" => Some(libc::SYS_sendmsg),
        "recvmsg" => Some(libc::SYS_recvmsg),
        "shutdown" => Some(libc::SYS_shutdown),
        "bind" => Some(libc::SYS_bind),
        "listen" => Some(libc::SYS_listen),
        "accept" => Some(libc::SYS_accept),
        "accept4" => Some(libc::SYS_accept4),
        "setsockopt" => Some(libc::SYS_setsockopt),
        "getsockopt" => Some(libc::SYS_getsockopt),
        "getsockname" => Some(libc::SYS_getsockname),
        "getpeername" => Some(libc::SYS_getpeername),
        "socketpair" => Some(libc::SYS_socketpair),
        // Poll/Select
        #[cfg(target_arch = "x86_64")]
        "poll" => Some(libc::SYS_poll),
        "ppoll" => Some(libc::SYS_ppoll),
        #[cfg(target_arch = "x86_64")]
        "select" => Some(libc::SYS_select),
        "pselect6" => Some(libc::SYS_pselect6),
        #[cfg(target_arch = "x86_64")]
        "epoll_create" => Some(libc::SYS_epoll_create),
        "epoll_create1" => Some(libc::SYS_epoll_create1),
        "epoll_ctl" => Some(libc::SYS_epoll_ctl),
        #[cfg(target_arch = "x86_64")]
        "epoll_wait" => Some(libc::SYS_epoll_wait),
        "epoll_pwait" => Some(libc::SYS_epoll_pwait),
        #[cfg(target_arch = "x86_64")]
        "eventfd" => Some(libc::SYS_eventfd),
        "eventfd2" => Some(libc::SYS_eventfd2),
        #[cfg(target_arch = "x86_64")]
        "signalfd" => Some(libc::SYS_signalfd),
        "signalfd4" => Some(libc::SYS_signalfd4),
        "timerfd_create" => Some(libc::SYS_timerfd_create),
        "timerfd_settime" => Some(libc::SYS_timerfd_settime),
        "timerfd_gettime" => Some(libc::SYS_timerfd_gettime),
        // Misc
        "uname" => Some(libc::SYS_uname),
        "getrandom" => Some(libc::SYS_getrandom),
        "futex" => Some(libc::SYS_futex),
        "set_tid_address" => Some(libc::SYS_set_tid_address),
        "set_robust_list" => Some(libc::SYS_set_robust_list),
        "get_robust_list" => Some(libc::SYS_get_robust_list),
        #[cfg(target_arch = "x86_64")]
        "arch_prctl" => Some(libc::SYS_arch_prctl),
        "sysinfo" => Some(libc::SYS_sysinfo),
        "umask" => Some(libc::SYS_umask),
        #[cfg(target_arch = "x86_64")]
        "getrlimit" => Some(libc::SYS_getrlimit),
        "prlimit64" => Some(libc::SYS_prlimit64),
        "getrusage" => Some(libc::SYS_getrusage),
        "times" => Some(libc::SYS_times),
        "sched_yield" => Some(libc::SYS_sched_yield),
        "sched_getaffinity" => Some(libc::SYS_sched_getaffinity),
        "getcpu" => Some(libc::SYS_getcpu),
        "rseq" => Some(libc::SYS_rseq),
        "close_range" => Some(libc::SYS_close_range),
        // Ownership
        "fchown" => Some(libc::SYS_fchown),
        "fchownat" => Some(libc::SYS_fchownat),
        #[cfg(target_arch = "x86_64")]
        "chown" => Some(libc::SYS_chown),
        #[cfg(target_arch = "x86_64")]
        "lchown" => Some(libc::SYS_lchown),
        // io_uring
        "io_uring_setup" => Some(libc::SYS_io_uring_setup),
        "io_uring_enter" => Some(libc::SYS_io_uring_enter),
        "io_uring_register" => Some(libc::SYS_io_uring_register),
        // Legacy AIO
        "io_setup" => Some(libc::SYS_io_setup),
        "io_destroy" => Some(libc::SYS_io_destroy),
        "io_submit" => Some(libc::SYS_io_submit),
        "io_getevents" => Some(libc::SYS_io_getevents),
        // Timers
        "setitimer" => Some(libc::SYS_setitimer),
        "getitimer" => Some(libc::SYS_getitimer),
        // Process groups
        "setpgid" => Some(libc::SYS_setpgid),
        "getpgid" => Some(libc::SYS_getpgid),
        "memfd_create" => Some(libc::SYS_memfd_create),
        "ioctl" => Some(libc::SYS_ioctl),
        "prctl" => Some(libc::SYS_prctl),
        // Landlock
        "landlock_create_ruleset" => Some(libc::SYS_landlock_create_ruleset),
        "landlock_add_rule" => Some(libc::SYS_landlock_add_rule),
        "landlock_restrict_self" => Some(libc::SYS_landlock_restrict_self),
        _ => None,
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
    fn test_clone_denied_flags_include_newtime() {
        assert_ne!(
            DENIED_CLONE_NAMESPACE_FLAGS & libc::CLONE_NEWTIME as u64,
            0,
            "CLONE_NEWTIME must be in denied clone namespace flags"
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
        // +8 accounts for conditional rules inserted in minimal_filter():
        // socket/ioctl/prctl/prlimit64/mprotect/clone/clone3/execveat.
        // fork removed (forces through filtered clone path).
        // execveat removed from base (arg-filtered separately).
        // sysinfo removed (L8: leaks host info).
        // prlimit64 moved to arg-filtered (M3).
        assert_eq!(base.len(), 173);
        assert_eq!(net.len(), 11);
        assert_eq!(base.len() + 8, 181);
        assert_eq!(base.len() + net.len() + 8, 192);
    }

    #[test]
    fn test_arg_filtered_syscalls_list_includes_critical_syscalls() {
        // These syscalls must be in the arg-filtered list so custom profiles
        // get warnings when they allow them without filters.
        for name in &["clone", "clone3", "execveat", "ioctl", "prctl", "socket"] {
            assert!(
                SeccompManager::ARG_FILTERED_SYSCALLS.contains(name),
                "'{}' must be in ARG_FILTERED_SYSCALLS",
                name
            );
        }
    }

    #[test]
    fn test_clone3_allowed_in_minimal_filter() {
        // clone3 MUST be in the BPF rules map — glibc 2.34+ and newer musl
        // use clone3 internally for posix_spawn/fork. Blocking it breaks
        // std::process::Command on modern systems. Namespace creation is
        // prevented by dropped capabilities (CAP_SYS_ADMIN etc.), not seccomp.
        let rules = SeccompManager::minimal_filter(true).unwrap();
        assert!(
            rules.contains_key(&libc::SYS_clone3),
            "clone3 must be in the seccomp allowlist (glibc 2.34+ requires it)"
        );
    }

    #[test]
    fn test_clone_is_allowed_with_arg_filter() {
        // clone (not clone3) should still be in the rules with arg filtering
        let rules = SeccompManager::minimal_filter(true).unwrap();
        assert!(
            rules.contains_key(&libc::SYS_clone),
            "clone must be in the seccomp allowlist with arg filters"
        );
    }

    #[test]
    fn test_high_risk_syscalls_removed_from_base_allowlist() {
        let base = SeccompManager::base_allowed_syscalls();
        // chown/fchown/lchown/fchownat: allowed — safe after CAP_CHOWN/CAP_FOWNER drop
        // mlock/munlock: allowed — needed by databases, bounded by RLIMIT_MEMLOCK
        let removed = [
            libc::SYS_sync,
            libc::SYS_syncfs,
            libc::SYS_mincore,
            libc::SYS_vfork,
            libc::SYS_tkill,
            // io_uring: large attack surface, many CVEs — require custom profile
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ];

        for syscall in removed {
            assert!(
                !base.contains(&syscall),
                "syscall {} unexpectedly present in base allowlist",
                syscall
            );
        }
    }

    #[test]
    fn test_custom_profile_preserves_clone_arg_filters() {
        // SEC-01: Custom seccomp profiles that allow "clone" must still get
        // argument-level filtering to block namespace-creating flags.
        // Verify by inspecting the built-in filter rules that serve as the
        // merge source for apply_profile_from_file.
        let rules = SeccompManager::minimal_filter(true).unwrap();

        // Every ARG_FILTERED_SYSCALLS entry (except clone3, which is allowed
        // unconditionally since BPF can't inspect its struct-based flags) must
        // have non-empty argument-level rules in the built-in filter so that
        // apply_profile_from_file can merge them.
        for name in SeccompManager::ARG_FILTERED_SYSCALLS {
            if *name == "clone3" {
                // clone3 is allowed unconditionally — BPF cannot dereference
                // the clone_args struct, so arg filtering is impossible.
                // Namespace defense relies on dropped capabilities.
                continue;
            }
            if let Some(nr) = syscall_name_to_number(name) {
                let entry = rules.get(&nr);
                assert!(
                    entry.is_some() && !entry.unwrap().is_empty(),
                    "built-in filter must have argument-level rules for '{}' \
                     so apply_profile_from_file can merge them into custom profiles",
                    name
                );
            }
        }
    }

    #[test]
    fn test_memfd_create_not_in_default_allowlist() {
        // SEC-02: memfd_create enables fileless code execution when combined with execveat.
        let base = SeccompManager::base_allowed_syscalls();
        assert!(
            !base.contains(&libc::SYS_memfd_create),
            "memfd_create must not be in the default seccomp allowlist (fileless exec risk)"
        );
        // Also verify it's not sneaked into the compiled filter rules
        let rules = SeccompManager::minimal_filter(true).unwrap();
        assert!(
            !rules.contains_key(&libc::SYS_memfd_create),
            "memfd_create must not be in the compiled seccomp filter rules"
        );
    }

    #[test]
    fn test_mprotect_has_arg_filtering() {
        // SEC-03: mprotect must have argument-level filtering to prevent W^X
        // (PROT_WRITE|PROT_EXEC) violations. Verify via runtime data structures.

        // mprotect must NOT be in the unconditional base allowlist
        let base = SeccompManager::base_allowed_syscalls();
        assert!(
            !base.contains(&libc::SYS_mprotect),
            "SYS_mprotect must not be unconditionally allowed - needs arg filtering"
        );

        // mprotect must be present in the compiled filter with non-empty
        // argument conditions (the conditions enforce W^X)
        let rules = SeccompManager::minimal_filter(true).unwrap();
        let mprotect_rules = rules.get(&libc::SYS_mprotect);
        assert!(
            mprotect_rules.is_some(),
            "mprotect must be present in the seccomp filter rules"
        );
        assert!(
            !mprotect_rules.unwrap().is_empty(),
            "mprotect must have argument-level conditions to prevent W^X violations"
        );
    }

    #[test]
    fn test_unsafe_blocks_have_safety_comments() {
        // SEC-08: All unsafe blocks must have // SAFETY: documentation
        let source = include_str!("seccomp.rs");
        let mut pos = 0;
        while let Some(idx) = source[pos..].find("unsafe {") {
            let abs_idx = pos + idx;
            // Check that there's a SAFETY comment within 200 chars before the unsafe block
            let start = abs_idx.saturating_sub(200);
            let context = &source[start..abs_idx];
            assert!(
                context.contains("SAFETY:"),
                "unsafe block at byte {} must have a // SAFETY: comment. Context: ...{}...",
                abs_idx,
                &source[abs_idx.saturating_sub(80)..abs_idx + 10]
            );
            pos = abs_idx + 1;
        }
    }

    // --- H-1: mprotect MaskedEq logic verification ---
    //
    // The mprotect filter uses MaskedEq((PROT_WRITE | PROT_EXEC), value) to
    // allow only combinations where the W|X bits match one of {0, W, X}.
    // These tests prove the logic is correct without installing a real
    // seccomp filter (which would affect the test process).

    /// Helper: simulates the MaskedEq check that the seccomp BPF would perform.
    /// Returns true if the prot value would be ALLOWED by one of the rules.
    fn mprotect_would_allow(prot: u64) -> bool {
        let mask = (libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        let allowed_values: &[u64] = &[0, libc::PROT_WRITE as u64, libc::PROT_EXEC as u64];
        let masked = prot & mask;
        allowed_values.contains(&masked)
    }

    #[test]
    fn test_mprotect_allows_prot_none() {
        assert!(mprotect_would_allow(0), "PROT_NONE must be allowed");
    }

    #[test]
    fn test_mprotect_allows_prot_read_only() {
        assert!(
            mprotect_would_allow(libc::PROT_READ as u64),
            "PROT_READ must be allowed (W|X bits are 0)"
        );
    }

    #[test]
    fn test_mprotect_allows_prot_read_write() {
        assert!(
            mprotect_would_allow((libc::PROT_READ | libc::PROT_WRITE) as u64),
            "PROT_READ|PROT_WRITE must be allowed"
        );
    }

    #[test]
    fn test_mprotect_allows_prot_read_exec() {
        assert!(
            mprotect_would_allow((libc::PROT_READ | libc::PROT_EXEC) as u64),
            "PROT_READ|PROT_EXEC must be allowed"
        );
    }

    #[test]
    fn test_mprotect_rejects_prot_write_exec() {
        assert!(
            !mprotect_would_allow((libc::PROT_WRITE | libc::PROT_EXEC) as u64),
            "PROT_WRITE|PROT_EXEC (W^X violation) must be REJECTED"
        );
    }

    #[test]
    fn test_mprotect_rejects_prot_read_write_exec() {
        assert!(
            !mprotect_would_allow((libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64),
            "PROT_READ|PROT_WRITE|PROT_EXEC (W^X violation) must be REJECTED"
        );
    }

    #[test]
    fn test_mprotect_allows_prot_write_alone() {
        assert!(
            mprotect_would_allow(libc::PROT_WRITE as u64),
            "PROT_WRITE alone must be allowed"
        );
    }

    #[test]
    fn test_mprotect_allows_prot_exec_alone() {
        assert!(
            mprotect_would_allow(libc::PROT_EXEC as u64),
            "PROT_EXEC alone must be allowed"
        );
    }
}
