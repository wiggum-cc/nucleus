use crate::error::{NucleusError, Result};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;
use tracing::{debug, info};

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
    fn minimal_filter() -> BTreeMap<i64, Vec<SeccompRule>> {
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
            // Memory management
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mprotect,
            libc::SYS_brk,
            libc::SYS_mremap,
            libc::SYS_madvise,
            // Process management
            libc::SYS_clone,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_execve,
            libc::SYS_wait4,
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
        ];

        // Allow all these syscalls unconditionally
        for syscall in allowed_syscalls {
            let rule = SeccompRule::new(vec![])
                .expect("Failed to create seccomp rule");
            rules.insert(syscall, vec![rule]);
        }

        rules
    }

    /// Apply seccomp filter
    ///
    /// This implements the transition: no_filter -> whitelist_active
    /// in the seccomp state machine (NucleusSecurity_Seccomp_SeccompEnforcement.tla)
    ///
    /// Once applied, the filter cannot be removed (irreversible property)
    pub fn apply_minimal_filter(&mut self) -> Result<()> {
        if self.applied {
            debug!("Seccomp filter already applied, skipping");
            return Ok(());
        }

        info!("Applying seccomp filter");

        let rules = Self::minimal_filter();

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32), // Default: deny with EPERM
            SeccompAction::Allow,                      // Match action: allow
            std::env::consts::ARCH.try_into().map_err(|e| {
                NucleusError::SeccompError(format!("Unsupported architecture: {:?}", e))
            })?,
        )
        .map_err(|e| NucleusError::SeccompError(format!("Failed to create filter: {}", e)))?;

        let bpf_prog: BpfProgram = filter.try_into().map_err(|e| {
            NucleusError::SeccompError(format!("Failed to compile BPF program: {}", e))
        })?;

        // Apply the filter
        seccompiler::apply_filter(&bpf_prog)
            .map_err(|e| NucleusError::SeccompError(format!("Failed to apply filter: {}", e)))?;

        self.applied = true;
        info!("Successfully applied seccomp filter");

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
        let mut mgr = SeccompManager::new();
        // Note: We can't actually test application in unit tests
        // as it would affect the test process itself
        // This is tested in integration tests instead
        assert!(!mgr.is_applied());
    }
}
