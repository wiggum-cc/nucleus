use crate::error::{NucleusError, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use tracing::{debug, info, warn};

/// Target ABI – covers up to Linux 6.12 features (Truncate, IoctlDev, Refer, etc.).
/// The landlock crate gracefully degrades for older kernels.
const TARGET_ABI: ABI = ABI::V5;

/// Landlock filesystem access-control manager
///
/// Implements fine-grained, path-based filesystem restrictions as an additional
/// defense layer on top of namespaces, capabilities, and seccomp.
///
/// Properties (matching Nucleus security invariants):
/// - Irreversible: once restrict_self() is called, restrictions cannot be lifted
/// - Stackable: layered with seccomp and capability dropping
/// - Unprivileged: works in rootless mode
pub struct LandlockManager {
    applied: bool,
}

impl LandlockManager {
    pub fn new() -> Self {
        Self { applied: false }
    }

    /// Apply the container Landlock policy.
    ///
    /// Rules:
    /// - `/` (root):         read-only traversal (ReadDir) so path resolution works
    /// - `/bin`, `/usr`:     read + execute (for running agent binaries)
    /// - `/lib`, `/lib64`:   read (shared libraries)
    /// - `/etc`:             read (config / resolv.conf / nsswitch)
    /// - `/dev`:             read (already minimal device nodes)
    /// - `/proc`:            read (already mounted read-only)
    /// - `/tmp`:             read + write + create + remove (agent scratch space)
    /// - `/context`:         read-only (pre-populated agent data)
    ///
    /// Everything else is denied by the ruleset.
    pub fn apply_container_policy(&mut self) -> Result<bool> {
        self.apply_container_policy_with_mode(false)
    }

    /// Apply with configurable failure behavior.
    ///
    /// When `best_effort` is true, failures (e.g. kernel without Landlock) are
    /// logged and execution continues.
    pub fn apply_container_policy_with_mode(&mut self, best_effort: bool) -> Result<bool> {
        if self.applied {
            debug!("Landlock policy already applied, skipping");
            return Ok(true);
        }

        info!("Applying Landlock filesystem policy");

        match self.build_and_restrict() {
            Ok(status) => match status {
                RulesetStatus::FullyEnforced => {
                    self.applied = true;
                    info!("Landlock policy fully enforced");
                    Ok(true)
                }
                RulesetStatus::PartiallyEnforced => {
                    self.applied = true;
                    info!("Landlock policy partially enforced (kernel lacks some access rights)");
                    Ok(true)
                }
                RulesetStatus::NotEnforced => {
                    warn!("Landlock not enforced (kernel does not support Landlock)");
                    Ok(false)
                }
            },
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to apply Landlock policy: {} (continuing without Landlock)",
                        e
                    );
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Build the ruleset and call restrict_self().
    fn build_and_restrict(&self) -> Result<RulesetStatus> {
        let access_all = AccessFs::from_all(TARGET_ABI);
        let access_read = AccessFs::from_read(TARGET_ABI);

        // Read + execute for binary paths
        let access_read_exec = access_read | AccessFs::Execute;

        // Write access set for /tmp
        let access_tmp = access_all;

        let mut ruleset = Ruleset::default()
            .handle_access(access_all)
            .map_err(ll_err)?
            .create()
            .map_err(ll_err)?;

        // Root directory: minimal traversal only
        // We add ReadDir so that path resolution through / works
        if let Ok(fd) = PathFd::new("/") {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, AccessFs::ReadDir))
                .map_err(ll_err)?;
        }

        // Binary paths: read + execute
        for path in &["/bin", "/usr", "/sbin"] {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, access_read_exec))
                    .map_err(ll_err)?;
            }
        }

        // Shared libraries: read
        for path in &["/lib", "/lib64", "/lib32"] {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, access_read))
                    .map_err(ll_err)?;
            }
        }

        // Config/device/proc: read
        for path in &["/etc", "/dev", "/proc"] {
            if let Ok(fd) = PathFd::new(path) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, access_read))
                    .map_err(ll_err)?;
            }
        }

        // /tmp: full read+write+create+remove
        if let Ok(fd) = PathFd::new("/tmp") {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access_tmp))
                .map_err(ll_err)?;
        }

        // /context: read-only (agent data)
        if let Ok(fd) = PathFd::new("/context") {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, access_read))
                .map_err(ll_err)?;
        }

        let status = ruleset.restrict_self().map_err(ll_err)?;
        Ok(status.ruleset)
    }

    /// Check if Landlock policy has been applied
    pub fn is_applied(&self) -> bool {
        self.applied
    }
}

impl Default for LandlockManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a landlock RulesetError into NucleusError::LandlockError
fn ll_err(e: RulesetError) -> NucleusError {
    NucleusError::LandlockError(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_manager_initial_state() {
        let mgr = LandlockManager::new();
        assert!(!mgr.is_applied());
    }

    #[test]
    fn test_apply_idempotent() {
        let mut mgr = LandlockManager::new();
        // Best-effort so it succeeds even without Landlock support
        let _ = mgr.apply_container_policy_with_mode(true);
        // Second call should be a no-op
        let result = mgr.apply_container_policy_with_mode(true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_best_effort_on_unsupported_kernel() {
        let mut mgr = LandlockManager::new();
        // Should not error even if kernel has no Landlock
        let result = mgr.apply_container_policy_with_mode(true);
        assert!(result.is_ok());
    }
}
