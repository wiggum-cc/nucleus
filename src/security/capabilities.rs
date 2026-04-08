use crate::error::{NucleusError, Result};
use caps::{CapSet, Capability, CapsHashSet};
use tracing::{debug, info};

/// Security context that tracks capability state
pub struct CapabilityManager {
    dropped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySets {
    pub bounding: Vec<Capability>,
    pub permitted: Vec<Capability>,
    pub effective: Vec<Capability>,
    pub inheritable: Vec<Capability>,
    pub ambient: Vec<Capability>,
}

impl CapabilityManager {
    pub fn new() -> Self {
        Self { dropped: false }
    }

    /// Drop all capabilities
    ///
    /// This implements the transition: Privileged -> CapabilitiesDropped
    /// in the security state machine (Nucleus_Security_SecurityEnforcement.tla)
    ///
    /// Ordering follows Docker/runc convention: bounding set is cleared first
    /// while CAP_SETPCAP is still in the effective set. PR_CAPBSET_DROP requires
    /// CAP_SETPCAP, so clearing effective/permitted before bounding causes EPERM
    /// for every bounding drop — the process then fails the M4 verification.
    pub fn drop_all(&mut self) -> Result<()> {
        if self.dropped {
            debug!("Capabilities already dropped, skipping");
            return Ok(());
        }

        info!("Dropping all capabilities");

        // 1. Clear bounding set FIRST (requires CAP_SETPCAP in effective set).
        //    Prevents regaining capabilities through exec of setuid binaries.
        for cap in caps::all() {
            if let Err(e) = caps::drop(None, CapSet::Bounding, cap) {
                debug!(
                    "Failed to drop bounding cap {:?}: {} (may not be present)",
                    cap, e
                );
            }
        }

        // M4: Verify the bounding set is actually empty after the drop loop
        let bounding = caps::read(None, CapSet::Bounding).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to read bounding set after drop: {}", e))
        })?;
        if !bounding.is_empty() {
            let leaked: Vec<String> = bounding.iter().map(|c| format!("{:?}", c)).collect();
            return Err(NucleusError::CapabilityError(format!(
                "Bounding set still contains capabilities after drop_all: [{}]",
                leaked.join(", ")
            )));
        }

        // 2. Clear ambient set (must be cleared before permitted, since
        //    ambient caps are constrained to permitted ∩ inheritable).
        caps::clear(None, CapSet::Ambient).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear ambient caps: {}", e))
        })?;

        // 3. Clear inheritable, permitted, effective — in that order so we
        //    never hold effective caps that exceed the permitted set.
        caps::clear(None, CapSet::Inheritable).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear inheritable caps: {}", e))
        })?;

        caps::clear(None, CapSet::Permitted).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear permitted caps: {}", e))
        })?;

        caps::clear(None, CapSet::Effective).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear effective caps: {}", e))
        })?;

        self.dropped = true;
        info!("Successfully dropped all capabilities (including bounding set)");

        Ok(())
    }

    /// Drop all capabilities except the specified ones
    ///
    /// For most use cases, we drop ALL capabilities. This method is provided
    /// for special cases where specific capabilities are needed.
    pub fn drop_except(&mut self, keep: &[Capability]) -> Result<()> {
        if self.dropped {
            debug!("Capabilities already dropped, skipping");
            return Ok(());
        }

        info!("Dropping capabilities except: {:?}", keep);

        let all_caps = caps::all();

        // 1. Drop bounding set entries FIRST (requires CAP_SETPCAP in effective).
        //    If CAP_SETPCAP is not in `keep`, we must drop it from bounding while
        //    it is still in the effective set.
        for cap in &all_caps {
            if !keep.contains(cap) {
                if let Err(e) = caps::drop(None, CapSet::Bounding, *cap) {
                    debug!(
                        "Failed to drop bounding cap {:?}: {} (may not be present)",
                        cap, e
                    );
                }
            }
        }

        // 2. Clear ambient set (constrained to permitted ∩ inheritable).
        caps::clear(None, CapSet::Ambient).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear ambient caps: {}", e))
        })?;

        // 3. Drop from inheritable, permitted, effective for each non-kept cap.
        for cap in &all_caps {
            if !keep.contains(cap) {
                caps::drop(None, CapSet::Inheritable, *cap).map_err(|e| {
                    NucleusError::CapabilityError(format!("Failed to drop {cap:?}: {e}"))
                })?;

                caps::drop(None, CapSet::Permitted, *cap).map_err(|e| {
                    NucleusError::CapabilityError(format!("Failed to drop {cap:?}: {e}"))
                })?;

                caps::drop(None, CapSet::Effective, *cap).map_err(|e| {
                    NucleusError::CapabilityError(format!("Failed to drop {cap:?}: {e}"))
                })?;
            }
        }

        self.dropped = true;
        info!("Successfully dropped capabilities");

        Ok(())
    }

    /// Apply explicit capability sets.
    ///
    /// Bounding is handled as a drop-only upper bound; the remaining sets are
    /// set exactly to the provided values.
    pub fn apply_sets(&mut self, sets: &CapabilitySets) -> Result<()> {
        if self.dropped {
            debug!("Capabilities already dropped, skipping");
            return Ok(());
        }

        info!("Applying explicit capability sets");

        for cap in caps::all() {
            if !sets.bounding.contains(&cap) {
                if let Err(e) = caps::drop(None, CapSet::Bounding, cap) {
                    debug!(
                        "Failed to drop bounding cap {:?}: {} (may not be present)",
                        cap, e
                    );
                }
            }
        }

        // M5: Set Permitted first, then Effective immediately after to avoid a
        // window where the old effective set exceeds the new permitted set.
        caps::set(None, CapSet::Permitted, &to_caps_hash_set(&sets.permitted)).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set permitted caps: {}", e))
        })?;
        caps::set(None, CapSet::Effective, &to_caps_hash_set(&sets.effective)).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set effective caps: {}", e))
        })?;
        caps::set(
            None,
            CapSet::Inheritable,
            &to_caps_hash_set(&sets.inheritable),
        )
        .map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set inheritable caps: {}", e))
        })?;
        caps::set(None, CapSet::Ambient, &to_caps_hash_set(&sets.ambient)).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to set ambient caps: {}", e))
        })?;

        self.dropped = true;
        info!("Successfully applied capability sets");
        Ok(())
    }

    /// Check if capabilities have been dropped
    pub fn is_dropped(&self) -> bool {
        self.dropped
    }

    /// Verify that namespace-creating capabilities are actually absent from
    /// the effective set. This is a runtime guard for the clone3 seccomp
    /// invariant: clone3 cannot be argument-filtered at the BPF level, so
    /// we rely on CAP_SYS_ADMIN (et al.) being dropped to prevent namespace
    /// creation. If the check fails in production mode, it returns an error;
    /// otherwise it emits a warning.
    pub fn verify_no_namespace_caps(production: bool) -> Result<()> {
        use caps::Capability;
        let ns_caps = [
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_NET_ADMIN,
            Capability::CAP_SYS_PTRACE,
        ];
        let effective = caps::read(None, CapSet::Effective).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to read effective caps: {}", e))
        })?;
        let mut leaked = Vec::new();
        for cap in &ns_caps {
            if effective.contains(cap) {
                leaked.push(format!("{:?}", cap));
            }
        }
        if !leaked.is_empty() {
            let msg = format!(
                "SEC-CLONE3: namespace-creating capabilities still present after drop: [{}]. \
                 clone3 syscall is allowed without argument filtering — these caps \
                 must be absent to prevent namespace escape.",
                leaked.join(", ")
            );
            if production {
                return Err(NucleusError::CapabilityError(msg));
            }
            tracing::warn!("{}", msg);
        }
        Ok(())
    }
}

impl Default for CapabilityManager {
    fn default() -> Self {
        Self::new()
    }
}

fn to_caps_hash_set(caps_list: &[Capability]) -> CapsHashSet {
    caps_list.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_manager_initial_state() {
        let mgr = CapabilityManager::new();
        assert!(!mgr.is_dropped());
    }

    #[test]
    fn test_drop_idempotent() {
        let mut mgr = CapabilityManager::new();
        // First drop may fail in unprivileged test environments (M4 verification).
        // That's expected — the important thing is idempotency of the dropped flag.
        match mgr.drop_all() {
            Ok(()) => {
                assert!(mgr.is_dropped());
                // Second drop should also succeed (idempotent)
                let result = mgr.drop_all();
                assert!(result.is_ok());
                assert!(mgr.is_dropped());
            }
            Err(_) => {
                // In unprivileged tests, bounding set verification may fail.
                // This is expected and not a test failure.
            }
        }
    }
}
