use crate::error::{NucleusError, Result};
use caps::{CapSet, Capability};
use tracing::{debug, info};

/// Security context that tracks capability state
pub struct CapabilityManager {
    dropped: bool,
}

impl CapabilityManager {
    pub fn new() -> Self {
        Self { dropped: false }
    }

    /// Drop all capabilities
    ///
    /// This implements the transition: Privileged -> CapabilitiesDropped
    /// in the security state machine (Nucleus_Security_SecurityEnforcement.tla)
    pub fn drop_all(&mut self) -> Result<()> {
        if self.dropped {
            debug!("Capabilities already dropped, skipping");
            return Ok(());
        }

        info!("Dropping all capabilities");

        // Clear all capability sets
        caps::clear(None, CapSet::Permitted).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear permitted caps: {}", e))
        })?;

        caps::clear(None, CapSet::Effective).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear effective caps: {}", e))
        })?;

        caps::clear(None, CapSet::Inheritable).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear inheritable caps: {}", e))
        })?;

        caps::clear(None, CapSet::Ambient).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear ambient caps: {}", e))
        })?;

        // Clear bounding set: prevents regaining capabilities through exec of setuid binaries
        for cap in caps::all() {
            if let Err(e) = caps::drop(None, CapSet::Bounding, cap) {
                // Some capabilities may not be in the bounding set; log and continue
                debug!(
                    "Failed to drop bounding cap {:?}: {} (may not be present)",
                    cap, e
                );
            }
        }

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

        // Get all capabilities
        let all_caps = caps::all();

        // Drop each capability that's not in the keep list
        for cap in all_caps {
            if !keep.contains(&cap) {
                caps::drop(None, CapSet::Permitted, cap).map_err(|e| {
                    NucleusError::CapabilityError(format!("Failed to drop {cap:?}: {e}"))
                })?;

                caps::drop(None, CapSet::Effective, cap).map_err(|e| {
                    NucleusError::CapabilityError(format!("Failed to drop {cap:?}: {e}"))
                })?;

                caps::drop(None, CapSet::Inheritable, cap).map_err(|e| {
                    NucleusError::CapabilityError(format!("Failed to drop {cap:?}: {e}"))
                })?;
            }
        }

        // Always clear ambient capabilities
        caps::clear(None, CapSet::Ambient).map_err(|e| {
            NucleusError::CapabilityError(format!("Failed to clear ambient caps: {}", e))
        })?;

        self.dropped = true;
        info!("Successfully dropped capabilities");

        Ok(())
    }

    /// Check if capabilities have been dropped
    pub fn is_dropped(&self) -> bool {
        self.dropped
    }
}

impl Default for CapabilityManager {
    fn default() -> Self {
        Self::new()
    }
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
        // First drop should succeed
        let _ = mgr.drop_all();
        assert!(mgr.is_dropped());

        // Second drop should also succeed (idempotent)
        let result = mgr.drop_all();
        assert!(result.is_ok());
        assert!(mgr.is_dropped());
    }
}
