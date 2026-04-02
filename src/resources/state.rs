use crate::error::StateTransition;

/// Cgroup lifecycle state machine matching Nucleus_Resources_CgroupLifecycle.tla
///
/// State transitions:
/// nonexistent -> created -> configured -> attached -> monitoring -> removed
///
/// Properties verified by TLA+ model:
/// - resource_limits_enforced: Once configured, can only move to attached, monitoring, or removed
/// - cleanup_guaranteed: Eventually reaches removed state
/// - no_resource_leak: Removed state is terminal and stable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupState {
    /// Initial state - cgroup doesn't exist
    Nonexistent,
    /// Cgroup created in filesystem
    Created,
    /// Resource limits configured
    Configured,
    /// Process attached to cgroup
    Attached,
    /// Monitoring resource usage
    Monitoring,
    /// Cgroup removed - terminal state
    Removed,
}

impl StateTransition for CgroupState {
    fn can_transition_to(&self, next: &CgroupState) -> bool {
        use CgroupState::*;

        matches!(
            (self, next),
            (Nonexistent, Created)
                | (Created, Configured)
                | (Configured, Attached)
                | (Attached, Monitoring)
                | (Monitoring, Removed)
                // Cleanup paths
                | (Created, Removed)
                | (Configured, Removed)
                | (Attached, Removed)
                // Stuttering
                | (Nonexistent, Nonexistent)
                | (Created, Created)
                | (Configured, Configured)
                | (Attached, Attached)
                | (Monitoring, Monitoring)
                | (Removed, Removed)
        )
    }

    fn is_terminal(&self) -> bool {
        matches!(self, CgroupState::Removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(CgroupState::Nonexistent.can_transition_to(&CgroupState::Created));
        assert!(CgroupState::Created.can_transition_to(&CgroupState::Configured));
        assert!(CgroupState::Configured.can_transition_to(&CgroupState::Attached));
        assert!(CgroupState::Attached.can_transition_to(&CgroupState::Monitoring));
        assert!(CgroupState::Monitoring.can_transition_to(&CgroupState::Removed));
    }

    #[test]
    fn test_error_paths() {
        // Can cleanup from Created or Configured on error
        assert!(CgroupState::Created.can_transition_to(&CgroupState::Removed));
        assert!(CgroupState::Configured.can_transition_to(&CgroupState::Removed));
    }

    #[test]
    fn test_invalid_transitions() {
        // Cannot skip states
        assert!(!CgroupState::Nonexistent.can_transition_to(&CgroupState::Configured));
        assert!(!CgroupState::Created.can_transition_to(&CgroupState::Attached));

        // Cannot go backwards
        assert!(!CgroupState::Configured.can_transition_to(&CgroupState::Created));
        assert!(!CgroupState::Removed.can_transition_to(&CgroupState::Monitoring));
    }

    #[test]
    fn test_terminal_state() {
        assert!(!CgroupState::Nonexistent.is_terminal());
        assert!(!CgroupState::Created.is_terminal());
        assert!(!CgroupState::Configured.is_terminal());
        assert!(!CgroupState::Attached.is_terminal());
        assert!(!CgroupState::Monitoring.is_terminal());
        assert!(CgroupState::Removed.is_terminal());
    }
}
