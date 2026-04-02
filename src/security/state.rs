use crate::error::StateTransition;

/// Security state machine matching Nucleus_Security_SecurityEnforcement.tla
///
/// State transitions:
/// privileged -> capabilities_dropped -> seccomp_applied -> landlock_applied -> locked
///
/// Properties verified by TLA+ model:
/// - irreversible_lockdown: Once security layers are applied, can only move forward to locked
/// - defense_in_depth: Locked state requires capabilities dropped, seccomp applied, and landlock applied
/// - no_privilege_escalation: Cannot return to privileged state after dropping capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityState {
    /// Initial state with all privileges
    Privileged,
    /// Capabilities have been dropped
    CapabilitiesDropped,
    /// Seccomp filter has been applied
    SeccompApplied,
    /// Landlock filesystem policy has been applied
    LandlockApplied,
    /// Final locked state - no further security changes possible
    Locked,
}

impl StateTransition for SecurityState {
    fn can_transition_to(&self, next: &SecurityState) -> bool {
        use SecurityState::*;

        matches!(
            (self, next),
            (Privileged, CapabilitiesDropped)
                | (CapabilitiesDropped, SeccompApplied)
                | (SeccompApplied, LandlockApplied)
                | (LandlockApplied, Locked)
                | (Privileged, Privileged)
                | (CapabilitiesDropped, CapabilitiesDropped)
                | (SeccompApplied, SeccompApplied)
                | (LandlockApplied, LandlockApplied)
                | (Locked, Locked)
        )
    }

    fn is_terminal(&self) -> bool {
        matches!(self, SecurityState::Locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(SecurityState::Privileged.can_transition_to(&SecurityState::CapabilitiesDropped));
        assert!(
            SecurityState::CapabilitiesDropped.can_transition_to(&SecurityState::SeccompApplied)
        );
        assert!(SecurityState::SeccompApplied.can_transition_to(&SecurityState::LandlockApplied));
        assert!(SecurityState::LandlockApplied.can_transition_to(&SecurityState::Locked));
    }

    #[test]
    fn test_self_transitions() {
        assert!(SecurityState::Privileged.can_transition_to(&SecurityState::Privileged));
        assert!(
            SecurityState::CapabilitiesDropped
                .can_transition_to(&SecurityState::CapabilitiesDropped)
        );
        assert!(SecurityState::SeccompApplied.can_transition_to(&SecurityState::SeccompApplied));
        assert!(SecurityState::LandlockApplied.can_transition_to(&SecurityState::LandlockApplied));
        assert!(SecurityState::Locked.can_transition_to(&SecurityState::Locked));
    }

    #[test]
    fn test_invalid_transitions() {
        // Cannot skip states
        assert!(!SecurityState::Privileged.can_transition_to(&SecurityState::SeccompApplied));
        assert!(!SecurityState::Privileged.can_transition_to(&SecurityState::LandlockApplied));
        assert!(!SecurityState::Privileged.can_transition_to(&SecurityState::Locked));
        assert!(
            !SecurityState::CapabilitiesDropped
                .can_transition_to(&SecurityState::LandlockApplied)
        );
        assert!(!SecurityState::CapabilitiesDropped.can_transition_to(&SecurityState::Locked));
        assert!(!SecurityState::SeccompApplied.can_transition_to(&SecurityState::Locked));

        // Cannot go backwards (no privilege escalation)
        assert!(!SecurityState::CapabilitiesDropped.can_transition_to(&SecurityState::Privileged));
        assert!(!SecurityState::SeccompApplied.can_transition_to(&SecurityState::Privileged));
        assert!(
            !SecurityState::SeccompApplied.can_transition_to(&SecurityState::CapabilitiesDropped)
        );
        assert!(!SecurityState::LandlockApplied.can_transition_to(&SecurityState::Privileged));
        assert!(
            !SecurityState::LandlockApplied.can_transition_to(&SecurityState::CapabilitiesDropped)
        );
        assert!(!SecurityState::LandlockApplied.can_transition_to(&SecurityState::SeccompApplied));
        assert!(!SecurityState::Locked.can_transition_to(&SecurityState::LandlockApplied));
        assert!(!SecurityState::Locked.can_transition_to(&SecurityState::SeccompApplied));
    }

    #[test]
    fn test_terminal_state() {
        assert!(!SecurityState::Privileged.is_terminal());
        assert!(!SecurityState::CapabilitiesDropped.is_terminal());
        assert!(!SecurityState::SeccompApplied.is_terminal());
        assert!(!SecurityState::LandlockApplied.is_terminal());
        assert!(SecurityState::Locked.is_terminal());
    }
}
