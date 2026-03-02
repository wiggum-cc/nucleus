/// Security state machine matching Nucleus_Security_SecurityEnforcement.tla
///
/// State transitions:
/// privileged -> capabilities_dropped -> seccomp_applied -> locked
///
/// Properties verified by TLA+ model:
/// - irreversible_lockdown: Once seccomp is applied, can only move to locked
/// - defense_in_depth: Locked state requires both capabilities dropped and seccomp applied
/// - no_privilege_escalation: Cannot return to privileged state after dropping capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityState {
    /// Initial state with all privileges
    Privileged,
    /// Capabilities have been dropped
    CapabilitiesDropped,
    /// Seccomp filter has been applied
    SeccompApplied,
    /// Final locked state - no further security changes possible
    Locked,
}

impl SecurityState {
    /// Check if transition is valid according to TLA+ spec
    pub fn can_transition_to(&self, next: SecurityState) -> bool {
        use SecurityState::*;

        matches!(
            (self, next),
            (Privileged, CapabilitiesDropped)
                | (CapabilitiesDropped, SeccompApplied)
                | (SeccompApplied, Locked)
                | (Privileged, Privileged)
                | (CapabilitiesDropped, CapabilitiesDropped)
                | (SeccompApplied, SeccompApplied)
                | (Locked, Locked)
        )
    }

    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, SecurityState::Locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(SecurityState::Privileged.can_transition_to(SecurityState::CapabilitiesDropped));
        assert!(SecurityState::CapabilitiesDropped.can_transition_to(SecurityState::SeccompApplied));
        assert!(SecurityState::SeccompApplied.can_transition_to(SecurityState::Locked));
    }

    #[test]
    fn test_invalid_transitions() {
        // Cannot skip states
        assert!(!SecurityState::Privileged.can_transition_to(SecurityState::SeccompApplied));
        assert!(!SecurityState::Privileged.can_transition_to(SecurityState::Locked));

        // Cannot go backwards (no privilege escalation)
        assert!(!SecurityState::CapabilitiesDropped.can_transition_to(SecurityState::Privileged));
        assert!(!SecurityState::SeccompApplied.can_transition_to(SecurityState::Privileged));
        assert!(
            !SecurityState::SeccompApplied.can_transition_to(SecurityState::CapabilitiesDropped)
        );
        assert!(!SecurityState::Locked.can_transition_to(SecurityState::SeccompApplied));
    }

    #[test]
    fn test_terminal_state() {
        assert!(!SecurityState::Privileged.is_terminal());
        assert!(!SecurityState::CapabilitiesDropped.is_terminal());
        assert!(!SecurityState::SeccompApplied.is_terminal());
        assert!(SecurityState::Locked.is_terminal());
    }
}
