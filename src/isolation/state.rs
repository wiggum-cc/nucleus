use crate::error::StateTransition;

/// Namespace lifecycle state machine matching Nucleus_Isolation_NamespaceLifecycle.tla
///
/// State transitions:
/// uninitialized -> unshared -> entered -> cleaned
///
/// Properties verified by TLA+ model:
/// - isolation_integrity: Once entered, can only move to entered or cleaned
/// - cleanup_happens: If entered, eventually cleaned
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceState {
    /// Initial state before namespace creation
    Uninitialized,
    /// Namespaces created via unshare(2)
    Unshared,
    /// Process entered the namespaces
    Entered,
    /// Namespaces cleaned up
    Cleaned,
}

impl StateTransition for NamespaceState {
    fn can_transition_to(&self, next: &NamespaceState) -> bool {
        use NamespaceState::*;

        // L9: Added Unshared->Cleaned transition for cleanup from
        // partially-initialized state (e.g., error during namespace setup).
        matches!(
            (self, next),
            (Uninitialized, Unshared)
                | (Unshared, Entered)
                | (Unshared, Cleaned)
                | (Entered, Cleaned)
                | (Uninitialized, Uninitialized)
                | (Unshared, Unshared)
                | (Entered, Entered)
                | (Cleaned, Cleaned)
        )
    }

    fn is_terminal(&self) -> bool {
        matches!(self, NamespaceState::Cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(NamespaceState::Uninitialized.can_transition_to(&NamespaceState::Unshared));
        assert!(NamespaceState::Unshared.can_transition_to(&NamespaceState::Entered));
        assert!(NamespaceState::Entered.can_transition_to(&NamespaceState::Cleaned));
    }

    #[test]
    fn test_unshared_to_cleaned() {
        // L9: Cleanup from partially-initialized state
        assert!(NamespaceState::Unshared.can_transition_to(&NamespaceState::Cleaned));
    }

    #[test]
    fn test_invalid_transitions() {
        // Cannot skip states
        assert!(!NamespaceState::Uninitialized.can_transition_to(&NamespaceState::Entered));
        assert!(!NamespaceState::Uninitialized.can_transition_to(&NamespaceState::Cleaned));

        // Cannot go backwards
        assert!(!NamespaceState::Entered.can_transition_to(&NamespaceState::Unshared));
        assert!(!NamespaceState::Cleaned.can_transition_to(&NamespaceState::Entered));
    }

    #[test]
    fn test_terminal_state() {
        assert!(!NamespaceState::Uninitialized.is_terminal());
        assert!(!NamespaceState::Unshared.is_terminal());
        assert!(!NamespaceState::Entered.is_terminal());
        assert!(NamespaceState::Cleaned.is_terminal());
    }
}
