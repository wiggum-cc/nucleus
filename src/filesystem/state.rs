/// Filesystem lifecycle state machine matching Nucleus_Filesystem_FilesystemLifecycle.tla
///
/// State transitions:
/// unmounted -> mounted -> populated -> pivoted -> unmounted_final
///
/// Properties verified by TLA+ model:
/// - context_isolation: Once pivoted, can only move to pivoted or unmounted_final
/// - ephemeral_guarantee: unmounted_final is terminal and stable
/// - mount_ordering: populated can only transition to pivoted or unmounted_final
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemState {
    /// Initial state - no filesystem mounted
    Unmounted,
    /// tmpfs mounted
    Mounted,
    /// Context files populated
    Populated,
    /// Root switched via pivot_root
    Pivoted,
    /// Final cleanup - terminal state
    UnmountedFinal,
}

impl FilesystemState {
    /// Check if transition is valid according to TLA+ spec
    pub fn can_transition_to(&self, next: FilesystemState) -> bool {
        use FilesystemState::*;

        matches!(
            (self, next),
            (Unmounted, Mounted)
                | (Mounted, Populated)
                | (Populated, Pivoted)
                | (Pivoted, UnmountedFinal)
                | (Unmounted, Unmounted)
                | (Mounted, Mounted)
                | (Populated, Populated)
                | (Pivoted, Pivoted)
                | (UnmountedFinal, UnmountedFinal)
        )
    }

    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, FilesystemState::UnmountedFinal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(FilesystemState::Unmounted.can_transition_to(FilesystemState::Mounted));
        assert!(FilesystemState::Mounted.can_transition_to(FilesystemState::Populated));
        assert!(FilesystemState::Populated.can_transition_to(FilesystemState::Pivoted));
        assert!(FilesystemState::Pivoted.can_transition_to(FilesystemState::UnmountedFinal));
    }

    #[test]
    fn test_invalid_transitions() {
        // Cannot skip states
        assert!(!FilesystemState::Unmounted.can_transition_to(FilesystemState::Populated));
        assert!(!FilesystemState::Mounted.can_transition_to(FilesystemState::Pivoted));

        // Cannot go backwards
        assert!(!FilesystemState::Pivoted.can_transition_to(FilesystemState::Populated));
        assert!(!FilesystemState::UnmountedFinal.can_transition_to(FilesystemState::Pivoted));
    }

    #[test]
    fn test_terminal_state() {
        assert!(!FilesystemState::Unmounted.is_terminal());
        assert!(!FilesystemState::Mounted.is_terminal());
        assert!(!FilesystemState::Populated.is_terminal());
        assert!(!FilesystemState::Pivoted.is_terminal());
        assert!(FilesystemState::UnmountedFinal.is_terminal());
    }
}
