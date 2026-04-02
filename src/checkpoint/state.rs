/// Checkpoint state tracking
#[derive(Debug, Clone)]
pub enum CheckpointState {
    /// No checkpoint in progress
    None,
    /// Checkpoint is being created
    Dumping,
    /// Checkpoint is complete
    Dumped,
    /// Restore is in progress
    Restoring,
    /// Restore is complete
    Restored,
}

impl CheckpointState {
    pub fn can_transition_to(&self, next: &CheckpointState) -> bool {
        matches!(
            (self, next),
            (CheckpointState::None, CheckpointState::Dumping)
                | (CheckpointState::Dumping, CheckpointState::Dumped)
                | (CheckpointState::Dumping, CheckpointState::None)
                | (CheckpointState::None, CheckpointState::Restoring)
                | (CheckpointState::Restoring, CheckpointState::Restored)
                | (CheckpointState::Restoring, CheckpointState::None)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abort_transitions() {
        // BUG-17: Dumping and Restoring must be able to transition back to None (abort)
        let state = CheckpointState::Dumping;
        assert!(
            state.can_transition_to(&CheckpointState::None),
            "Dumping must be able to abort back to None"
        );
        let state = CheckpointState::Restoring;
        assert!(
            state.can_transition_to(&CheckpointState::None),
            "Restoring must be able to abort back to None"
        );
    }
}
