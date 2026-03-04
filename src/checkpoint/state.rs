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
                | (CheckpointState::None, CheckpointState::Restoring)
                | (CheckpointState::Restoring, CheckpointState::Restored)
        )
    }
}
