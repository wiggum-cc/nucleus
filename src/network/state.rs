/// Network state tracking
#[derive(Debug, Clone)]
pub enum NetworkState {
    /// No network configured
    Unconfigured,
    /// Network is being set up
    Configuring,
    /// Network is active
    Active,
    /// Network has been torn down
    Cleaned,
}

impl NetworkState {
    pub fn can_transition_to(&self, next: &NetworkState) -> bool {
        matches!(
            (self, next),
            (NetworkState::Unconfigured, NetworkState::Configuring)
                | (NetworkState::Configuring, NetworkState::Active)
                | (NetworkState::Active, NetworkState::Cleaned)
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, NetworkState::Cleaned)
    }

    /// Transition to the next state, returning an error if the transition is invalid
    pub fn transition(self, next: NetworkState) -> crate::error::Result<NetworkState> {
        if self.can_transition_to(&next) {
            Ok(next)
        } else {
            Err(crate::error::NucleusError::InvalidStateTransition {
                from: format!("{:?}", self),
                to: format!("{:?}", next),
            })
        }
    }
}
