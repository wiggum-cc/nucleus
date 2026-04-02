use crate::error::StateTransition;

/// Network state tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl StateTransition for NetworkState {
    fn can_transition_to(&self, next: &NetworkState) -> bool {
        matches!(
            (self, next),
            (NetworkState::Unconfigured, NetworkState::Configuring)
                | (NetworkState::Configuring, NetworkState::Active)
                | (NetworkState::Active, NetworkState::Cleaned)
        )
    }

    fn is_terminal(&self) -> bool {
        matches!(self, NetworkState::Cleaned)
    }
}
