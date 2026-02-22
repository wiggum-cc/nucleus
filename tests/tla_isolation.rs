/// Model-based testing for isolation module using tla-connect
///
/// Replays traces from Nucleus_Isolation_NamespaceLifecycle.tla

use anyhow::Result;
use nucleus::isolation::NamespaceState;
use serde::Deserialize;
use tla_connect::*;

/// State type matching TLA+ spec variables
#[derive(Debug, PartialEq, Eq, Deserialize)]
struct IsolationSpecState {
    state: String,
    pc: i64,
}

/// Driver wrapping the Rust NamespaceState implementation
struct IsolationDriver {
    state: NamespaceState,
}

impl IsolationDriver {
    fn new() -> Self {
        Self {
            state: NamespaceState::Uninitialized,
        }
    }
}

impl Driver for IsolationDriver {
    type State = IsolationSpecState;

    fn step(&mut self, step: &Step) -> Result<()> {
        switch!(step {
            "uninitialized_create_namespaces" => {
                // TLA+ transition: uninitialized -> unshared
                if self.state != NamespaceState::Uninitialized {
                    anyhow::bail!("Invalid state for create_namespaces: {:?}", self.state);
                }
                self.state = NamespaceState::Unshared;
            },
            "unshared_enter_namespaces" => {
                // TLA+ transition: unshared -> entered
                if self.state != NamespaceState::Unshared {
                    anyhow::bail!("Invalid state for enter_namespaces: {:?}", self.state);
                }
                self.state = NamespaceState::Entered;
            },
            "entered_cleanup" => {
                // TLA+ transition: entered -> cleaned
                if self.state != NamespaceState::Entered {
                    anyhow::bail!("Invalid state for cleanup: {:?}", self.state);
                }
                self.state = NamespaceState::Cleaned;
            },
        })
    }
}

impl State<IsolationDriver> for IsolationSpecState {
    fn from_driver(driver: &IsolationDriver) -> Result<Self> {
        let state_str = match driver.state {
            NamespaceState::Uninitialized => "uninitialized",
            NamespaceState::Unshared => "unshared",
            NamespaceState::Entered => "entered",
            NamespaceState::Cleaned => "cleaned",
        };

        Ok(Self {
            state: state_str.to_string(),
            pc: 0,
        })
    }
}

#[test]
#[ignore] // Requires Apalache
fn test_isolation_replay_apalache_traces() -> Result<()> {
    let traces = generate_traces(&ApalacheConfig {
        spec: "formal/tla/Nucleus_Isolation_NamespaceLifecycle.tla".into(),
        inv: "Liveness".into(),
        max_traces: 10,
        max_length: 10,
        mode: ApalacheMode::Simulate,
        ..Default::default()
    })?;

    replay_traces(IsolationDriver::new, &traces)?;

    Ok(())
}

// Manual trace test removed - use Apalache-generated traces instead

#[test]
fn test_isolation_property_no_state_skipping() {
    // Verify cannot skip from uninitialized directly to entered
    let mut driver = IsolationDriver::new();

    let invalid_step = Step {
        action_taken: "unshared_enter_namespaces".to_string(),
        nondet_picks: itf::Value::Record(Default::default()),
        state: itf::Value::Record(Default::default()),
    };

    let result = driver.step(&invalid_step);
    assert!(result.is_err(), "Should reject skipping unshared state");
}
