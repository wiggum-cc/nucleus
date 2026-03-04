/// Model-based testing for isolation module using tla-connect
///
/// Replays traces from Nucleus_Isolation_NamespaceLifecycle.tla
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
    pc: i64,
}

impl IsolationDriver {
    fn new() -> Self {
        Self {
            state: NamespaceState::Uninitialized,
            pc: 0,
        }
    }
}

impl Driver for IsolationDriver {
    type State = IsolationSpecState;

    fn step(&mut self, step: &Step) -> Result<(), DriverError> {
        switch!(step {
            "init" => {
                // Initial state – already set by new()
                Ok(())
            },
            "uninitialized_create_namespaces" => {
                if self.state != NamespaceState::Uninitialized {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for create_namespaces: {:?}", self.state),
                    });
                }
                self.state = NamespaceState::Unshared;
                self.pc += 1;
                Ok(())
            },
            "unshared_enter_namespaces" => {
                if self.state != NamespaceState::Unshared {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for enter_namespaces: {:?}", self.state),
                    });
                }
                self.state = NamespaceState::Entered;
                self.pc += 1;
                Ok(())
            },
            "entered_cleanup" => {
                if self.state != NamespaceState::Entered {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for cleanup: {:?}", self.state),
                    });
                }
                self.state = NamespaceState::Cleaned;
                self.pc += 1;
                Ok(())
            },
        })
    }
}

impl State for IsolationSpecState {}

impl ExtractState<IsolationDriver> for IsolationSpecState {
    fn from_driver(driver: &IsolationDriver) -> Result<Self, DriverError> {
        let state_str = match driver.state {
            NamespaceState::Uninitialized => "uninitialized",
            NamespaceState::Unshared => "unshared",
            NamespaceState::Entered => "entered",
            NamespaceState::Cleaned => "cleaned",
        };

        Ok(Self {
            state: state_str.to_string(),
            pc: driver.pc,
        })
    }
}

#[test]
#[ignore] // Requires Apalache
fn test_isolation_replay_apalache_traces() -> TlaResult<()> {
    let config = ApalacheConfig::builder()
        .spec("formal/tla/Nucleus_Isolation_NamespaceLifecycle.tla")
        .inv("NotTerminated")
        .max_traces(10_usize)
        .max_length(10_usize)
        .mode(ApalacheMode::Simulate)
        .build()?;
    let traces = generate_traces(&config)?;

    let _ = replay_traces(IsolationDriver::new, &traces.traces)?;

    Ok(())
}

fn itf_state(index: u64, action: &str, state: &str, pc: i64) -> itf::state::State<itf::Value> {
    itf::state::State {
        meta: itf::state::Meta { index: Some(index), ..Default::default() },
        value: itf::Value::Record(
            [
                ("state".into(), itf::Value::String(state.into())),
                ("pc".into(), itf::Value::BigInt(itf::value::BigInt::new(pc))),
                ("action_taken".into(), itf::Value::String(action.into())),
            ]
            .into_iter()
            .collect(),
        ),
    }
}

fn itf_trace(states: Vec<itf::state::State<itf::Value>>) -> itf::Trace<itf::Value> {
    itf::Trace {
        meta: Default::default(),
        params: vec![],
        vars: vec!["state".into(), "pc".into(), "action_taken".into()],
        loop_index: None,
        states,
    }
}

#[test]
fn test_isolation_property_no_state_skipping() {
    // Verify cannot skip from uninitialized directly to entered
    let trace = itf_trace(vec![
        itf_state(0, "init", "uninitialized", 0),
        itf_state(1, "unshared_enter_namespaces", "entered", 1),
    ]);
    let result = replay_traces(IsolationDriver::new, &[trace]);
    assert!(result.is_err(), "Should reject skipping unshared state");
}
