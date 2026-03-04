/// Model-based testing for security module using tla-connect
///
/// Replays traces from Nucleus_Security_SecurityEnforcement.tla against the
/// Rust SecurityState implementation, verifying conformance with the TLA+ spec.
use nucleus::security::SecurityState;
use serde::Deserialize;
use tla_connect::*;

/// State type matching TLA+ spec variables
#[derive(Debug, PartialEq, Eq, Deserialize)]
struct SecuritySpecState {
    state: String,
    pc: i64,
}

/// Driver wrapping the Rust SecurityState implementation
struct SecurityDriver {
    state: SecurityState,
    pc: i64,
}

impl SecurityDriver {
    fn new() -> Self {
        Self {
            state: SecurityState::Privileged,
            pc: 0,
        }
    }
}

impl Driver for SecurityDriver {
    type State = SecuritySpecState;

    fn step(&mut self, step: &Step) -> Result<(), DriverError> {
        switch!(step {
            "init" => {
                Ok(())
            },
            "privileged_drop_capabilities" => {
                if self.state != SecurityState::Privileged {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for drop_capabilities: {:?}", self.state),
                    });
                }
                self.state = SecurityState::CapabilitiesDropped;
                self.pc += 1;
                Ok(())
            },
            "capabilities_dropped_apply_seccomp" => {
                if self.state != SecurityState::CapabilitiesDropped {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for apply_seccomp: {:?}", self.state),
                    });
                }
                self.state = SecurityState::SeccompApplied;
                self.pc += 1;
                Ok(())
            },
            "seccomp_applied_apply_landlock" => {
                if self.state != SecurityState::SeccompApplied {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for apply_landlock: {:?}", self.state),
                    });
                }
                self.state = SecurityState::LandlockApplied;
                self.pc += 1;
                Ok(())
            },
            "landlock_applied_finalize" => {
                if self.state != SecurityState::LandlockApplied {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for finalize: {:?}", self.state),
                    });
                }
                self.state = SecurityState::Locked;
                self.pc += 1;
                Ok(())
            },
        })
    }
}

impl State for SecuritySpecState {}

impl ExtractState<SecurityDriver> for SecuritySpecState {
    fn from_driver(driver: &SecurityDriver) -> Result<Self, DriverError> {
        let state_str = match driver.state {
            SecurityState::Privileged => "privileged",
            SecurityState::CapabilitiesDropped => "capabilities_dropped",
            SecurityState::SeccompApplied => "seccomp_applied",
            SecurityState::LandlockApplied => "landlock_applied",
            SecurityState::Locked => "locked",
        };

        Ok(Self {
            state: state_str.to_string(),
            pc: driver.pc,
        })
    }
}

#[test]
#[ignore] // Requires Apalache
fn test_security_replay_apalache_traces() -> TlaResult<()> {
    let config = ApalacheConfig::builder()
        .spec("formal/tla/Nucleus_Security_SecurityEnforcement.tla")
        .inv("NotTerminated")
        .max_traces(10_usize)
        .max_length(10_usize)
        .mode(ApalacheMode::Simulate)
        .build()?;
    let traces = generate_traces(&config)?;

    let _ = replay_traces(SecurityDriver::new, &traces.traces)?;

    Ok(())
}

#[test]
fn test_security_state_comparison() -> TlaResult<()> {
    let driver = SecurityDriver {
        state: SecurityState::CapabilitiesDropped,
        pc: 1,
    };

    let state = SecuritySpecState::from_driver(&driver)?;

    assert_eq!(state.state, "capabilities_dropped");
    assert_eq!(state.pc, 1);

    Ok(())
}

fn itf_state(index: u64, action: &str, state: &str, pc: i64) -> itf::state::State<itf::Value> {
    itf::state::State {
        meta: itf::state::Meta {
            index: Some(index),
            ..Default::default()
        },
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
fn test_security_invalid_transition() {
    // From privileged state, try capabilities_dropped_apply_seccomp (requires CapabilitiesDropped)
    let trace = itf_trace(vec![
        itf_state(0, "init", "privileged", 0),
        itf_state(
            1,
            "capabilities_dropped_apply_seccomp",
            "seccomp_applied",
            1,
        ),
    ]);
    let result = replay_traces(SecurityDriver::new, &[trace]);
    assert!(result.is_err(), "Should reject invalid transition");
}
