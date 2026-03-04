/// Model-based testing for resources module using tla-connect
///
/// Replays traces from Nucleus_Resources_CgroupLifecycle.tla
use nucleus::resources::CgroupState;
use serde::Deserialize;
use tla_connect::*;

/// State type matching TLA+ spec variables
#[derive(Debug, PartialEq, Eq, Deserialize)]
struct ResourcesSpecState {
    state: String,
    pc: i64,
}

/// Driver wrapping the Rust CgroupState implementation
struct ResourcesDriver {
    state: CgroupState,
    pc: i64,
}

impl ResourcesDriver {
    fn new() -> Self {
        Self {
            state: CgroupState::Nonexistent,
            pc: 0,
        }
    }
}

impl Driver for ResourcesDriver {
    type State = ResourcesSpecState;

    fn step(&mut self, step: &Step) -> Result<(), DriverError> {
        switch!(step {
            "init" => {
                // Initial state – already set by new()
                Ok(())
            },
            "nonexistent_create_cgroup" => {
                if self.state != CgroupState::Nonexistent {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for create_cgroup: {:?}", self.state),
                    });
                }
                self.state = CgroupState::Created;
                self.pc += 1;
                Ok(())
            },
            "created_set_limits" => {
                if self.state != CgroupState::Created {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for set_limits: {:?}", self.state),
                    });
                }
                self.state = CgroupState::Configured;
                self.pc += 1;
                Ok(())
            },
            "configured_attach_process" => {
                if self.state != CgroupState::Configured {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for attach_process: {:?}", self.state),
                    });
                }
                self.state = CgroupState::Attached;
                self.pc += 1;
                Ok(())
            },
            "attached_start_monitoring" => {
                if self.state != CgroupState::Attached {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for start_monitoring: {:?}", self.state),
                    });
                }
                self.state = CgroupState::Monitoring;
                self.pc += 1;
                Ok(())
            },
            "monitoring_cleanup" => {
                if self.state != CgroupState::Monitoring {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for cleanup: {:?}", self.state),
                    });
                }
                self.state = CgroupState::Removed;
                self.pc += 1;
                Ok(())
            },
            "created_cleanup_failed_cgroup" => {
                // Error path: created -> removed
                if self.state != CgroupState::Created {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for cleanup_failed_cgroup: {:?}", self.state),
                    });
                }
                self.state = CgroupState::Removed;
                self.pc += 1;
                Ok(())
            },
            "configured_cleanup_failed_cgroup" => {
                // Error path: configured -> removed
                if self.state != CgroupState::Configured {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for cleanup_failed_cgroup: {:?}", self.state),
                    });
                }
                self.state = CgroupState::Removed;
                self.pc += 1;
                Ok(())
            },
            "attached_cleanup" => {
                // Cleanup path: attached -> removed (no monitoring phase)
                if self.state != CgroupState::Attached {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for attached_cleanup: {:?}", self.state),
                    });
                }
                self.state = CgroupState::Removed;
                self.pc += 1;
                Ok(())
            },
        })
    }
}

impl State for ResourcesSpecState {}

impl ExtractState<ResourcesDriver> for ResourcesSpecState {
    fn from_driver(driver: &ResourcesDriver) -> Result<Self, DriverError> {
        let state_str = match driver.state {
            CgroupState::Nonexistent => "nonexistent",
            CgroupState::Created => "created",
            CgroupState::Configured => "configured",
            CgroupState::Attached => "attached",
            CgroupState::Monitoring => "monitoring",
            CgroupState::Removed => "removed",
        };

        Ok(Self {
            state: state_str.to_string(),
            pc: driver.pc,
        })
    }
}

#[test]
#[ignore] // Requires Apalache
fn test_resources_replay_apalache_traces() -> TlaResult<()> {
    let config = ApalacheConfig::builder()
        .spec("formal/tla/Nucleus_Resources_CgroupLifecycle.tla")
        .inv("NotTerminated")
        .max_traces(10_usize)
        .max_length(15_usize)
        .mode(ApalacheMode::Simulate)
        .build()?;
    let traces = generate_traces(&config)?;

    let _ = replay_traces(ResourcesDriver::new, &traces.traces)?;

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
fn test_resources_property_no_backwards_transition() {
    // Verify cannot go backwards from monitoring to attached
    let trace = itf_trace(vec![
        itf_state(0, "init", "nonexistent", 0),
        itf_state(1, "nonexistent_create_cgroup", "created", 1),
        itf_state(2, "created_set_limits", "configured", 2),
        itf_state(3, "configured_attach_process", "attached", 3),
        itf_state(4, "attached_start_monitoring", "monitoring", 4),
        itf_state(5, "configured_attach_process", "attached", 5),
    ]);
    let result = replay_traces(ResourcesDriver::new, &[trace]);
    assert!(result.is_err(), "Should reject backwards transition");
}
