/// Model-based testing for filesystem module using tla-connect
///
/// Replays traces from Nucleus_Filesystem_FilesystemLifecycle.tla
use nucleus::filesystem::FilesystemState;
use serde::Deserialize;
use tla_connect::*;

/// State type matching TLA+ spec variables
#[derive(Debug, PartialEq, Eq, Deserialize)]
struct FilesystemSpecState {
    state: String,
    pc: i64,
}

/// Driver wrapping the Rust FilesystemState implementation
struct FilesystemDriver {
    state: FilesystemState,
    pc: i64,
}

impl FilesystemDriver {
    fn new() -> Self {
        Self {
            state: FilesystemState::Unmounted,
            pc: 0,
        }
    }
}

impl Driver for FilesystemDriver {
    type State = FilesystemSpecState;

    fn step(&mut self, step: &Step) -> Result<(), DriverError> {
        switch!(step {
            "init" => {
                Ok(())
            },
            "unmounted_mount_tmpfs" => {
                if self.state != FilesystemState::Unmounted {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for mount_tmpfs: {:?}", self.state),
                    });
                }
                self.state = FilesystemState::Mounted;
                self.pc += 1;
                Ok(())
            },
            "mounted_populate_context" => {
                if self.state != FilesystemState::Mounted {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for populate_context: {:?}", self.state),
                    });
                }
                self.state = FilesystemState::Populated;
                self.pc += 1;
                Ok(())
            },
            "populated_pivot_root" => {
                if self.state != FilesystemState::Populated {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for pivot_root: {:?}", self.state),
                    });
                }
                self.state = FilesystemState::Pivoted;
                self.pc += 1;
                Ok(())
            },
            "pivoted_cleanup" => {
                if self.state != FilesystemState::Pivoted {
                    return Err(DriverError::ActionFailed {
                        action: step.action_taken.clone(),
                        reason: format!("Invalid state for cleanup: {:?}", self.state),
                    });
                }
                self.state = FilesystemState::UnmountedFinal;
                self.pc += 1;
                Ok(())
            },
        })
    }
}

impl State for FilesystemSpecState {}

impl ExtractState<FilesystemDriver> for FilesystemSpecState {
    fn from_driver(driver: &FilesystemDriver) -> Result<Self, DriverError> {
        let state_str = match driver.state {
            FilesystemState::Unmounted => "unmounted",
            FilesystemState::Mounted => "mounted",
            FilesystemState::Populated => "populated",
            FilesystemState::Pivoted => "pivoted",
            FilesystemState::UnmountedFinal => "unmounted_final",
        };

        Ok(Self {
            state: state_str.to_string(),
            pc: driver.pc,
        })
    }
}

#[test]
#[ignore] // Requires Apalache
fn test_filesystem_replay_apalache_traces() -> TlaResult<()> {
    let config = ApalacheConfig::builder()
        .spec("formal/tla/Nucleus_Filesystem_FilesystemLifecycle.tla")
        .inv("NotTerminated")
        .max_traces(10_usize)
        .max_length(10_usize)
        .mode(ApalacheMode::Simulate)
        .build()?;
    let traces = generate_traces(&config)?;

    let _ = replay_traces(FilesystemDriver::new, &traces.traces)?;

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
fn test_filesystem_property_context_isolation() {
    // Verify cannot go backwards from pivoted to populated
    let trace = itf_trace(vec![
        itf_state(0, "init", "unmounted", 0),
        itf_state(1, "unmounted_mount_tmpfs", "mounted", 1),
        itf_state(2, "mounted_populate_context", "populated", 2),
        itf_state(3, "populated_pivot_root", "pivoted", 3),
        itf_state(4, "mounted_populate_context", "mounted", 4),
    ]);
    let result = replay_traces(FilesystemDriver::new, &[trace]);
    assert!(
        result.is_err(),
        "Should reject backwards transition from pivoted"
    );
}

#[test]
fn test_filesystem_property_mount_ordering() {
    // Verify cannot populate before mounting
    let trace = itf_trace(vec![
        itf_state(0, "init", "unmounted", 0),
        itf_state(1, "mounted_populate_context", "populated", 1),
    ]);
    let result = replay_traces(FilesystemDriver::new, &[trace]);
    assert!(result.is_err(), "Should require mounting before populating");
}
