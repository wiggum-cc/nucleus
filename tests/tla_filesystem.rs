/// Model-based testing for filesystem module using tla-connect
///
/// Replays traces from Nucleus_Filesystem_FilesystemLifecycle.tla
use anyhow::Result;
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

/// Extract pc from ITF state record for stuttering detection
fn spec_pc(step: &Step) -> Option<i64> {
    if let itf::Value::Record(ref rec) = step.state {
        if let Some(itf::Value::BigInt(ref n)) = rec.get("pc") {
            return n.to_string().parse().ok();
        }
    }
    None
}

impl Driver for FilesystemDriver {
    type State = FilesystemSpecState;

    fn step(&mut self, step: &Step) -> Result<()> {
        // Skip stuttering steps (UNCHANGED vars – pc stays the same)
        if let Some(p) = spec_pc(step) {
            if p == self.pc {
                return Ok(());
            }
        }

        switch!(step {
            "unmounted_mount_tmpfs" => {
                if self.state != FilesystemState::Unmounted {
                    anyhow::bail!("Invalid state for mount_tmpfs: {:?}", self.state);
                }
                self.state = FilesystemState::Mounted;
                self.pc += 1;
            },
            "mounted_populate_context" => {
                if self.state != FilesystemState::Mounted {
                    anyhow::bail!("Invalid state for populate_context: {:?}", self.state);
                }
                self.state = FilesystemState::Populated;
                self.pc += 1;
            },
            "populated_pivot_root" => {
                if self.state != FilesystemState::Populated {
                    anyhow::bail!("Invalid state for pivot_root: {:?}", self.state);
                }
                self.state = FilesystemState::Pivoted;
                self.pc += 1;
            },
            "pivoted_cleanup" => {
                if self.state != FilesystemState::Pivoted {
                    anyhow::bail!("Invalid state for cleanup: {:?}", self.state);
                }
                self.state = FilesystemState::UnmountedFinal;
                self.pc += 1;
            },
        })
    }
}

impl State<FilesystemDriver> for FilesystemSpecState {
    fn from_driver(driver: &FilesystemDriver) -> Result<Self> {
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
fn test_filesystem_replay_apalache_traces() -> Result<()> {
    let traces = generate_traces(&ApalacheConfig {
        spec: "formal/tla/Nucleus_Filesystem_FilesystemLifecycle.tla".into(),
        inv: "NotTerminated".into(),
        max_traces: 10,
        max_length: 10,
        mode: ApalacheMode::Simulate,
        ..Default::default()
    })?;

    replay_traces(FilesystemDriver::new, &traces)?;

    Ok(())
}

#[test]
fn test_filesystem_property_context_isolation() {
    let mut driver = FilesystemDriver {
        state: FilesystemState::Pivoted,
        pc: 3,
    };

    let invalid_step = Step {
        action_taken: "mounted_populate_context".to_string(),
        nondet_picks: itf::Value::Record(Default::default()),
        state: itf::Value::Record(
            [(
                "pc".to_string(),
                itf::Value::BigInt(itf::value::BigInt::new(4)),
            )]
            .into_iter()
            .collect(),
        ),
    };

    let result = driver.step(&invalid_step);
    assert!(
        result.is_err(),
        "Should reject backwards transition from pivoted"
    );
}

#[test]
fn test_filesystem_property_mount_ordering() {
    let mut driver = FilesystemDriver::new();

    let invalid_step = Step {
        action_taken: "mounted_populate_context".to_string(),
        nondet_picks: itf::Value::Record(Default::default()),
        state: itf::Value::Record(
            [(
                "pc".to_string(),
                itf::Value::BigInt(itf::value::BigInt::new(1)),
            )]
            .into_iter()
            .collect(),
        ),
    };

    let result = driver.step(&invalid_step);
    assert!(result.is_err(), "Should require mounting before populating");
}
