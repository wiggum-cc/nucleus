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
}

impl FilesystemDriver {
    fn new() -> Self {
        Self {
            state: FilesystemState::Unmounted,
        }
    }
}

impl Driver for FilesystemDriver {
    type State = FilesystemSpecState;

    fn step(&mut self, step: &Step) -> Result<()> {
        switch!(step {
            "unmounted_mount_tmpfs" => {
                if self.state != FilesystemState::Unmounted {
                    anyhow::bail!("Invalid state for mount_tmpfs: {:?}", self.state);
                }
                self.state = FilesystemState::Mounted;
            },
            "mounted_populate_context" => {
                if self.state != FilesystemState::Mounted {
                    anyhow::bail!("Invalid state for populate_context: {:?}", self.state);
                }
                self.state = FilesystemState::Populated;
            },
            "populated_pivot_root" => {
                if self.state != FilesystemState::Populated {
                    anyhow::bail!("Invalid state for pivot_root: {:?}", self.state);
                }
                self.state = FilesystemState::Pivoted;
            },
            "pivoted_cleanup" => {
                if self.state != FilesystemState::Pivoted {
                    anyhow::bail!("Invalid state for cleanup: {:?}", self.state);
                }
                self.state = FilesystemState::UnmountedFinal;
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
            pc: 0,
        })
    }
}

#[test]
#[ignore] // Requires Apalache
fn test_filesystem_replay_apalache_traces() -> Result<()> {
    let traces = generate_traces(&ApalacheConfig {
        spec: "formal/tla/Nucleus_Filesystem_FilesystemLifecycle.tla".into(),
        inv: "Liveness".into(),
        max_traces: 10,
        max_length: 10,
        mode: ApalacheMode::Simulate,
        ..Default::default()
    })?;

    replay_traces(FilesystemDriver::new, &traces)?;

    Ok(())
}

// Manual trace test removed - use Apalache-generated traces instead

#[test]
fn test_filesystem_property_context_isolation() {
    // Property: Once pivoted, can only move to pivoted or unmounted_final
    let mut driver = FilesystemDriver {
        state: FilesystemState::Pivoted,
    };

    // Try to go back to populated (should fail)
    let invalid_step = Step {
        action_taken: "mounted_populate_context".to_string(),
        nondet_picks: itf::Value::Record(Default::default()),
        state: itf::Value::Record(Default::default()),
    };

    let result = driver.step(&invalid_step);
    assert!(
        result.is_err(),
        "Should reject backwards transition from pivoted"
    );
}

#[test]
fn test_filesystem_property_mount_ordering() {
    // Property: Must mount before populating
    let mut driver = FilesystemDriver::new();

    // Try to populate without mounting first
    let invalid_step = Step {
        action_taken: "mounted_populate_context".to_string(),
        nondet_picks: itf::Value::Record(Default::default()),
        state: itf::Value::Record(Default::default()),
    };

    let result = driver.step(&invalid_step);
    assert!(result.is_err(), "Should require mounting before populating");
}
