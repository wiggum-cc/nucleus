/// Model-based testing for resources module using tla-connect
///
/// Replays traces from Nucleus_Resources_CgroupLifecycle.tla
use anyhow::Result;
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

/// Extract pc from ITF state record for stuttering detection
fn spec_pc(step: &Step) -> Option<i64> {
    if let itf::Value::Record(ref rec) = step.state {
        if let Some(itf::Value::BigInt(ref n)) = rec.get("pc") {
            return n.to_string().parse().ok();
        }
    }
    None
}

impl Driver for ResourcesDriver {
    type State = ResourcesSpecState;

    fn step(&mut self, step: &Step) -> Result<()> {
        // Skip stuttering steps (UNCHANGED vars – pc stays the same)
        if let Some(p) = spec_pc(step) {
            if p == self.pc {
                return Ok(());
            }
        }

        switch!(step {
            "init" => {
                // Initial state – already set by new()
            },
            "nonexistent_create_cgroup" => {
                if self.state != CgroupState::Nonexistent {
                    anyhow::bail!("Invalid state for create_cgroup: {:?}", self.state);
                }
                self.state = CgroupState::Created;
                self.pc += 1;
            },
            "created_set_limits" => {
                if self.state != CgroupState::Created {
                    anyhow::bail!("Invalid state for set_limits: {:?}", self.state);
                }
                self.state = CgroupState::Configured;
                self.pc += 1;
            },
            "configured_attach_process" => {
                if self.state != CgroupState::Configured {
                    anyhow::bail!("Invalid state for attach_process: {:?}", self.state);
                }
                self.state = CgroupState::Attached;
                self.pc += 1;
            },
            "attached_start_monitoring" => {
                if self.state != CgroupState::Attached {
                    anyhow::bail!("Invalid state for start_monitoring: {:?}", self.state);
                }
                self.state = CgroupState::Monitoring;
                self.pc += 1;
            },
            "monitoring_cleanup" => {
                if self.state != CgroupState::Monitoring {
                    anyhow::bail!("Invalid state for cleanup: {:?}", self.state);
                }
                self.state = CgroupState::Removed;
                self.pc += 1;
            },
            "created_cleanup_failed_cgroup" => {
                // Error path: created -> removed
                if self.state != CgroupState::Created {
                    anyhow::bail!("Invalid state for cleanup_failed_cgroup: {:?}", self.state);
                }
                self.state = CgroupState::Removed;
                self.pc += 1;
            },
            "configured_cleanup_failed_cgroup" => {
                // Error path: configured -> removed
                if self.state != CgroupState::Configured {
                    anyhow::bail!("Invalid state for cleanup_failed_cgroup: {:?}", self.state);
                }
                self.state = CgroupState::Removed;
                self.pc += 1;
            },
            "attached_cleanup" => {
                // Cleanup path: attached -> removed (no monitoring phase)
                if self.state != CgroupState::Attached {
                    anyhow::bail!("Invalid state for attached_cleanup: {:?}", self.state);
                }
                self.state = CgroupState::Removed;
                self.pc += 1;
            },
        })
    }
}

impl State<ResourcesDriver> for ResourcesSpecState {
    fn from_driver(driver: &ResourcesDriver) -> Result<Self> {
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
fn test_resources_replay_apalache_traces() -> Result<()> {
    let traces = generate_traces(&ApalacheConfig {
        spec: "formal/tla/Nucleus_Resources_CgroupLifecycle.tla".into(),
        inv: "NotTerminated".into(),
        max_traces: 10,
        max_length: 15,
        mode: ApalacheMode::Simulate,
        ..Default::default()
    })?;

    replay_traces(ResourcesDriver::new, &traces)?;

    Ok(())
}

// Manual trace tests removed - use Apalache-generated traces instead

#[test]
fn test_resources_property_no_backwards_transition() {
    // Verify cannot go backwards from monitoring to attached
    let mut driver = ResourcesDriver {
        state: CgroupState::Monitoring,
        pc: 4,
    };

    let invalid_step = Step {
        action_taken: "configured_attach_process".to_string(),
        nondet_picks: itf::Value::Record(Default::default()),
        state: itf::Value::Record(
            [(
                "pc".to_string(),
                itf::Value::BigInt(itf::value::BigInt::new(5)),
            )]
            .into_iter()
            .collect(),
        ),
    };

    let result = driver.step(&invalid_step);
    assert!(result.is_err(), "Should reject backwards transition");
}
