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

/// Extract pc from ITF state record for stuttering detection
fn spec_pc(step: &Step) -> Option<i64> {
    if let itf::Value::Record(ref rec) = step.state {
        if let Some(itf::Value::BigInt(ref n)) = rec.get("pc") {
            return n.to_string().parse().ok();
        }
    }
    None
}

impl Driver for IsolationDriver {
    type State = IsolationSpecState;

    fn step(&mut self, step: &Step) -> Result<()> {
        // Skip stuttering steps (UNCHANGED vars — pc stays the same)
        if let Some(p) = spec_pc(step) {
            if p == self.pc {
                return Ok(());
            }
        }

        switch!(step {
            "init" => {
                // Initial state — already set by new()
            },
            "uninitialized_create_namespaces" => {
                // TLA+ transition: uninitialized -> unshared
                if self.state != NamespaceState::Uninitialized {
                    anyhow::bail!("Invalid state for create_namespaces: {:?}", self.state);
                }
                self.state = NamespaceState::Unshared;
                self.pc += 1;
            },
            "unshared_enter_namespaces" => {
                // TLA+ transition: unshared -> entered
                if self.state != NamespaceState::Unshared {
                    anyhow::bail!("Invalid state for enter_namespaces: {:?}", self.state);
                }
                self.state = NamespaceState::Entered;
                self.pc += 1;
            },
            "entered_cleanup" => {
                // TLA+ transition: entered -> cleaned
                if self.state != NamespaceState::Entered {
                    anyhow::bail!("Invalid state for cleanup: {:?}", self.state);
                }
                self.state = NamespaceState::Cleaned;
                self.pc += 1;
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
            pc: driver.pc,
        })
    }
}

#[test]
#[ignore] // Requires Apalache
fn test_isolation_replay_apalache_traces() -> Result<()> {
    let traces = generate_traces(&ApalacheConfig {
        spec: "formal/tla/Nucleus_Isolation_NamespaceLifecycle.tla".into(),
        inv: "NotTerminated".into(),
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
    assert!(result.is_err(), "Should reject skipping unshared state");
}
