/// Model-based testing for security module using tla-connect
///
/// Replays traces from Nucleus_Security_SecurityEnforcement.tla against the
/// Rust SecurityState implementation, verifying conformance with the TLA+ spec.
use anyhow::Result;
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

/// Extract pc from ITF state record for stuttering detection
fn spec_pc(step: &Step) -> Option<i64> {
    if let itf::Value::Record(ref rec) = step.state {
        if let Some(itf::Value::BigInt(ref n)) = rec.get("pc") {
            return n.to_string().parse().ok();
        }
    }
    None
}

impl Driver for SecurityDriver {
    type State = SecuritySpecState;

    fn step(&mut self, step: &Step) -> Result<()> {
        // Skip stuttering steps (UNCHANGED vars – pc stays the same)
        if let Some(p) = spec_pc(step) {
            if p == self.pc {
                return Ok(());
            }
        }

        switch!(step {
            "privileged_drop_capabilities" => {
                if self.state != SecurityState::Privileged {
                    anyhow::bail!("Invalid state for drop_capabilities: {:?}", self.state);
                }
                self.state = SecurityState::CapabilitiesDropped;
                self.pc += 1;
            },
            "capabilities_dropped_apply_seccomp" => {
                if self.state != SecurityState::CapabilitiesDropped {
                    anyhow::bail!("Invalid state for apply_seccomp: {:?}", self.state);
                }
                self.state = SecurityState::SeccompApplied;
                self.pc += 1;
            },
            "seccomp_applied_apply_landlock" => {
                if self.state != SecurityState::SeccompApplied {
                    anyhow::bail!("Invalid state for apply_landlock: {:?}", self.state);
                }
                self.state = SecurityState::LandlockApplied;
                self.pc += 1;
            },
            "landlock_applied_finalize" => {
                if self.state != SecurityState::LandlockApplied {
                    anyhow::bail!("Invalid state for finalize: {:?}", self.state);
                }
                self.state = SecurityState::Locked;
                self.pc += 1;
            },
        })
    }
}

impl State<SecurityDriver> for SecuritySpecState {
    fn from_driver(driver: &SecurityDriver) -> Result<Self> {
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
fn test_security_replay_apalache_traces() -> Result<()> {
    let traces = generate_traces(&ApalacheConfig {
        spec: "formal/tla/Nucleus_Security_SecurityEnforcement.tla".into(),
        inv: "NotTerminated".into(),
        max_traces: 10,
        max_length: 10,
        mode: ApalacheMode::Simulate,
        ..Default::default()
    })?;

    replay_traces(SecurityDriver::new, &traces)?;

    Ok(())
}

#[test]
fn test_security_state_comparison() -> Result<()> {
    let driver = SecurityDriver {
        state: SecurityState::CapabilitiesDropped,
        pc: 1,
    };

    let state = SecuritySpecState::from_driver(&driver)?;

    assert_eq!(state.state, "capabilities_dropped");
    assert_eq!(state.pc, 1);

    Ok(())
}

#[test]
fn test_security_invalid_transition() {
    let mut driver = SecurityDriver::new();

    let invalid_step = Step {
        action_taken: "capabilities_dropped_apply_seccomp".to_string(),
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
    assert!(result.is_err(), "Should reject invalid transition");
}
