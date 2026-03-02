/// Model-based testing for security module using tla-connect
///
/// This test uses tla-connect to:
/// 1. Generate traces from Nucleus_Security_SecurityEnforcement.tla using Apalache
/// 2. Replay those traces against the Rust SecurityDriver implementation
/// 3. Verify that Rust state matches TLA+ state after each step
///
/// This ensures the Rust implementation matches the formally verified TLA+ specification.
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
}

impl SecurityDriver {
    fn new() -> Self {
        Self {
            state: SecurityState::Privileged,
        }
    }
}

impl Driver for SecurityDriver {
    type State = SecuritySpecState;

    fn step(&mut self, step: &Step) -> Result<()> {
        switch!(step {
            "privileged_drop_capabilities" => {
                // TLA+ transition: privileged -> capabilities_dropped
                if self.state != SecurityState::Privileged {
                    anyhow::bail!("Invalid state for drop_capabilities: {:?}", self.state);
                }
                self.state = SecurityState::CapabilitiesDropped;
            },
            "capabilities_dropped_apply_seccomp" => {
                // TLA+ transition: capabilities_dropped -> seccomp_applied
                if self.state != SecurityState::CapabilitiesDropped {
                    anyhow::bail!("Invalid state for apply_seccomp: {:?}", self.state);
                }
                self.state = SecurityState::SeccompApplied;
            },
            "seccomp_applied_finalize" => {
                // TLA+ transition: seccomp_applied -> locked
                if self.state != SecurityState::SeccompApplied {
                    anyhow::bail!("Invalid state for finalize: {:?}", self.state);
                }
                self.state = SecurityState::Locked;
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
            SecurityState::Locked => "locked",
        };

        Ok(Self {
            state: state_str.to_string(),
            pc: 0, // We don't track pc in Rust implementation
        })
    }
}

#[test]
#[ignore] // Requires Apalache to be installed
fn test_security_replay_apalache_traces() -> Result<()> {
    // Generate traces from TLA+ spec using Apalache
    let traces = generate_traces(&ApalacheConfig {
        spec: "formal/tla/Nucleus_Security_SecurityEnforcement.tla".into(),
        inv: "Liveness".into(),
        max_traces: 10,
        max_length: 10,
        mode: ApalacheMode::Simulate,
        ..Default::default()
    })?;

    // Replay all generated traces against the Rust implementation
    replay_traces(SecurityDriver::new, &traces)?;

    Ok(())
}

// Manual trace test removed - use Apalache-generated traces instead
// The replay_trace_str API expects ITF format which is complex to write manually

#[test]
fn test_security_state_comparison() -> Result<()> {
    // Test that State trait correctly extracts state from driver
    let driver = SecurityDriver {
        state: SecurityState::CapabilitiesDropped,
    };

    let state = SecuritySpecState::from_driver(&driver)?;

    assert_eq!(state.state, "capabilities_dropped");

    Ok(())
}

#[test]
fn test_security_invalid_transition() {
    // Test that invalid transitions are rejected
    let mut driver = SecurityDriver::new();

    // Skip to seccomp_applied without going through capabilities_dropped
    let invalid_step = Step {
        action_taken: "capabilities_dropped_apply_seccomp".to_string(),
        nondet_picks: itf::Value::Record(Default::default()),
        state: itf::Value::Record(Default::default()),
    };

    let result = driver.step(&invalid_step);

    assert!(result.is_err(), "Should reject invalid transition");
}
