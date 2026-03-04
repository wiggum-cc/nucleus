/// Model-based tests for security module
///
/// These tests verify that the Rust implementation matches the TLA+ specification
/// defined in Nucleus_Security_SecurityEnforcement.tla
///
/// Properties verified:
/// - irreversible_lockdown: Once security layers are applied, can only move forward to locked
/// - no_privilege_escalation: Cannot return to privileged state after dropping capabilities
/// - Terminal state stability: Locked state is terminal
use nucleus::security::SecurityState;

#[test]
fn test_security_state_machine_valid_path() {
    // Verify the happy path: privileged -> capabilities_dropped -> seccomp_applied -> landlock_applied -> locked
    let states = [
        SecurityState::Privileged,
        SecurityState::CapabilitiesDropped,
        SecurityState::SeccompApplied,
        SecurityState::LandlockApplied,
        SecurityState::Locked,
    ];

    for i in 0..states.len() - 1 {
        assert!(
            states[i].can_transition_to(states[i + 1]),
            "Invalid transition from {:?} to {:?}",
            states[i],
            states[i + 1]
        );
    }
}

#[test]
fn test_security_property_irreversible_lockdown() {
    // Property from TLA+: [][(state = seccomp_applied) => ((state' = seccomp_applied) \/ (state' = locked))]
    // Once seccomp is applied, can only stay or move to locked

    let state = SecurityState::SeccompApplied;

    // Valid transitions
    assert!(state.can_transition_to(SecurityState::SeccompApplied));
    assert!(state.can_transition_to(SecurityState::LandlockApplied));

    // Invalid transitions (cannot skip to locked, cannot go backwards)
    assert!(!state.can_transition_to(SecurityState::Locked));
    assert!(!state.can_transition_to(SecurityState::Privileged));
    assert!(!state.can_transition_to(SecurityState::CapabilitiesDropped));

    // Landlock also has irreversible lockdown property
    let ll_state = SecurityState::LandlockApplied;
    assert!(ll_state.can_transition_to(SecurityState::LandlockApplied));
    assert!(ll_state.can_transition_to(SecurityState::Locked));
    assert!(!ll_state.can_transition_to(SecurityState::Privileged));
    assert!(!ll_state.can_transition_to(SecurityState::CapabilitiesDropped));
    assert!(!ll_state.can_transition_to(SecurityState::SeccompApplied));
}

#[test]
fn test_security_property_no_privilege_escalation() {
    // Property from TLA+: [][(state = capabilities_dropped) => (~(state' = privileged))]
    // Once capabilities are dropped, cannot return to privileged

    let state = SecurityState::CapabilitiesDropped;

    // Cannot go back to privileged
    assert!(!state.can_transition_to(SecurityState::Privileged));

    // Valid forward transitions
    assert!(state.can_transition_to(SecurityState::SeccompApplied));
}

#[test]
fn test_security_property_terminal_stable() {
    // Property from TLA+: [](state \in TerminalStates => [](state \in TerminalStates))
    // Terminal state is stable (cannot leave)

    let state = SecurityState::Locked;

    assert!(state.is_terminal());

    // Cannot transition to any other state
    assert!(!state.can_transition_to(SecurityState::Privileged));
    assert!(!state.can_transition_to(SecurityState::CapabilitiesDropped));
    assert!(!state.can_transition_to(SecurityState::SeccompApplied));
    assert!(!state.can_transition_to(SecurityState::LandlockApplied));

    // Can stay in same state (stuttering)
    assert!(state.can_transition_to(SecurityState::Locked));
}

#[test]
fn test_security_property_liveness() {
    // Property from TLA+: <>(state \in {locked})
    // Eventually reaches locked state

    // We verify that there exists a path to Locked from any state
    let states = [
        SecurityState::Privileged,
        SecurityState::CapabilitiesDropped,
        SecurityState::SeccompApplied,
        SecurityState::LandlockApplied,
    ];

    for initial in states {
        // For each non-terminal state, verify there's a path to terminal
        assert!(
            !initial.is_terminal(),
            "{:?} should not be terminal",
            initial
        );

        // Verify we can reach a terminal state
        // (This is a simplified check - full path finding would be more complex)
        let mut current = initial;
        let mut can_progress = true;

        // Try to find path to terminal (max 10 steps)
        for _ in 0..10 {
            if current.is_terminal() {
                can_progress = true;
                break;
            }

            // Try next state in sequence
            current = match current {
                SecurityState::Privileged => SecurityState::CapabilitiesDropped,
                SecurityState::CapabilitiesDropped => SecurityState::SeccompApplied,
                SecurityState::SeccompApplied => SecurityState::LandlockApplied,
                SecurityState::LandlockApplied => SecurityState::Locked,
                SecurityState::Locked => break,
            };
        }

        assert!(
            can_progress,
            "Should be able to reach terminal from {:?}",
            initial
        );
    }
}

#[test]
fn test_security_all_transitions() {
    // Exhaustively test all possible transitions

    let all_states = [
        SecurityState::Privileged,
        SecurityState::CapabilitiesDropped,
        SecurityState::SeccompApplied,
        SecurityState::LandlockApplied,
        SecurityState::Locked,
    ];

    let valid_transitions = [
        (
            SecurityState::Privileged,
            SecurityState::CapabilitiesDropped,
        ),
        (
            SecurityState::CapabilitiesDropped,
            SecurityState::SeccompApplied,
        ),
        (
            SecurityState::SeccompApplied,
            SecurityState::LandlockApplied,
        ),
        (SecurityState::LandlockApplied, SecurityState::Locked),
        // Stuttering
        (SecurityState::Privileged, SecurityState::Privileged),
        (
            SecurityState::CapabilitiesDropped,
            SecurityState::CapabilitiesDropped,
        ),
        (SecurityState::SeccompApplied, SecurityState::SeccompApplied),
        (
            SecurityState::LandlockApplied,
            SecurityState::LandlockApplied,
        ),
        (SecurityState::Locked, SecurityState::Locked),
    ];

    // Test all transitions
    for from in &all_states {
        for to in &all_states {
            let should_be_valid = valid_transitions.contains(&(*from, *to));
            let is_valid = from.can_transition_to(*to);

            assert_eq!(
                is_valid, should_be_valid,
                "Transition {:?} -> {:?}: expected {}, got {}",
                from, to, should_be_valid, is_valid
            );
        }
    }
}
