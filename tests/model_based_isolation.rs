/// Model-based tests for isolation module
///
/// These tests verify that the Rust implementation matches the TLA+ specification
/// defined in Nucleus_Isolation_NamespaceLifecycle.tla
///
/// Properties verified:
/// - isolation_integrity: Once entered, can only move to entered or cleaned
/// - cleanup_happens: If entered, eventually cleaned
/// - Terminal state stability: Cleaned state is terminal

use nucleus::isolation::NamespaceState;

#[test]
fn test_namespace_state_machine_valid_path() {
    // Verify the happy path: uninitialized -> unshared -> entered -> cleaned
    let states = vec![
        NamespaceState::Uninitialized,
        NamespaceState::Unshared,
        NamespaceState::Entered,
        NamespaceState::Cleaned,
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
fn test_namespace_property_isolation_integrity() {
    // Property from TLA+: [][(state = entered) => ((state' = entered) \/ (state' = cleaned))]
    // Once entered, can only stay or move to cleaned

    let state = NamespaceState::Entered;

    // Valid transitions
    assert!(state.can_transition_to(NamespaceState::Entered));
    assert!(state.can_transition_to(NamespaceState::Cleaned));

    // Invalid transitions
    assert!(!state.can_transition_to(NamespaceState::Uninitialized));
    assert!(!state.can_transition_to(NamespaceState::Unshared));
}

#[test]
fn test_namespace_property_terminal_stable() {
    // Terminal state is stable (cannot leave)

    let state = NamespaceState::Cleaned;

    assert!(state.is_terminal());

    // Cannot transition to any other state
    assert!(!state.can_transition_to(NamespaceState::Uninitialized));
    assert!(!state.can_transition_to(NamespaceState::Unshared));
    assert!(!state.can_transition_to(NamespaceState::Entered));

    // Can stay in same state (stuttering)
    assert!(state.can_transition_to(NamespaceState::Cleaned));
}

#[test]
fn test_namespace_property_liveness() {
    // Property from TLA+: <>(state \in {cleaned})
    // Eventually reaches cleaned state

    let states = [
        NamespaceState::Uninitialized,
        NamespaceState::Unshared,
        NamespaceState::Entered,
    ];

    for initial in states {
        assert!(!initial.is_terminal(), "{:?} should not be terminal", initial);

        // Verify there's a path to terminal
        let mut current = initial;

        for _ in 0..10 {
            if current.is_terminal() {
                break;
            }

            current = match current {
                NamespaceState::Uninitialized => NamespaceState::Unshared,
                NamespaceState::Unshared => NamespaceState::Entered,
                NamespaceState::Entered => NamespaceState::Cleaned,
                NamespaceState::Cleaned => break,
            };
        }

        assert!(current.is_terminal(), "Should reach terminal from {:?}", initial);
    }
}

#[test]
fn test_namespace_no_state_skipping() {
    // Cannot skip intermediate states

    assert!(!NamespaceState::Uninitialized.can_transition_to(NamespaceState::Entered));
    assert!(!NamespaceState::Uninitialized.can_transition_to(NamespaceState::Cleaned));
    assert!(!NamespaceState::Unshared.can_transition_to(NamespaceState::Cleaned));
}

#[test]
fn test_namespace_no_backwards_transitions() {
    // Cannot move backwards in the state machine

    assert!(!NamespaceState::Unshared.can_transition_to(NamespaceState::Uninitialized));
    assert!(!NamespaceState::Entered.can_transition_to(NamespaceState::Unshared));
    assert!(!NamespaceState::Cleaned.can_transition_to(NamespaceState::Entered));
}
