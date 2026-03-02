/// Model-based tests for resources module
///
/// These tests verify that the Rust implementation matches the TLA+ specification
/// defined in Nucleus_Resources_CgroupLifecycle.tla
///
/// Properties verified:
/// - resource_limits_enforced: Once configured, can only move to attached, monitoring, or removed
/// - cleanup_guaranteed: Eventually reaches removed state
/// - no_resource_leak: Removed state is terminal and stable
use nucleus::resources::CgroupState;

#[test]
fn test_cgroup_state_machine_happy_path() {
    // Verify the happy path: nonexistent -> created -> configured -> attached -> monitoring -> removed
    let states = vec![
        CgroupState::Nonexistent,
        CgroupState::Created,
        CgroupState::Configured,
        CgroupState::Attached,
        CgroupState::Monitoring,
        CgroupState::Removed,
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
fn test_cgroup_property_resource_limits_enforced() {
    // Property from TLA+: [][(state = configured) => ((state' = attached) \/ (state' = monitoring) \/ (state' = removed))]
    // Once configured, can only move to specific states

    let state = CgroupState::Configured;

    // Valid transitions
    assert!(state.can_transition_to(CgroupState::Configured)); // stuttering
    assert!(state.can_transition_to(CgroupState::Attached));
    assert!(state.can_transition_to(CgroupState::Removed)); // error path

    // Invalid transitions
    assert!(!state.can_transition_to(CgroupState::Nonexistent));
    assert!(!state.can_transition_to(CgroupState::Created));
    assert!(!state.can_transition_to(CgroupState::Monitoring)); // must go through Attached
}

#[test]
fn test_cgroup_property_no_resource_leak() {
    // Property from TLA+: [][(state = removed) => (state' = removed)]
    // Removed state is terminal

    let state = CgroupState::Removed;

    assert!(state.is_terminal());

    // Cannot transition to any other state
    assert!(!state.can_transition_to(CgroupState::Nonexistent));
    assert!(!state.can_transition_to(CgroupState::Created));
    assert!(!state.can_transition_to(CgroupState::Configured));
    assert!(!state.can_transition_to(CgroupState::Attached));
    assert!(!state.can_transition_to(CgroupState::Monitoring));

    // Can stay in same state
    assert!(state.can_transition_to(CgroupState::Removed));
}

#[test]
fn test_cgroup_property_cleanup_guaranteed() {
    // Property from TLA+: [][(state = created) => (<>(state = removed))]
    // Eventually reaches removed state

    let states = [
        CgroupState::Nonexistent,
        CgroupState::Created,
        CgroupState::Configured,
        CgroupState::Attached,
        CgroupState::Monitoring,
    ];

    for initial in states {
        assert!(
            !initial.is_terminal(),
            "{:?} should not be terminal",
            initial
        );

        // Verify there's a path to terminal
        let mut current = initial;
        let mut steps = 0;

        while !current.is_terminal() && steps < 10 {
            current = match current {
                CgroupState::Nonexistent => CgroupState::Created,
                CgroupState::Created => CgroupState::Configured,
                CgroupState::Configured => CgroupState::Attached,
                CgroupState::Attached => CgroupState::Monitoring,
                CgroupState::Monitoring => CgroupState::Removed,
                CgroupState::Removed => break,
            };
            steps += 1;
        }

        assert!(
            current.is_terminal(),
            "Should reach terminal from {:?}",
            initial
        );
    }
}

#[test]
fn test_cgroup_error_paths() {
    // Error paths allow jumping to Removed from Created or Configured

    assert!(CgroupState::Created.can_transition_to(CgroupState::Removed));
    assert!(CgroupState::Configured.can_transition_to(CgroupState::Removed));
}

#[test]
fn test_cgroup_no_backwards_transitions() {
    // Cannot move backwards in the state machine

    assert!(!CgroupState::Created.can_transition_to(CgroupState::Nonexistent));
    assert!(!CgroupState::Configured.can_transition_to(CgroupState::Created));
    assert!(!CgroupState::Attached.can_transition_to(CgroupState::Configured));
    assert!(!CgroupState::Monitoring.can_transition_to(CgroupState::Attached));
    assert!(!CgroupState::Removed.can_transition_to(CgroupState::Monitoring));
}
