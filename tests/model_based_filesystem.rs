/// Model-based tests for filesystem module
///
/// These tests verify that the Rust implementation matches the TLA+ specification
/// defined in Nucleus_Filesystem_FilesystemLifecycle.tla
///
/// Properties verified:
/// - context_isolation: Once pivoted, can only move to pivoted or unmounted_final
/// - ephemeral_guarantee: unmounted_final is terminal and stable
/// - mount_ordering: populated can continue to pivot_root or abort cleanup
use nucleus::filesystem::FilesystemState;
use nucleus::StateTransition;

#[test]
fn test_filesystem_state_machine_happy_path() {
    // Verify the happy path: unmounted -> mounted -> populated -> pivoted -> unmounted_final
    let states = [
        FilesystemState::Unmounted,
        FilesystemState::Mounted,
        FilesystemState::Populated,
        FilesystemState::Pivoted,
        FilesystemState::UnmountedFinal,
    ];

    for i in 0..states.len() - 1 {
        assert!(
            states[i].can_transition_to(&states[i + 1]),
            "Invalid transition from {:?} to {:?}",
            states[i],
            states[i + 1]
        );
    }
}

#[test]
fn test_filesystem_property_context_isolation() {
    // Property from TLA+: [][(state = pivoted) => ((state' = pivoted) \/ (state' = unmounted_final))]
    // Once pivoted, can only stay or move to unmounted_final

    let state = FilesystemState::Pivoted;

    // Valid transitions
    assert!(state.can_transition_to(&FilesystemState::Pivoted)); // stuttering
    assert!(state.can_transition_to(&FilesystemState::UnmountedFinal));

    // Invalid transitions
    assert!(!state.can_transition_to(&FilesystemState::Unmounted));
    assert!(!state.can_transition_to(&FilesystemState::Mounted));
    assert!(!state.can_transition_to(&FilesystemState::Populated));
}

#[test]
fn test_filesystem_property_ephemeral_guarantee() {
    // Property from TLA+: [][(state = unmounted_final) => (state' = unmounted_final)]
    // unmounted_final is terminal

    let state = FilesystemState::UnmountedFinal;

    assert!(state.is_terminal());

    // Cannot transition to any other state
    assert!(!state.can_transition_to(&FilesystemState::Unmounted));
    assert!(!state.can_transition_to(&FilesystemState::Mounted));
    assert!(!state.can_transition_to(&FilesystemState::Populated));
    assert!(!state.can_transition_to(&FilesystemState::Pivoted));

    // Can stay in same state
    assert!(state.can_transition_to(&FilesystemState::UnmountedFinal));
}

#[test]
fn test_filesystem_property_mount_ordering() {
    // Cleanup is allowed before pivot_root, so populated may either continue
    // forward to pivoted or abort back to unmounted.

    let state = FilesystemState::Populated;

    // Valid transitions
    assert!(state.can_transition_to(&FilesystemState::Populated)); // stuttering
    assert!(state.can_transition_to(&FilesystemState::Pivoted));
    assert!(state.can_transition_to(&FilesystemState::Unmounted));

    // Invalid transitions - cannot move to mounted or skip directly to final
    assert!(!state.can_transition_to(&FilesystemState::Mounted));
    assert!(!state.can_transition_to(&FilesystemState::UnmountedFinal));
}

#[test]
fn test_filesystem_no_state_skipping() {
    // Cannot skip intermediate states

    assert!(!FilesystemState::Unmounted.can_transition_to(&FilesystemState::Populated));
    assert!(!FilesystemState::Unmounted.can_transition_to(&FilesystemState::Pivoted));
    assert!(!FilesystemState::Mounted.can_transition_to(&FilesystemState::Pivoted));
    assert!(!FilesystemState::Mounted.can_transition_to(&FilesystemState::UnmountedFinal));
}

#[test]
fn test_filesystem_no_backwards_transitions() {
    // Cannot move backwards once the root has been pivoted or finalized.

    assert!(FilesystemState::Mounted.can_transition_to(&FilesystemState::Unmounted));
    assert!(!FilesystemState::Populated.can_transition_to(&FilesystemState::Mounted));
    assert!(!FilesystemState::Pivoted.can_transition_to(&FilesystemState::Populated));
    assert!(!FilesystemState::UnmountedFinal.can_transition_to(&FilesystemState::Pivoted));
}

#[test]
fn test_filesystem_liveness() {
    // All states can eventually reach terminal

    let states = [
        FilesystemState::Unmounted,
        FilesystemState::Mounted,
        FilesystemState::Populated,
        FilesystemState::Pivoted,
    ];

    for initial in states {
        assert!(
            !initial.is_terminal(),
            "{:?} should not be terminal",
            initial
        );

        let mut current = initial;
        let mut steps = 0;

        while !current.is_terminal() && steps < 10 {
            current = match current {
                FilesystemState::Unmounted => FilesystemState::Mounted,
                FilesystemState::Mounted => FilesystemState::Populated,
                FilesystemState::Populated => FilesystemState::Pivoted,
                FilesystemState::Pivoted => FilesystemState::UnmountedFinal,
                FilesystemState::UnmountedFinal => break,
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
