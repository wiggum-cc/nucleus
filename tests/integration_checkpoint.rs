/// Integration tests for checkpoint metadata
///
/// Tests serialization/deserialization and persistence of checkpoint
/// metadata without requiring CRIU or root privileges.
#[cfg(test)]
mod tests {
    use nucleus::checkpoint::CheckpointMetadata;
    use nucleus::container::{ContainerState, ContainerStateParams};
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn sample_state() -> ContainerState {
        ContainerState::new(ContainerStateParams {
            id: "abc123def456".to_string(),
            name: "my-worker".to_string(),
            pid: 12345,
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "while true; do sleep 1; done".to_string(),
            ],
            memory_limit: Some(256 * 1024 * 1024),
            cpu_limit: Some(1000),
            using_gvisor: false,
            rootless: true,
            cgroup_path: Some("/sys/fs/cgroup/nucleus-abc123def456".to_string()),
            process_uid: 0,
            process_gid: 0,
            additional_gids: Vec::new(),
        })
    }

    #[test]
    fn test_metadata_from_state() {
        let state = sample_state();
        let meta = CheckpointMetadata::from_state(&state);

        assert_eq!(meta.container_id, "abc123def456");
        assert_eq!(meta.container_name, "my-worker");
        assert_eq!(meta.original_pid, 12345);
        assert_eq!(meta.command.len(), 3);
        assert!(!meta.using_gvisor);
        assert!(meta.rootless);
        assert!(meta.checkpoint_at > 0);
        assert!(!meta.version.is_empty());
    }

    #[test]
    fn test_metadata_save_and_load() {
        let temp = TempDir::new().unwrap();
        let state = sample_state();
        let meta = CheckpointMetadata::from_state(&state);

        meta.save(temp.path()).unwrap();

        // Verify file exists
        assert!(temp.path().join("metadata.json").exists());

        // Verify permissions (0o600)
        let file_meta = std::fs::metadata(temp.path().join("metadata.json")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);

        // Load and verify
        let loaded = CheckpointMetadata::load(temp.path()).unwrap();
        assert_eq!(loaded.container_id, meta.container_id);
        assert_eq!(loaded.container_name, meta.container_name);
        assert_eq!(loaded.original_pid, meta.original_pid);
        assert_eq!(loaded.command, meta.command);
        assert_eq!(loaded.checkpoint_at, meta.checkpoint_at);
        assert_eq!(loaded.version, meta.version);
        assert_eq!(loaded.using_gvisor, meta.using_gvisor);
        assert_eq!(loaded.rootless, meta.rootless);
    }

    #[test]
    fn test_metadata_serialization_roundtrip() {
        let state = sample_state();
        let meta = CheckpointMetadata::from_state(&state);

        let json = serde_json::to_string_pretty(&meta).unwrap();
        let deserialized: CheckpointMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.container_id, meta.container_id);
        assert_eq!(deserialized.command, meta.command);
        assert_eq!(deserialized.version, meta.version);
    }

    #[test]
    fn test_metadata_load_nonexistent_errors() {
        let temp = TempDir::new().unwrap();
        let result = CheckpointMetadata::load(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_save_overwrites() {
        let temp = TempDir::new().unwrap();

        let state1 = sample_state();
        let meta1 = CheckpointMetadata::from_state(&state1);
        meta1.save(temp.path()).unwrap();

        let mut state2 = sample_state();
        state2.name = "updated-worker".to_string();
        let meta2 = CheckpointMetadata::from_state(&state2);
        meta2.save(temp.path()).unwrap();

        let loaded = CheckpointMetadata::load(temp.path()).unwrap();
        assert_eq!(loaded.container_name, "updated-worker");
    }

    #[test]
    fn test_metadata_with_gvisor_state() {
        let mut state = sample_state();
        state.using_gvisor = true;
        state.rootless = false;

        let meta = CheckpointMetadata::from_state(&state);
        assert!(meta.using_gvisor);
        assert!(!meta.rootless);

        // Roundtrip
        let temp = TempDir::new().unwrap();
        meta.save(temp.path()).unwrap();
        let loaded = CheckpointMetadata::load(temp.path()).unwrap();
        assert!(loaded.using_gvisor);
        assert!(!loaded.rootless);
    }

    #[test]
    fn test_metadata_save_rejects_symlinked_tempfile() {
        let temp = TempDir::new().unwrap();
        let victim = temp.path().join("victim.txt");
        fs::write(&victim, "host-data").unwrap();
        symlink(&victim, temp.path().join("metadata.json.tmp")).unwrap();

        let meta = CheckpointMetadata::from_state(&sample_state());
        let err = meta.save(temp.path()).unwrap_err();

        assert!(
            err.to_string().contains("temp metadata file"),
            "save must fail closed on symlinked temp path"
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), "host-data");
    }

    #[test]
    fn test_metadata_load_rejects_symlink() {
        let temp = TempDir::new().unwrap();
        let victim = temp.path().join("victim.txt");
        fs::write(&victim, "{\"container_id\":\"leak\"}").unwrap();
        symlink(&victim, temp.path().join("metadata.json")).unwrap();

        let err = CheckpointMetadata::load(temp.path()).unwrap_err();
        assert!(
            err.to_string().contains("metadata"),
            "load must reject symlinked metadata files"
        );
    }
}
