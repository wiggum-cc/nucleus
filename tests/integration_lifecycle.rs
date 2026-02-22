/// Integration test for complete container lifecycle
///
/// This test verifies the complete container execution flow matching
/// NucleusVerification_IntegrationTests_ContainerLifecycleTest.tla
///
/// State transitions tested:
/// test_start -> container_created -> container_running -> container_exited -> cleanup_done

#[cfg(test)]
mod tests {
    use nucleus::container::{Container, ContainerConfig};
    use nucleus::isolation::NamespaceConfig;
    use nucleus::resources::ResourceLimits;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    #[ignore] // Requires root privileges
    fn test_container_lifecycle_echo() {
        // Create temporary context directory
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let context_path = temp_dir.path().to_path_buf();

        // Create a simple file in context
        std::fs::write(context_path.join("test.txt"), "Hello from nucleus")
            .expect("Failed to write test file");

        // Configure container with minimal resources
        let limits = ResourceLimits::unlimited()
            .with_memory("128M").expect("Failed to set memory")
            .with_cpu_cores(1.0).expect("Failed to set CPU");

        let config = ContainerConfig::new(
            "test-echo".to_string(),
            vec!["/bin/echo".to_string(), "hello".to_string()],
        )
        .with_context(context_path)
        .with_limits(limits)
        .with_namespaces(NamespaceConfig::minimal());

        // Run container
        let container = Container::new(config);
        let result = container.run();

        // Verify successful execution
        assert!(result.is_ok(), "Container should execute successfully");
        let exit_code = result.unwrap();
        assert_eq!(exit_code, 0, "Container should exit with code 0");
    }

    #[test]
    fn test_container_config_builder() {
        // Test the configuration builder pattern
        let config = ContainerConfig::new(
            "test".to_string(),
            vec!["/bin/sh".to_string(), "-c".to_string(), "exit 0".to_string()],
        )
        .with_context(PathBuf::from("/tmp/test"))
        .with_namespaces(NamespaceConfig::minimal())
        .with_gvisor(false);

        assert_eq!(config.name, "test");
        assert_eq!(config.command.len(), 3);
        assert!(config.context_dir.is_some());
        assert!(!config.use_gvisor);
    }

    #[test]
    fn test_resource_limits_configuration() {
        // Test resource limit parsing and configuration
        let limits = ResourceLimits::unlimited()
            .with_memory("512M").expect("Failed to set memory")
            .with_cpu_cores(2.0).expect("Failed to set CPU")
            .with_pids(100).expect("Failed to set PIDs");

        assert_eq!(limits.memory_bytes, Some(512 * 1024 * 1024));
        assert_eq!(limits.cpu_quota_us, Some(200_000)); // 2.0 * 100_000
        assert_eq!(limits.pids_max, Some(100));
    }

    #[test]
    fn test_namespace_config_variations() {
        // Test different namespace configurations
        let all = NamespaceConfig::all();
        assert!(all.pid && all.mnt && all.net && all.uts && all.ipc);

        let minimal = NamespaceConfig::minimal();
        assert!(minimal.pid && minimal.mnt && minimal.net);
        assert!(!minimal.uts && !minimal.ipc);
    }
}
