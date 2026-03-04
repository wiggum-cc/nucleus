//! Example: Container with pre-populated context
//!
//! This example shows how to pre-populate a container with files
//! that the containerized process can access.
//! Note: Requires root privileges to run.

use anyhow::Result;
use nucleus::container::{Container, ContainerConfig};
use nucleus::isolation::NamespaceConfig;
use nucleus::resources::ResourceLimits;
use tempfile::TempDir;

fn main() -> Result<()> {
    // Create temporary context directory with sample files
    let temp_dir = TempDir::new()?;
    let context_path = temp_dir.path();

    std::fs::write(context_path.join("data.txt"), "Sample data for agent")?;
    std::fs::write(context_path.join("config.json"), r#"{"key": "value"}"#)?;

    println!("Context directory: {:?}", context_path);

    // Create container configuration
    let limits = ResourceLimits::unlimited()
        .with_memory("512M")?
        .with_cpu_cores(2.0)?;

    let config = ContainerConfig::new(
        Some("context-example".to_string()),
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "ls -la /context && cat /context/data.txt".to_string(),
        ],
    )
    .with_context(context_path.to_path_buf())
    .with_limits(limits)
    .with_namespaces(NamespaceConfig::all());

    // Run container
    println!("Starting container with context...");
    let container = Container::new(config);
    let exit_code = container.run()?;

    println!("Container exited with code: {}", exit_code);

    Ok(())
}
