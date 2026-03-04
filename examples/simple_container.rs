//! Example: Simple container execution
//!
//! This example demonstrates basic container creation and execution.
//! Note: Requires root privileges to run.

use anyhow::Result;
use nucleus::container::{Container, ContainerConfig};
use nucleus::isolation::NamespaceConfig;
use nucleus::resources::ResourceLimits;

fn main() -> Result<()> {
    // Create container configuration
    let limits = ResourceLimits::unlimited()
        .with_memory("256M")?
        .with_cpu_cores(1.0)?;

    let config = ContainerConfig::new(
        Some("example-container".to_string()),
        vec!["/bin/echo".to_string(), "Hello from Nucleus!".to_string()],
    )
    .with_limits(limits)
    .with_namespaces(NamespaceConfig::all());

    // Run container
    println!("Starting container...");
    let container = Container::new(config);
    let exit_code = container.run()?;

    println!("Container exited with code: {}", exit_code);

    Ok(())
}
