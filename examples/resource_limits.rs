//! Example: Container with resource limits
//!
//! This example demonstrates how to set memory, CPU, and PID limits
//! for a container using cgroups v2.
//! Note: Requires root privileges and cgroup v2 to run.

use nucleus::container::{Container, ContainerConfig};
use nucleus::error::Result;
use nucleus::isolation::NamespaceConfig;
use nucleus::resources::ResourceLimits;

fn main() -> Result<()> {
    // Configure resource limits
    let limits = ResourceLimits::unlimited()
        .with_memory("128M")? // 128 MB memory limit
        .with_cpu_cores(0.5)? // 0.5 CPU cores (50% of one core)
        .with_pids(50)?; // Maximum 50 processes

    println!("Resource limits configured:");
    println!("  Memory: {:?} bytes", limits.memory_bytes);
    println!(
        "  CPU quota: {:?} µs / {:?} µs",
        limits.cpu_quota_us, limits.cpu_period_us
    );
    println!("  PIDs: {:?}", limits.pids_max);

    let config = ContainerConfig::try_new(
        Some("limited-container".to_string()),
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo 'Running with resource limits'; sleep 1".to_string(),
        ],
    )?
    .with_limits(limits)
    .with_namespaces(NamespaceConfig::all());

    // Run container
    println!("\nStarting container...");
    let container = Container::new(config);
    let exit_code = container.run()?;

    println!("Container exited with code: {}", exit_code);

    Ok(())
}
