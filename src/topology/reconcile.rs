//! Reconciliation engine: diff running vs desired state and apply changes.
//!
//! Implements the core reconciliation loop that:
//! 1. Diffs running containers against the desired topology
//! 2. Stops containers whose config hash changed
//! 3. Starts new/changed containers in dependency order
//! 4. Leaves unchanged containers running

use crate::container::{ContainerLifecycle, ContainerStateManager};
use crate::error::{NucleusError, Result};
use crate::topology::config::{ServiceDef, TopologyConfig};
use crate::topology::dag::DependencyGraph;
use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Reconciliation action for a single service.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileAction {
    /// Service is running with correct config — no action needed.
    NoChange,
    /// Service needs to be started (new or previously stopped).
    Start,
    /// Service config changed — stop then restart.
    Restart,
    /// Service is running but not in desired state — stop it.
    Stop,
}

/// The result of diffing desired vs running state.
#[derive(Debug)]
pub struct ReconcilePlan {
    /// Actions to take, in dependency order.
    pub actions: Vec<(String, ReconcileAction)>,
    /// Startup order from the DAG.
    pub startup_order: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostStartWait {
    Started,
    Healthy,
}

/// Diff the desired topology against running containers.
///
/// Returns a plan of actions to reconcile the two states.
pub fn plan_reconcile(
    config: &TopologyConfig,
    state_mgr: &ContainerStateManager,
) -> Result<ReconcilePlan> {
    let graph = DependencyGraph::resolve(config)?;
    let running_states = state_mgr.list_running().unwrap_or_default();

    // Build a map of running containers by name prefix
    let mut running_by_name: BTreeMap<String, Option<u64>> = BTreeMap::new();
    for state in &running_states {
        // Topology containers are named "topology-service" (e.g., "myapp-postgres")
        if state.name.starts_with(&format!("{}-", config.name)) {
            let service_name = state
                .name
                .strip_prefix(&format!("{}-", config.name))
                .unwrap_or(&state.name)
                .to_string();

            running_by_name.insert(service_name, state.config_hash);
        }
    }

    let mut actions = Vec::new();

    // Process in startup order
    for service_name in &graph.startup_order {
        let desired_hash = config.service_config_hash(service_name).unwrap_or(0);

        if let Some(&running_hash) = running_by_name.get(service_name) {
            if running_hash == Some(desired_hash) {
                actions.push((service_name.clone(), ReconcileAction::NoChange));
            } else {
                actions.push((service_name.clone(), ReconcileAction::Restart));
            }
        } else {
            actions.push((service_name.clone(), ReconcileAction::Start));
        }
    }

    // Find services that are running but not in desired state
    for running_name in running_by_name.keys() {
        if !config.services.contains_key(running_name) {
            actions.push((running_name.clone(), ReconcileAction::Stop));
        }
    }

    Ok(ReconcilePlan {
        actions,
        startup_order: graph.startup_order.clone(),
    })
}

/// Execute a reconciliation plan.
///
/// Stops changed/removed services in reverse dependency order,
/// then starts new/changed services in dependency order.
pub fn execute_reconcile(
    config: &TopologyConfig,
    plan: &ReconcilePlan,
    state_mgr: &ContainerStateManager,
    stop_timeout: u64,
) -> Result<()> {
    let graph = DependencyGraph::resolve(config)?;

    // Phase 1: Stop services that need stopping (in reverse dependency order)
    let shutdown_order = graph.shutdown_order();
    for service_name in &shutdown_order {
        let action = plan.actions.iter().find(|(n, _)| n == service_name);
        match action {
            Some((_, ReconcileAction::Restart)) | Some((_, ReconcileAction::Stop)) => {
                let container_name = format!("{}-{}", config.name, service_name);
                info!("Stopping service: {}", container_name);
                match state_mgr.resolve_container(&container_name) {
                    Ok(state) => {
                        if let Err(e) = ContainerLifecycle::stop(&state, stop_timeout) {
                            warn!("Failed to stop {}: {} (continuing)", container_name, e);
                        }
                    }
                    Err(_) => {
                        // Container not found — already stopped
                    }
                }
            }
            _ => {}
        }
    }

    // Phase 2: Start services that need starting (in dependency order)
    for service_name in &plan.startup_order {
        let action = plan.actions.iter().find(|(n, _)| n == service_name);
        match action {
            Some((_, ReconcileAction::Start)) | Some((_, ReconcileAction::Restart)) => {
                let svc = config.services.get(service_name).ok_or_else(|| {
                    NucleusError::ConfigError(format!(
                        "Service '{}' not found in topology",
                        service_name
                    ))
                })?;
                let container_name = format!("{}-{}", config.name, service_name);
                info!(
                    "Starting service: {} (rootfs={}, memory={})",
                    container_name, svc.rootfs, svc.memory
                );
                let desired_hash = config.service_config_hash(service_name).ok_or_else(|| {
                    NucleusError::ConfigError(format!(
                        "Service '{}' missing config hash",
                        service_name
                    ))
                })?;
                let args = build_service_run_args(svc, &container_name, desired_hash);

                // Spawn the container as a background process
                // Fail hard if current_exe() fails instead of falling back to
                // PATH search. A PATH-resolved binary could be a malicious replacement.
                let nucleus_bin = std::env::current_exe().map_err(|e| {
                    NucleusError::ExecError(format!(
                        "Failed to resolve nucleus binary path via /proc/self/exe: {}. \
                         Refusing to fall back to PATH search for security.",
                        e
                    ))
                })?;

                match Command::new(&nucleus_bin)
                    .args(&args[1..]) // skip "nucleus" since we're using current_exe
                    .stdin(Stdio::null())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()
                {
                    Ok(child) => {
                        info!("Started service {} (PID {})", container_name, child.id());
                    }
                    Err(e) => {
                        return Err(NucleusError::ExecError(format!(
                            "Failed to start service {}: {}",
                            container_name, e
                        )));
                    }
                }
                wait_for_started(state_mgr, &container_name, Duration::from_secs(10))?;
                if post_start_wait(&graph, service_name) == PostStartWait::Healthy {
                    wait_for_healthy(state_mgr, &container_name, service_name, svc)?;
                }
            }
            _ => {
                info!("Service {} unchanged, skipping", service_name);
            }
        }
    }

    Ok(())
}

fn build_service_run_args(
    svc: &ServiceDef,
    container_name: &str,
    desired_hash: u64,
) -> Vec<String> {
    let mut args = vec![
        "nucleus".to_string(),
        "run".to_string(),
        "--service-mode".to_string(),
        "production".to_string(),
        "--quiet-id".to_string(),
        "--topology-config-hash".to_string(),
        desired_hash.to_string(),
        "--name".to_string(),
        container_name.to_string(),
        "--rootfs".to_string(),
        svc.rootfs.clone(),
        "--memory".to_string(),
        svc.memory.clone(),
        "--cpus".to_string(),
        svc.cpus.to_string(),
        "--pids".to_string(),
        svc.pids.to_string(),
        "--network".to_string(),
        if svc.networks.is_empty() {
            "none".to_string()
        } else {
            "bridge".to_string()
        },
    ];

    for dns in &svc.dns {
        args.push("--dns".to_string());
        args.push(dns.clone());
    }

    for cidr in &svc.egress_allow {
        args.push("--egress-allow".to_string());
        args.push(cidr.clone());
    }

    for port in &svc.egress_tcp_ports {
        args.push("--egress-tcp-port".to_string());
        args.push(port.to_string());
    }

    for pf in &svc.port_forwards {
        args.push("-p".to_string());
        args.push(pf.clone());
    }

    for secret in &svc.secrets {
        args.push("--secret".to_string());
        args.push(secret.clone());
    }

    for (key, value) in &svc.environment {
        args.push("-e".to_string());
        args.push(format!("{}={}", key, value));
    }

    if let Some(ref hc) = svc.health_check {
        args.push("--health-cmd".to_string());
        args.push(hc.clone());
        args.push("--health-interval".to_string());
        args.push(svc.health_interval.to_string());
    }

    if svc.runtime == "gvisor" {
        args.push("--runtime".to_string());
        args.push("gvisor".to_string());
    }

    args.push("--sd-notify".to_string());
    args.push("--".to_string());
    args.extend(svc.command.clone());
    args
}

fn post_start_wait(graph: &DependencyGraph, service_name: &str) -> PostStartWait {
    for dependent in graph.dependents.get(service_name).into_iter().flatten() {
        if let Some(edges) = graph.edges.get(dependent) {
            if edges
                .iter()
                .any(|edge| edge.service == service_name && edge.condition == "healthy")
            {
                return PostStartWait::Healthy;
            }
        }
    }
    PostStartWait::Started
}

fn wait_for_started(
    state_mgr: &ContainerStateManager,
    container_name: &str,
    timeout: Duration,
) -> Result<u32> {
    let start = Instant::now();
    loop {
        match state_mgr.resolve_container(container_name) {
            Ok(state) if state.is_running() => return Ok(state.pid),
            Ok(_) | Err(_) if start.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => {
                return Err(NucleusError::ExecError(format!(
                    "Service {} did not enter running state within {:?}",
                    container_name, timeout
                )));
            }
            Err(e) => {
                return Err(NucleusError::ExecError(format!(
                    "Service {} failed to register state within {:?}: {}",
                    container_name, timeout, e
                )));
            }
        }
    }
}

fn wait_for_healthy(
    state_mgr: &ContainerStateManager,
    container_name: &str,
    service_name: &str,
    svc: &ServiceDef,
) -> Result<()> {
    let health_cmd = svc.health_check.as_ref().ok_or_else(|| {
        NucleusError::ConfigError(format!(
            "Service '{}' must define health_check to satisfy healthy dependencies",
            service_name
        ))
    })?;

    let timeout_secs = (svc.health_interval.saturating_mul(3))
        .saturating_add(10)
        .max(20);
    let timeout = Duration::from_secs(timeout_secs);
    let start = Instant::now();

    loop {
        let state = state_mgr.resolve_container(container_name)?;
        if !state.is_running() {
            return Err(NucleusError::ExecError(format!(
                "Service {} exited before becoming healthy",
                container_name
            )));
        }

        if health_check_passes(state.pid, health_cmd)? {
            info!("Service {} is healthy", container_name);
            return Ok(());
        }

        if start.elapsed() >= timeout {
            return Err(NucleusError::ExecError(format!(
                "Service {} did not become healthy within {:?}",
                container_name, timeout
            )));
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Characters that are unsafe in shell commands passed to `sh -c`.
/// Reject these to prevent command injection via topology config.
const UNSAFE_HEALTH_CHECK_CHARS: &[char] = &[
    ';', '&', '|', '$', '`', '(', ')', '{', '}', '<', '>', '!', '\\', '\n', '\r', '\0',
];

/// Validate that a health check command does not contain shell metacharacters
/// that could enable command injection.
fn validate_health_check_command(command: &str) -> Result<()> {
    if command.is_empty() {
        return Err(NucleusError::ConfigError(
            "Health check command must not be empty".to_string(),
        ));
    }
    for ch in UNSAFE_HEALTH_CHECK_CHARS {
        if command.contains(*ch) {
            return Err(NucleusError::ConfigError(format!(
                "Health check command contains unsafe character '{}': {}",
                ch.escape_default(),
                command
            )));
        }
    }
    Ok(())
}

fn health_check_passes(pid: u32, command: &str) -> Result<bool> {
    validate_health_check_command(command)?;

    let pid_str = pid.to_string();
    let status = Command::new(resolve_nsenter())
        .args([
            "-t", &pid_str, "-m", "-p", "-n", "--", "/bin/sh", "-c", command,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| {
            NucleusError::ExecError(format!("Failed to run health check for PID {}: {}", pid, e))
        })?;
    Ok(status.success())
}

fn resolve_nsenter() -> String {
    if nix::unistd::Uid::effective().is_root() {
        for path in ["/usr/bin/nsenter", "/usr/sbin/nsenter", "/bin/nsenter"] {
            if std::path::Path::new(path).exists() {
                return path.to_string();
            }
        }
    }
    "nsenter".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::ContainerState;

    #[test]
    fn test_plan_new_topology() {
        let toml = r#"
name = "test"

[services.db]
rootfs = "/nix/store/db"
command = ["postgres"]
memory = "1G"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"

[[services.web.depends_on]]
service = "db"
condition = "healthy"
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let state_mgr = ContainerStateManager::with_state_dir(temp.path().join("nucleus")).unwrap();
        let plan = plan_reconcile(&config, &state_mgr).unwrap();

        // Both services should be Start since nothing is running
        assert_eq!(plan.actions.len(), 2);
        assert!(plan
            .actions
            .iter()
            .all(|(_, a)| *a == ReconcileAction::Start));
        // db should be before web in startup order
        assert_eq!(plan.startup_order[0], "db");
        assert_eq!(plan.startup_order[1], "web");
    }

    #[test]
    fn test_plan_matching_running_hash_is_no_change() {
        let toml = r#"
name = "test"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let state_mgr = ContainerStateManager::with_state_dir(temp.path().join("nucleus")).unwrap();
        let mut state = ContainerState::new(
            "abc123".to_string(),
            "test-web".to_string(),
            std::process::id(),
            vec!["/bin/web".to_string()],
            None,
            None,
            false,
            false,
            None,
        );
        state.config_hash = config.service_config_hash("web");
        state_mgr.save_state(&state).unwrap();

        let plan = plan_reconcile(&config, &state_mgr).unwrap();
        assert_eq!(
            plan.actions,
            vec![("web".to_string(), ReconcileAction::NoChange)]
        );
    }

    #[test]
    fn test_post_start_wait_marks_healthy_dependencies() {
        let toml = r#"
name = "test"

[services.db]
rootfs = "/nix/store/db"
command = ["postgres"]
memory = "1G"
health_check = "pg_isready"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"

[[services.web.depends_on]]
service = "db"
condition = "healthy"
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let graph = DependencyGraph::resolve(&config).unwrap();

        assert_eq!(post_start_wait(&graph, "db"), PostStartWait::Healthy);
        assert_eq!(post_start_wait(&graph, "web"), PostStartWait::Started);
    }

    #[test]
    fn test_build_service_run_args_include_topology_hash() {
        let toml = r#"
name = "test"

[services.web]
rootfs = "/nix/store/web"
command = ["/bin/web"]
memory = "256M"
"#;
        let config = TopologyConfig::from_toml(toml).unwrap();
        let svc = config.services.get("web").unwrap();
        let args = build_service_run_args(svc, "test-web", 42);

        assert!(args
            .windows(2)
            .any(|pair| { pair[0] == "--topology-config-hash" && pair[1] == "42" }));
        assert!(args.iter().any(|arg| arg == "--quiet-id"));
    }

    #[test]
    fn test_health_check_rejects_shell_metacharacters() {
        // H-4: health check commands must not contain shell injection chars
        assert!(validate_health_check_command("pg_isready").is_ok());
        assert!(validate_health_check_command("curl -f http://localhost:8080/health").is_ok());

        // Semicolon injection
        assert!(validate_health_check_command("pg_isready; rm -rf /").is_err());
        // Pipe injection
        assert!(validate_health_check_command("echo test | sh").is_err());
        // Command substitution
        assert!(validate_health_check_command("$(cat /etc/shadow)").is_err());
        // Backtick substitution
        assert!(validate_health_check_command("`cat /etc/shadow`").is_err());
        // Background
        assert!(validate_health_check_command("malware &").is_err());
        // Empty
        assert!(validate_health_check_command("").is_err());
    }
}
