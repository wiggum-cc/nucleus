//! Reconciliation engine: diff running vs desired state and apply changes.
//!
//! Implements the core reconciliation loop that:
//! 1. Diffs running containers against the desired topology
//! 2. Stops containers whose config hash changed
//! 3. Starts new/changed containers in dependency order
//! 4. Leaves unchanged containers running

use crate::container::{ContainerLifecycle, ContainerStateManager};
use crate::error::{NucleusError, Result};
use crate::isolation::{NamespaceCommandRunner, NamespaceProbe};
use crate::topology::config::{ServiceDef, TopologyConfig};
use crate::topology::dag::DependencyGraph;
use std::collections::BTreeMap;
use std::os::unix::fs::OpenOptionsExt;
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

    // Phase 1b: Stop removed services that are NOT in shutdown_order.
    // shutdown_order only contains services from the desired topology, so
    // services that were removed from config won't appear there at all.
    for (service_name, action) in &plan.actions {
        if *action != ReconcileAction::Stop {
            continue;
        }
        // Already handled above if it happened to be in shutdown_order
        if shutdown_order.contains(service_name) {
            continue;
        }
        let container_name = format!("{}-{}", config.name, service_name);
        info!("Stopping removed service: {}", container_name);
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
                let args = build_service_run_args(svc, &container_name, desired_hash)?;

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
) -> Result<Vec<String>> {
    let mut args = vec![
        "nucleus".to_string(),
        "create".to_string(),
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

    // C-2: Write secrets to a secure temp file instead of passing via CLI args.
    // Secrets on the command line are visible in /proc/<pid>/cmdline to any user.
    if !svc.secrets.is_empty() {
        let secrets_file = write_secrets_file(container_name, &svc.secrets)?;
        args.push("--secrets-file".to_string());
        args.push(secrets_file);
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

    // Write hooks to a temp file and pass via --hooks flag
    if let Some(ref hooks) = svc.hooks {
        if !hooks.is_empty() {
            if let Ok(hooks_json) = serde_json::to_string(hooks) {
                let hooks_path =
                    std::env::temp_dir().join(format!("nucleus-hooks-{}.json", container_name));
                if std::fs::write(&hooks_path, hooks_json).is_ok() {
                    args.push("--hooks".to_string());
                    args.push(hooks_path.to_string_lossy().to_string());
                }
            }
        }
    }

    args.push("--sd-notify".to_string());
    args.push("--".to_string());
    args.extend(svc.command.clone());
    Ok(args)
}

/// Write secrets to a secure temp file (mode 0o600) and return the path.
///
/// The child process reads secrets from this file instead of receiving them
/// via CLI arguments, which would be visible in /proc/<pid>/cmdline.
fn write_secrets_file(container_name: &str, secrets: &[String]) -> Result<String> {
    let secrets_path = std::env::temp_dir().join(format!("nucleus-secrets-{}.txt", container_name));

    // Open with restrictive permissions (owner read/write only)
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&secrets_path)
        .map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to create secrets file for {}: {}",
                container_name, e
            ))
        })?;

    use std::io::Write;
    let mut writer = std::io::BufWriter::new(file);
    for secret in secrets {
        writeln!(writer, "{}", secret).map_err(|e| {
            NucleusError::ConfigError(format!(
                "Failed to write secrets file for {}: {}",
                container_name, e
            ))
        })?;
    }
    writer.flush().map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to flush secrets file for {}: {}",
            container_name, e
        ))
    })?;

    Ok(secrets_path.to_string_lossy().to_string())
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

        if health_check_passes(state.pid, state.rootless, state.using_gvisor, health_cmd)? {
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

/// Characters that are safe in shell commands passed to `sh -c`.
/// Only allow these characters — everything else is rejected.
const SAFE_HEALTH_CHECK_CHARS: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', ' ', '-', '_', '.', '/', ':', '@', '=', '?',
];

/// Validate that a health check command contains only safe characters.
/// Uses an allowlist approach — only alphanumeric, spaces, and a few
/// safe punctuation marks are permitted.
fn validate_health_check_command(command: &str) -> Result<()> {
    if command.is_empty() {
        return Err(NucleusError::ConfigError(
            "Health check command must not be empty".to_string(),
        ));
    }
    for ch in command.chars() {
        if !SAFE_HEALTH_CHECK_CHARS.contains(&ch) {
            return Err(NucleusError::ConfigError(format!(
                "Health check command contains unsafe character '{}' (code point U+{:04X}): {}",
                ch.escape_default(),
                ch as u32,
                command
            )));
        }
    }
    Ok(())
}

fn health_check_passes(
    pid: u32,
    rootless: bool,
    using_gvisor: bool,
    command: &str,
) -> Result<bool> {
    validate_health_check_command(command)?;

    NamespaceCommandRunner::run(
        pid,
        rootless,
        using_gvisor,
        NamespaceProbe::Exec(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            command.to_string(),
        ]),
        Some(Duration::from_secs(5)),
    )
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
        let args = build_service_run_args(svc, "test-web", 42).unwrap();

        assert!(args
            .windows(2)
            .any(|pair| { pair[0] == "--topology-config-hash" && pair[1] == "42" }));
        assert!(args.iter().any(|arg| arg == "--quiet-id"));
    }

    #[test]
    fn test_health_check_rejects_shell_metacharacters() {
        // H-4: health check commands must only contain allowlisted characters
        assert!(validate_health_check_command("pg_isready").is_ok());
        assert!(validate_health_check_command("curl -f http://localhost:8080/health").is_ok());

        // Semicolon injection — not in allowlist
        assert!(validate_health_check_command("pg_isready; rm -rf /").is_err());
        // Pipe — not in allowlist
        assert!(validate_health_check_command("echo test | sh").is_err());
        // Command substitution — not in allowlist
        assert!(validate_health_check_command("$(cat /etc/shadow)").is_err());
        // Backtick — not in allowlist
        assert!(validate_health_check_command("`cat /etc/shadow`").is_err());
        // Dollar sign — not in allowlist
        assert!(validate_health_check_command("$HOME").is_err());
        // Background ampersand — not in allowlist
        assert!(validate_health_check_command("malware &").is_err());
        // Empty
        assert!(validate_health_check_command("").is_err());
        // Newline — not in allowlist
        assert!(validate_health_check_command("test\ngood").is_err());
    }

    /// Extract the body of a function from source text by brace-matching,
    /// avoiding fragile hardcoded character-window offsets (SEC-MED-03).
    fn extract_fn_body<'a>(source: &'a str, fn_signature: &str) -> &'a str {
        let fn_start = source
            .find(fn_signature)
            .unwrap_or_else(|| panic!("function '{}' not found in source", fn_signature));
        let after = &source[fn_start..];
        let open = after
            .find('{')
            .unwrap_or_else(|| panic!("no opening brace found for '{}'", fn_signature));
        let mut depth = 0u32;
        let mut end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        &after[..end]
    }

    #[test]
    fn test_topology_health_checks_do_not_spawn_host_nsenter() {
        let source = include_str!("reconcile.rs");
        let fn_body = extract_fn_body(source, "fn health_check_passes");
        assert!(
            !fn_body.contains("Command::new(resolve_nsenter())"),
            "topology health checks must not execute via host nsenter"
        );
    }

    #[test]
    fn test_plan_stop_for_removed_services() {
        // BUG-01: Services removed from topology must get ReconcileAction::Stop
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

        // Simulate a previously-running service "db" that is no longer in config
        let state = ContainerState::new(
            "old-db-id".to_string(),
            "test-db".to_string(),
            std::process::id(), // use our own PID so is_running() returns true
            vec!["postgres".to_string()],
            None,
            None,
            false,
            false,
            None,
        );
        state_mgr.save_state(&state).unwrap();

        let plan = plan_reconcile(&config, &state_mgr).unwrap();

        // The plan must include a Stop action for "db"
        let stop_actions: Vec<_> = plan
            .actions
            .iter()
            .filter(|(_, a)| *a == ReconcileAction::Stop)
            .collect();
        assert!(
            !stop_actions.is_empty(),
            "removed services must have Stop action"
        );
        assert_eq!(stop_actions[0].0, "db");
    }
}
