use clap::Parser;
use nucleus::checkpoint::CriuRuntime;
use nucleus::container::{
    parse_signal, validate_container_name, validate_hostname, Container, ContainerConfig,
    ContainerLifecycle, ContainerState, ContainerStateManager, ContainerStateParams, HealthCheck,
    KernelLockdownMode, NetworkModeArg, OciStatus, ProcessIdentity, ReadinessProbe,
    RuntimeSelection, SeccompMode, SecretMount, ServiceMode, TrustLevel, VolumeMount, VolumeSource,
};
use nucleus::error::{NucleusError, Result};
use nucleus::filesystem::ContextMode;
use nucleus::isolation::{ContainerAttach, NamespaceConfig};
use nucleus::network::{BridgeConfig, EgressPolicy, NetworkMode, PortForward};
use nucleus::resources::{IoDeviceLimit, ResourceLimits, ResourceStats};
use nucleus::security::GVisorPlatform;
use nucleus::topology::{
    execute_reconcile, plan_reconcile, DependencyGraph, ReconcileAction, TopologyConfig,
};
use std::path::PathBuf;
use tracing::info;

fn validate_systemd_credential_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(NucleusError::ConfigError(
            "Systemd credential name cannot be empty".to_string(),
        ));
    }
    if name.contains('/') || name.contains('\0') || name == "." || name == ".." {
        return Err(NucleusError::ConfigError(format!(
            "Invalid systemd credential name '{}'",
            name
        )));
    }
    Ok(())
}

fn resolve_systemd_credential_source(name: &str) -> Result<PathBuf> {
    validate_systemd_credential_name(name)?;
    let credentials_dir = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
        NucleusError::ConfigError(
            "--systemd-credential requires CREDENTIALS_DIRECTORY from systemd".to_string(),
        )
    })?;
    let credentials_dir = PathBuf::from(credentials_dir);
    let canonical_dir = std::fs::canonicalize(&credentials_dir).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to resolve CREDENTIALS_DIRECTORY {:?}: {}",
            credentials_dir, e
        ))
    })?;
    let source = std::fs::canonicalize(credentials_dir.join(name)).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Systemd credential '{}' cannot be resolved under {:?}: {}",
            name, credentials_dir, e
        ))
    })?;
    if !source.starts_with(&canonical_dir) {
        return Err(NucleusError::ConfigError(format!(
            "Systemd credential '{}' resolved outside CREDENTIALS_DIRECTORY",
            name
        )));
    }
    Ok(source)
}

fn resolve_uid_spec(spec: &str) -> Result<(u32, Option<u32>)> {
    if let Ok(uid) = spec.parse::<u32>() {
        return Ok((uid, None));
    }

    let user = nix::unistd::User::from_name(spec)
        .map_err(|e| {
            NucleusError::ConfigError(format!("Failed to resolve user '{}': {}", spec, e))
        })?
        .ok_or_else(|| NucleusError::ConfigError(format!("Unknown user '{}'", spec)))?;

    Ok((user.uid.as_raw(), Some(user.gid.as_raw())))
}

fn resolve_gid_spec(spec: &str) -> Result<u32> {
    if let Ok(gid) = spec.parse::<u32>() {
        return Ok(gid);
    }

    let group = nix::unistd::Group::from_name(spec)
        .map_err(|e| {
            NucleusError::ConfigError(format!("Failed to resolve group '{}': {}", spec, e))
        })?
        .ok_or_else(|| NucleusError::ConfigError(format!("Unknown group '{}'", spec)))?;

    Ok(group.gid.as_raw())
}

fn resolve_process_identity(
    user: Option<&str>,
    group: Option<&str>,
    additional_groups: &[String],
) -> Result<Option<ProcessIdentity>> {
    if user.is_none() && group.is_none() && additional_groups.is_empty() {
        return Ok(None);
    }

    let user = user.ok_or_else(|| {
        NucleusError::ConfigError(
            "--group/--additional-group require --user to be set as well".to_string(),
        )
    })?;
    let (uid, default_gid) = resolve_uid_spec(user)?;
    let gid = match group {
        Some(group) => resolve_gid_spec(group)?,
        None => default_gid.ok_or_else(|| {
            NucleusError::ConfigError(
                "Numeric --user values require an explicit --group".to_string(),
            )
        })?,
    };

    let mut resolved_additional_gids = Vec::new();
    for group in additional_groups {
        let resolved = resolve_gid_spec(group)?;
        if resolved != gid && !resolved_additional_gids.contains(&resolved) {
            resolved_additional_gids.push(resolved);
        }
    }

    Ok(Some(ProcessIdentity {
        uid,
        gid,
        additional_gids: resolved_additional_gids,
    }))
}

#[derive(Parser, Debug)]
#[command(name = "nucleus")]
#[command(about = "Extremely lightweight Docker alternative for agents", long_about = None)]
struct Cli {
    /// Root directory for state storage (overrides default)
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    /// Log file path (OCI runtime interface)
    #[arg(long, global = true)]
    log: Option<PathBuf>,

    /// Log format: text (default) or json (OCI runtime interface)
    #[arg(long, global = true, default_value = "text")]
    log_format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Create and run a container
    Create {
        /// Container name (optional, auto-generated if not specified)
        #[arg(long)]
        name: Option<String>,

        /// Path to context directory to pre-populate in container
        #[arg(long)]
        context: Option<String>,

        /// Memory limit (e.g., 512M, 1G)
        #[arg(long)]
        memory: Option<String>,

        /// CPU limit (number of cores)
        #[arg(long)]
        cpus: Option<f64>,

        /// Hostname to set in container (requires UTS namespace)
        #[arg(long)]
        hostname: Option<String>,

        /// CPU scheduling weight (1-10000)
        #[arg(long)]
        cpu_weight: Option<u64>,

        /// I/O device limit (repeatable, format: "major:minor riops=N wbps=N")
        #[arg(long = "io-limit")]
        io_limits: Vec<String>,

        /// Maximum number of PIDs (default: 512, 0 = unlimited)
        #[arg(long)]
        pids: Option<u64>,

        /// RLIMIT_MEMLOCK limit (e.g. "8M"). Required for io_uring ring buffers.
        /// Default: 64K.
        #[arg(long)]
        memlock: Option<String>,

        /// Enable swap (by default swap is disabled when --memory is set)
        #[arg(long)]
        swap: bool,

        /// Container runtime: gvisor or native
        #[arg(long, default_value = "gvisor")]
        runtime: RuntimeSelection,

        /// Run container in the background as a systemd transient service
        #[arg(short = 'd', long)]
        detach: bool,

        /// Internal: suppress printing the container ID before execution
        #[arg(long, hide = true)]
        quiet_id: bool,

        /// Internal: use a pre-generated container ID (set by --detach re-exec)
        #[arg(long, hide = true)]
        preset_id: Option<String>,

        /// Run in rootless mode with user namespace
        #[arg(long)]
        rootless: bool,

        /// User name or numeric UID to run the workload as after setup
        #[arg(long)]
        user: Option<String>,

        /// Group name or numeric GID to run the workload as after setup
        #[arg(long)]
        group: Option<String>,

        /// Supplementary group name or numeric GID (repeatable)
        #[arg(long = "additional-group")]
        additional_groups: Vec<String>,

        /// Path to OCI bundle directory (requires gVisor). Replaces --oci flag.
        #[arg(long)]
        bundle: Option<PathBuf>,

        /// Write container PID to this file after creation
        #[arg(long)]
        pid_file: Option<PathBuf>,

        /// Path to AF_UNIX socket for console pseudo-terminal master
        #[arg(long)]
        console_socket: Option<PathBuf>,

        /// Network mode: none, host, or bridge (default: none)
        #[arg(long, default_value = "none")]
        network: NetworkModeArg,

        /// Explicitly allow host network mode (dangerous: weakens isolation)
        #[arg(long)]
        allow_host_network: bool,

        /// Allow degraded security if seccomp/Landlock cannot be applied
        #[arg(long)]
        allow_degraded_security: bool,

        /// Allow chroot fallback if pivot_root fails (weaker than pivot_root)
        #[arg(long)]
        allow_chroot_fallback: bool,

        /// Workload trust level: trusted (native isolation) or untrusted (requires gVisor)
        #[arg(long, default_value = "untrusted")]
        trust_level: TrustLevel,

        /// Mount /proc writable (default is read-only for hardening)
        #[arg(long)]
        proc_rw: bool,

        /// Publish a port (format: HOST:CONTAINER, HOST:CONTAINER/PROTOCOL,
        /// or HOST_IP:HOST:CONTAINER[/PROTOCOL])
        #[arg(short = 'p', long = "publish")]
        publish: Vec<String>,

        /// Context population mode: copy or bind (default: copy)
        #[arg(long = "context-mode", default_value = "copy")]
        context_mode: ContextMode,

        /// Service mode: agent (default) or production (strict security invariants)
        #[arg(long, default_value = "agent")]
        service_mode: ServiceMode,

        /// Pre-built rootfs path (Nix store closure). Replaces host bind mounts.
        #[arg(long)]
        rootfs: Option<String>,

        /// Allowed egress CIDRs (repeatable). Enables egress policy when set.
        #[arg(long = "egress-allow")]
        egress_allow: Vec<String>,

        /// Allowed egress TCP ports (repeatable, used with --egress-allow)
        #[arg(long = "egress-tcp-port")]
        egress_tcp_ports: Vec<u16>,

        /// Allowed egress UDP ports (repeatable, used with --egress-allow)
        #[arg(long = "egress-udp-port")]
        egress_udp_ports: Vec<u16>,

        /// DNS servers (repeatable). Required for bridge mode in production.
        #[arg(long)]
        dns: Vec<String>,

        /// Health check command (run inside container)
        #[arg(long = "health-cmd")]
        health_cmd: Option<String>,

        /// Health check interval in seconds (default: 30)
        #[arg(long = "health-interval")]
        health_interval: Option<u64>,

        /// Health check retries before unhealthy (default: 3)
        #[arg(long = "health-retries")]
        health_retries: Option<u32>,

        /// Health check start period in seconds (default: 5)
        #[arg(long = "health-start-period")]
        health_start_period: Option<u64>,

        /// Mount a secret file: SOURCE:DEST (repeatable)
        #[arg(long = "secret")]
        secrets: Vec<String>,

        /// Mount a systemd credential by name: NAME:DEST (repeatable)
        #[arg(long = "systemd-credential")]
        systemd_credentials: Vec<String>,

        /// Mount a host path as a bind volume: SOURCE:DEST[:ro|rw] (repeatable)
        #[arg(long = "volume")]
        volumes: Vec<String>,

        /// Mount a tmpfs volume: DEST[:SIZE][:ro|rw] (repeatable)
        #[arg(long = "tmpfs")]
        tmpfs: Vec<String>,

        /// Set environment variable: KEY=VALUE (repeatable)
        #[arg(short = 'e', long = "env")]
        env_vars: Vec<String>,

        /// Enable sd_notify integration (pass NOTIFY_SOCKET into container)
        #[arg(long)]
        sd_notify: bool,

        /// Readiness probe: exec command (ready when it exits 0)
        #[arg(long = "readiness-exec")]
        readiness_exec: Option<String>,

        /// Readiness probe: TCP port (ready when port accepts connections)
        #[arg(long = "readiness-tcp")]
        readiness_tcp: Option<u16>,

        /// Readiness probe: sd_notify (container sends READY=1 itself)
        #[arg(long = "readiness-sd-notify")]
        readiness_sd_notify: bool,

        /// Path to per-service seccomp profile (JSON, OCI subset format)
        #[arg(long = "seccomp-profile")]
        seccomp_profile: Option<String>,

        /// Expected SHA-256 hash of the seccomp profile for integrity verification
        #[arg(long = "seccomp-profile-sha256")]
        seccomp_profile_sha256: Option<String>,

        /// Seccomp mode: enforce (default) or trace (record syscalls for profile generation)
        #[arg(long = "seccomp-mode", default_value = "enforce")]
        seccomp_mode: SeccompMode,

        /// Path to write seccomp trace log (NDJSON) when --seccomp-mode=trace
        #[arg(long = "seccomp-log")]
        seccomp_log: Option<String>,

        /// Request kernel logging for denied seccomp decisions when supported
        #[arg(long = "seccomp-log-denied")]
        seccomp_log_denied: bool,

        /// Additional syscalls to allow beyond the built-in default allowlist.
        /// Can be specified multiple times (e.g. --seccomp-allow io_uring_setup --seccomp-allow sysinfo).
        /// These are merged into the built-in filter; they do NOT replace it.
        #[arg(long = "seccomp-allow")]
        seccomp_allow: Vec<String>,

        /// Path to capability policy file (TOML)
        #[arg(long = "caps-policy")]
        caps_policy: Option<String>,

        /// Expected SHA-256 hash of the capability policy file
        #[arg(long = "caps-policy-sha256")]
        caps_policy_sha256: Option<String>,

        /// Path to Landlock policy file (TOML)
        #[arg(long = "landlock-policy")]
        landlock_policy: Option<String>,

        /// Expected SHA-256 hash of the Landlock policy file
        #[arg(long = "landlock-policy-sha256")]
        landlock_policy_sha256: Option<String>,

        /// Verify context contents before the workload runs
        #[arg(long = "verify-context-integrity")]
        verify_context_integrity: bool,

        /// Verify rootfs attestation manifest before mounting it
        #[arg(long = "verify-rootfs-attestation")]
        verify_rootfs_attestation: bool,

        /// Require host kernel lockdown mode: integrity or confidentiality
        #[arg(long = "require-kernel-lockdown")]
        require_kernel_lockdown: Option<KernelLockdownMode>,

        /// gVisor platform backend: systrap, kvm, or ptrace
        #[arg(long = "gvisor-platform", default_value = "systrap")]
        gvisor_platform: GVisorPlatform,

        /// Enable time namespace isolation
        #[arg(long = "time-namespace")]
        time_namespace: bool,

        /// Disable cgroup namespace isolation
        #[arg(long = "disable-cgroup-namespace")]
        disable_cgroup_namespace: bool,

        /// Path to OCI hooks JSON file (defines lifecycle hooks)
        #[arg(long = "hooks")]
        hooks: Option<String>,

        /// Internal: topology config hash for reconciliation diffing
        #[arg(long = "topology-config-hash", hide = true)]
        topology_config_hash: Option<u64>,

        /// Command to run in container
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Query container state
    State {
        /// Container ID, name, or ID prefix (outputs OCI state JSON)
        container: Option<String>,

        /// Show all containers (including stopped)
        #[arg(short, long)]
        all: bool,
    },

    /// Show resource usage statistics for containers
    Stats {
        /// Container ID (if not specified, shows all containers)
        container_id: Option<String>,
    },

    /// Stop a running container
    Stop {
        /// Container ID, name, or ID prefix
        container: String,

        /// Seconds to wait before killing (default: 10)
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },

    /// Start (resume) a stopped container
    Start {
        /// Container ID, name, or ID prefix
        container: String,
    },

    /// Delete a container
    Delete {
        /// Container ID, name, or ID prefix
        container: String,

        /// Force delete (stop if running)
        #[arg(short, long)]
        force: bool,
    },

    /// Send a signal to a container
    Kill {
        /// Container ID, name, or ID prefix
        container: String,

        /// Signal to send (default: SIGKILL)
        #[arg(default_value = "KILL")]
        signal: String,
    },

    /// Attach to a running container
    Attach {
        /// Container ID, name, or ID prefix
        container: String,

        /// Command to run (default: /bin/sh)
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Checkpoint a running container
    Checkpoint {
        /// Container ID, name, or ID prefix
        container: String,

        /// Output directory for checkpoint data
        #[arg(short, long)]
        output: String,

        /// Leave container running after checkpoint
        #[arg(long)]
        leave_running: bool,
    },

    /// Restore a container from checkpoint
    Restore {
        /// Input directory containing checkpoint data
        #[arg(short, long)]
        input: String,
    },

    /// View logs for a detached container (from systemd journal)
    Logs {
        /// Container ID, name, or ID prefix
        container: String,

        /// Follow log output (like tail -f)
        #[arg(short, long)]
        follow: bool,

        /// Number of recent lines to show (default: all)
        #[arg(short = 'n', long)]
        lines: Option<u64>,
    },

    /// Manage multi-container topologies (Compose equivalent)
    #[command(subcommand)]
    Compose(ComposeCommands),

    /// Seccomp profile tools
    #[command(subcommand)]
    Seccomp(SeccompCommands),
}

#[derive(Parser, Debug)]
enum SeccompCommands {
    /// Generate a minimal seccomp profile from a trace log
    Generate {
        /// Path to NDJSON trace file from --seccomp-mode=trace
        trace_file: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Parser, Debug)]
enum ComposeCommands {
    /// Bring up a topology in dependency order
    Up {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,

        /// Stop timeout in seconds (default: 10)
        #[arg(long, default_value = "10")]
        timeout: u64,
    },

    /// Graceful teardown in reverse dependency order
    Down {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,

        /// Stop timeout in seconds (default: 10)
        #[arg(long, default_value = "10")]
        timeout: u64,
    },

    /// Show topology state
    State {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,
    },

    /// Show reconciliation plan without executing
    Plan {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,
    },

    /// Validate a topology file
    Validate {
        /// Path to topology TOML file
        #[arg(short, long)]
        file: String,
    },
}

/// Truncate a container ID to 12 chars for display.
fn truncate_id(id: &str) -> &str {
    if id.len() > 12 {
        &id[..12]
    } else {
        id
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let state_root = cli.root.clone();

    nucleus::telemetry::init_tracing();

    match cli.command {
        Commands::State { container, all } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;

            // If a specific container is given, output OCI state JSON
            if let Some(ref id) = container {
                let state = state_mgr.resolve_container(id)?;
                println!("{}", serde_json::to_string_pretty(&state.oci_state())?);
                return Ok(());
            }

            let states = if all {
                state_mgr.list_states()?
            } else {
                state_mgr.list_running()?
            };

            if states.is_empty() {
                println!("No containers found");
                return Ok(());
            }

            println!(
                "{:<15} {:<20} {:<10} {:<10} {:<10} {:<10} COMMAND",
                "CONTAINER ID", "NAME", "PID", "STATUS", "RUNTIME", "ROOTLESS"
            );

            for state in states {
                let status = if state.is_running() {
                    state.status.to_string()
                } else {
                    OciStatus::Stopped.to_string()
                };
                let runtime = if state.using_gvisor {
                    "gvisor"
                } else {
                    "native"
                };
                let rootless = if state.rootless { "yes" } else { "no" };
                let command = state.command.join(" ");
                let command_display = if command.len() > 40 {
                    format!("{}...", &command[..37])
                } else {
                    command
                };

                let id_display = truncate_id(&state.id);

                let name_display = if state.name.len() > 18 {
                    format!("{}...", &state.name[..15])
                } else {
                    state.name.clone()
                };

                println!(
                    "{:<15} {:<20} {:<10} {:<10} {:<10} {:<10} {}",
                    id_display, name_display, state.pid, status, runtime, rootless, command_display
                );
            }

            Ok(())
        }

        Commands::Stats { container_id } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;

            let states = if let Some(ref id) = container_id {
                vec![state_mgr.resolve_container(id)?]
            } else {
                state_mgr.list_running()?
            };

            if states.is_empty() {
                println!("No running containers found");
                return Ok(());
            }

            println!(
                "{:<15} {:<10} {:<15} {:<15} {:<10} {:<10} {:<10}",
                "CONTAINER ID", "CPU TIME", "MEM USAGE", "MEM LIMIT", "MEM %", "SWAP", "PIDS"
            );

            for state in states {
                if !state.is_running() {
                    continue;
                }

                if let Some(cgroup_path) = &state.cgroup_path {
                    match ResourceStats::from_cgroup(cgroup_path) {
                        Ok(stats) => {
                            let mem_usage = ResourceStats::format_memory(stats.memory_usage);
                            let mem_limit = if stats.memory_limit > 0 {
                                ResourceStats::format_memory(stats.memory_limit)
                            } else {
                                "unlimited".to_string()
                            };
                            let cpu_time = ResourceStats::format_cpu_time(stats.cpu_usage_ns);
                            let swap_usage = ResourceStats::format_memory(stats.memory_swap_usage);

                            let id_display = if state.id.len() > 12 {
                                &state.id[..12]
                            } else {
                                &state.id
                            };

                            println!(
                                "{:<15} {:<10} {:<15} {:<15} {:<10.2} {:<10} {:<10}",
                                id_display,
                                cpu_time,
                                mem_usage,
                                mem_limit,
                                stats.memory_percent,
                                swap_usage,
                                stats.pid_count
                            );
                        }
                        Err(e) => {
                            eprintln!("Failed to read stats for {}: {}", state.id, e);
                        }
                    }
                } else {
                    eprintln!("No cgroup path for container {}", state.id);
                }
            }

            Ok(())
        }

        Commands::Stop { container, timeout } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            ContainerLifecycle::stop(&state, timeout)?;
            println!("{}", state.id);
            Ok(())
        }

        Commands::Start { container } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            if state.status != OciStatus::Created {
                return Err(NucleusError::InvalidStateTransition {
                    from: state.status.to_string(),
                    to: "created".to_string(),
                });
            }
            Container::trigger_start(&state.id, state_root.clone())?;
            println!("{}", state.id);
            Ok(())
        }

        Commands::Delete { container, force } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            ContainerLifecycle::remove(&state_mgr, &state, force)?;
            println!("{}", state.id);
            Ok(())
        }

        Commands::Kill { container, signal } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            let sig = parse_signal(&signal)?;
            ContainerLifecycle::kill_container(&state, sig)?;
            println!("{}", state.id);
            Ok(())
        }

        Commands::Attach { container, command } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            let cmd = if command.is_empty() {
                vec!["/bin/sh".to_string()]
            } else {
                command
            };
            let exit_code = ContainerAttach::attach(&state, cmd)?;
            std::process::exit(exit_code);
        }

        Commands::Logs {
            container,
            follow,
            lines,
        } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;
            let unit_name = format!("nucleus-{}", &state.id[..12.min(state.id.len())]);

            let mut cmd = std::process::Command::new("journalctl");
            cmd.arg("--unit").arg(&unit_name).arg("--no-pager");
            if follow {
                cmd.arg("--follow");
            }
            if let Some(n) = lines {
                cmd.arg("-n").arg(n.to_string());
            }
            let status = cmd.status().map_err(|e| {
                NucleusError::ExecError(format!(
                    "Failed to run journalctl: {}. Is systemd available?",
                    e
                ))
            })?;
            if !status.success() {
                return Err(NucleusError::ExecError(format!(
                    "journalctl exited with status {}",
                    status
                )));
            }
            Ok(())
        }

        Commands::Checkpoint {
            container,
            output,
            leave_running,
        } => {
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = state_mgr.resolve_container(&container)?;

            if state.using_gvisor {
                return Err(NucleusError::CheckpointError(format!(
                    "Container {} uses gVisor runtime; CRIU checkpoint is not supported \
                     (gVisor manages its own sandbox state)",
                    state.id
                )));
            }

            let mut criu = CriuRuntime::new()?;
            criu.checkpoint(&state, &PathBuf::from(&output), leave_running)?;
            println!("Checkpoint saved to {}", output);
            Ok(())
        }

        Commands::Restore { input } => {
            let mut criu = CriuRuntime::new()?;
            let input_path = PathBuf::from(&input);
            let pid = criu.restore(&input_path)?;

            // Register restored container in state manager so state/stop/kill/attach work.
            // Generate a NEW container ID to avoid overwriting the original state file
            // (the original container may still be running with --leave-running).
            let metadata = nucleus::checkpoint::CheckpointMetadata::load(&input_path)?;
            let new_id = nucleus::container::generate_container_id()?;
            let new_name = format!("{}-restored", metadata.container_name);
            let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
            let state = ContainerState::new(ContainerStateParams {
                id: new_id.clone(),
                name: new_name,
                pid,
                command: metadata.command,
                memory_limit: None, // memory limit unknown after restore
                cpu_limit: None,    // cpu limit unknown after restore
                using_gvisor: metadata.using_gvisor,
                rootless: metadata.rootless,
                cgroup_path: None, // cgroup path unknown after restore
                process_uid: 0,
                process_gid: 0,
                additional_gids: Vec::new(),
            });
            state_mgr.save_state(&state)?;
            info!(
                "Registered restored container {} (was {}, PID {})",
                new_id, metadata.container_id, pid
            );

            println!("{}", new_id);
            Ok(())
        }

        Commands::Create {
            name,
            context,
            memory,
            cpus,
            cpu_weight,
            io_limits,
            pids,
            memlock,
            swap,
            hostname,
            runtime,
            detach,
            quiet_id,
            preset_id,
            rootless,
            user,
            group,
            additional_groups,
            bundle,
            pid_file,
            console_socket,
            network,
            allow_host_network,
            allow_degraded_security,
            allow_chroot_fallback,
            trust_level,
            proc_rw,
            publish,
            context_mode,
            service_mode,
            rootfs,
            egress_allow,
            egress_tcp_ports,
            egress_udp_ports,
            dns,
            health_cmd,
            health_interval,
            health_retries,
            health_start_period,
            secrets,
            systemd_credentials,
            volumes,
            tmpfs,
            env_vars,
            sd_notify,
            readiness_exec,
            readiness_tcp,
            readiness_sd_notify,
            seccomp_profile,
            seccomp_profile_sha256,
            seccomp_mode,
            seccomp_log,
            seccomp_log_denied,
            seccomp_allow,
            caps_policy,
            caps_policy_sha256,
            landlock_policy,
            landlock_policy_sha256,
            verify_context_integrity,
            verify_rootfs_attestation,
            require_kernel_lockdown,
            gvisor_platform,
            time_namespace,
            disable_cgroup_namespace,
            hooks,
            topology_config_hash,
            command,
        } => {
            if command.is_empty() {
                return Err(NucleusError::ConfigError(
                    "No command specified".to_string(),
                ));
            }

            // --detach: re-exec under systemd-run as a transient service
            if detach {
                let id = nucleus::container::generate_container_id()?;
                let exe = std::env::current_exe().map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to resolve current executable for detach re-exec: {}",
                        e
                    ))
                })?;

                // Reconstruct args: remove --detach/-d, inject --quiet-id and --preset-id
                let raw_args: Vec<String> = std::env::args().collect();
                let mut inner_args: Vec<String> = Vec::with_capacity(raw_args.len() + 2);
                // Find the "--" separator position (everything after is the container command)
                let separator_pos = raw_args.iter().position(|a| a == "--");

                for (i, arg) in raw_args.iter().enumerate().skip(1) {
                    // Only strip --detach/-d from nucleus args, not from the container command
                    if separator_pos.map_or(true, |sep| i < sep)
                        && (arg == "--detach" || arg == "-d")
                    {
                        continue;
                    }
                    inner_args.push(arg.clone());
                }

                // Insert --quiet-id and --preset-id right after "create"
                if let Some(create_pos) = inner_args
                    .iter()
                    .position(|a| a.eq_ignore_ascii_case("create"))
                {
                    inner_args.insert(create_pos + 1, format!("--preset-id={}", id));
                    inner_args.insert(create_pos + 1, "--quiet-id".to_string());
                }

                // Propagate --root if set (it's a global arg before the subcommand)
                if let Some(ref root) = state_root {
                    if !raw_args.iter().any(|a| a.starts_with("--root")) {
                        inner_args.insert(0, root.display().to_string());
                        inner_args.insert(0, "--root".to_string());
                    }
                }

                let unit_name = format!("nucleus-{}", &id[..12]);
                let status = std::process::Command::new("systemd-run")
                    .arg("--unit")
                    .arg(&unit_name)
                    .arg("--collect")
                    .arg("--quiet")
                    .arg("-p")
                    .arg("KillMode=mixed")
                    .arg("-p")
                    .arg("KillSignal=SIGTERM")
                    .arg("-p")
                    .arg("TimeoutStopSec=30")
                    .arg("--")
                    .arg(&exe)
                    .args(&inner_args)
                    .status()
                    .map_err(|e| {
                        NucleusError::ExecError(format!(
                            "Failed to launch systemd-run for detach: {}. \
                             Is systemd available?",
                            e
                        ))
                    })?;

                if !status.success() {
                    return Err(NucleusError::ExecError(format!(
                        "systemd-run exited with status {}",
                        status
                    )));
                }

                println!("{}", id);
                return Ok(());
            }

            if let Some(ref n) = name {
                validate_container_name(n)?;
            }

            // Build resource limits (default includes pids_max=512)
            let mut limits = ResourceLimits::default();

            if let Some(mem_str) = memory {
                limits = limits.with_memory(&mem_str)?;
                info!("Memory limit: {}", mem_str);
            }

            if let Some(cores) = cpus {
                limits = limits.with_cpu_cores(cores)?;
                info!("CPU limit: {} cores", cores);
            }

            if let Some(weight) = cpu_weight {
                limits = limits.with_cpu_weight(weight)?;
                info!("CPU weight: {}", weight);
            }

            if let Some(max_pids) = pids {
                if max_pids == 0 {
                    limits.pids_max = None;
                    info!("PID limit: unlimited");
                } else {
                    limits = limits.with_pids(max_pids)?;
                    info!("PID limit: {}", max_pids);
                }
            }

            if let Some(ref memlock_str) = memlock {
                limits = limits.with_memlock(memlock_str)?;
            }

            for io_spec in &io_limits {
                let io_limit = IoDeviceLimit::parse(io_spec)?;
                limits = limits.with_io_limit(io_limit);
                info!("I/O limit: {}", io_spec);
            }

            if swap {
                limits = limits.with_swap_enabled();
                info!("Swap enabled");
            }

            let net_mode = match network {
                NetworkModeArg::None => NetworkMode::None,
                NetworkModeArg::Host => NetworkMode::Host,
                NetworkModeArg::Bridge => {
                    // Production mode requires explicit DNS to avoid silent empty resolv.conf
                    if service_mode == ServiceMode::Production && dns.is_empty() {
                        return Err(NucleusError::ConfigError(
                            "Production mode with bridge networking requires explicit --dns servers".to_string()
                        ));
                    }
                    let mut bridge_config = if dns.is_empty() {
                        BridgeConfig::default().with_public_dns()
                    } else {
                        BridgeConfig::default().with_dns(dns.clone())
                    };
                    // Parse port forwards
                    for spec in &publish {
                        let pf = PortForward::parse(spec)?;
                        bridge_config.port_forwards.push(pf);
                    }
                    NetworkMode::Bridge(bridge_config)
                }
            };

            let mut namespaces = NamespaceConfig::all();
            if time_namespace {
                namespaces = namespaces.with_time_namespace(true);
            }
            if disable_cgroup_namespace {
                namespaces = namespaces.with_cgroup_namespace(false);
            }

            // Build configuration
            let mut config = ContainerConfig::try_new_with_id(preset_id, name, command)?
                .with_limits(limits)
                .with_namespaces(namespaces)
                .with_network(net_mode)
                .with_context_mode(context_mode)
                .with_allow_host_network(allow_host_network)
                .with_allow_degraded_security(allow_degraded_security)
                .with_allow_chroot_fallback(allow_chroot_fallback)
                .with_trust_level(trust_level)
                .with_proc_readonly(!proc_rw)
                .with_service_mode(service_mode)
                .with_sd_notify(sd_notify)
                .with_seccomp_log_denied(seccomp_log_denied)
                .with_verify_context_integrity(verify_context_integrity)
                .with_verify_rootfs_attestation(verify_rootfs_attestation)
                .with_gvisor_platform(gvisor_platform);

            if let Some(mode) = require_kernel_lockdown {
                config = config.with_required_kernel_lockdown(mode);
            }

            if let Some(hash) = topology_config_hash {
                config = config.with_config_hash(hash);
            }

            if let Some(ctx) = context {
                let canonical_ctx = std::fs::canonicalize(&ctx).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize context path '{}': {}",
                        ctx, e
                    ))
                })?;
                config = config.with_context(canonical_ctx);
            }

            if let Some(host) = hostname {
                validate_hostname(&host)?;
                config = config.with_hostname(Some(host));
            }

            config = config.apply_runtime_selection(runtime, bundle.is_some())?;

            // OCI bundle directory override
            if let Some(ref bundle_dir) = bundle {
                config = config.with_bundle_dir(bundle_dir.clone());
            }

            // Console socket — canonicalize parent to prevent symlink traversal
            if let Some(ref socket_path) = console_socket {
                let socket = PathBuf::from(socket_path);
                let canonical = if let Some(parent) = socket.parent() {
                    let canon_parent = std::fs::canonicalize(parent).map_err(|e| {
                        NucleusError::ConfigError(format!(
                            "Failed to canonicalize console socket parent '{}': {}",
                            parent.display(),
                            e
                        ))
                    })?;
                    canon_parent.join(socket.file_name().unwrap_or_default())
                } else {
                    socket
                };
                config = config.with_console_socket(canonical);
            }

            if rootless {
                info!("Enabling rootless mode");
                config = config.with_rootless();
            }

            if let Some(identity) =
                resolve_process_identity(user.as_deref(), group.as_deref(), &additional_groups)?
            {
                info!(
                    "Running workload as uid={} gid={} supplementary_gids={:?}",
                    identity.uid, identity.gid, identity.additional_gids
                );
                config = config.with_process_identity(identity);
            }

            // Rootfs path
            if let Some(rootfs_dir) = rootfs {
                config = config.with_rootfs_path(PathBuf::from(rootfs_dir));
            }

            // Seccomp profile and mode
            if let Some(profile_path) = seccomp_profile {
                let canonical = std::fs::canonicalize(&profile_path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize seccomp profile path '{}': {}",
                        profile_path, e
                    ))
                })?;
                config = config.with_seccomp_profile(canonical);
            }
            if let Some(sha256) = seccomp_profile_sha256 {
                config = config.with_seccomp_profile_sha256(sha256);
            }
            match seccomp_mode {
                SeccompMode::Enforce => {}
                SeccompMode::Trace => {
                    config = config.with_seccomp_mode(SeccompMode::Trace);
                    if let Some(log_path) = seccomp_log {
                        config = config.with_seccomp_trace_log(PathBuf::from(log_path));
                    } else {
                        return Err(NucleusError::ConfigError(
                            "--seccomp-log is required when --seccomp-mode=trace".to_string(),
                        ));
                    }
                }
            }

            if !seccomp_allow.is_empty() {
                config = config.with_seccomp_allow_syscalls(seccomp_allow);
            }

            // Capability policy
            if let Some(path) = caps_policy {
                let canonical = std::fs::canonicalize(&path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize capability policy path '{}': {}",
                        path, e
                    ))
                })?;
                config = config.with_caps_policy(canonical);
            }
            if let Some(sha256) = caps_policy_sha256 {
                config = config.with_caps_policy_sha256(sha256);
            }

            // Landlock policy
            if let Some(path) = landlock_policy {
                let canonical = std::fs::canonicalize(&path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize Landlock policy path '{}': {}",
                        path, e
                    ))
                })?;
                config = config.with_landlock_policy(canonical);
            }
            if let Some(sha256) = landlock_policy_sha256 {
                config = config.with_landlock_policy_sha256(sha256);
            }

            // Egress policy: in production mode, always set a policy (deny-all if no
            // --egress-allow given); in agent mode, only set when explicitly configured.
            if !egress_allow.is_empty() {
                let policy = EgressPolicy::default()
                    .with_allowed_cidrs(egress_allow)
                    .with_allowed_tcp_ports(egress_tcp_ports)
                    .with_allowed_udp_ports(egress_udp_ports);
                config = config.with_egress_policy(policy);
            } else if service_mode == ServiceMode::Production {
                // Default deny-all egress for production services
                config = config.with_egress_policy(EgressPolicy::deny_all());
            }

            // Readiness probe (mutually exclusive options)
            {
                let probe_count = readiness_exec.is_some() as u8
                    + readiness_tcp.is_some() as u8
                    + readiness_sd_notify as u8;
                if probe_count > 1 {
                    return Err(NucleusError::ConfigError(
                        "Only one readiness probe type may be set \
                         (--readiness-exec, --readiness-tcp, --readiness-sd-notify)"
                            .to_string(),
                    ));
                }
                if let Some(cmd) = readiness_exec {
                    config = config.with_readiness_probe(ReadinessProbe::Exec {
                        command: vec!["/bin/sh".to_string(), "-c".to_string(), cmd],
                    });
                } else if let Some(port) = readiness_tcp {
                    config = config.with_readiness_probe(ReadinessProbe::TcpPort(port));
                } else if readiness_sd_notify {
                    config = config.with_readiness_probe(ReadinessProbe::SdNotify);
                }
            }

            // Health check
            if let Some(cmd) = health_cmd {
                let hc = HealthCheck {
                    command: vec!["/bin/sh".to_string(), "-c".to_string(), cmd],
                    interval: std::time::Duration::from_secs(health_interval.unwrap_or(30)),
                    retries: health_retries.unwrap_or(3),
                    start_period: std::time::Duration::from_secs(health_start_period.unwrap_or(5)),
                    timeout: std::time::Duration::from_secs(5),
                };
                config = config.with_health_check(hc);
            }

            // Secrets
            for spec in &secrets {
                let parts: Vec<&str> = spec.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(NucleusError::ConfigError(format!(
                        "Invalid secret format '{}', expected SOURCE:DEST",
                        spec
                    )));
                }
                // Canonicalize source path to resolve symlinks and prevent
                // path traversal (e.g., "../../etc/shadow:...").
                let source = std::fs::canonicalize(parts[0]).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Secret source '{}' cannot be resolved: {}",
                        parts[0], e
                    ))
                })?;
                config = config.with_secret(SecretMount {
                    source,
                    dest: PathBuf::from(parts[1]),
                    mode: 0o400,
                });
            }

            // Systemd credentials
            for spec in &systemd_credentials {
                let parts: Vec<&str> = spec.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(NucleusError::ConfigError(format!(
                        "Invalid systemd credential format '{}', expected NAME:DEST",
                        spec
                    )));
                }
                let source = resolve_systemd_credential_source(parts[0])?;
                config = config.with_secret(SecretMount {
                    source,
                    dest: PathBuf::from(parts[1]),
                    mode: 0o400,
                });
            }

            // Bind volumes
            for spec in &volumes {
                let parts: Vec<&str> = spec.split(':').collect();
                let (source_raw, dest_raw, read_only) = match parts.as_slice() {
                    [source, dest] => (*source, *dest, false),
                    [source, dest, mode] if *mode == "ro" => (*source, *dest, true),
                    [source, dest, mode] if *mode == "rw" => (*source, *dest, false),
                    _ => {
                        return Err(NucleusError::ConfigError(format!(
                            "Invalid volume format '{}', expected SOURCE:DEST[:ro|rw]",
                            spec
                        )));
                    }
                };
                let source = std::fs::canonicalize(source_raw).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Volume source '{}' cannot be resolved: {}",
                        source_raw, e
                    ))
                })?;
                config = config.with_volume(VolumeMount {
                    source: VolumeSource::Bind { source },
                    dest: PathBuf::from(dest_raw),
                    read_only,
                });
            }

            // Tmpfs volumes — format: DEST[:SIZE][:ro|rw]
            // SIZE must match a numeric-with-suffix pattern (e.g. "64M", "1G", "512k").
            for spec in &tmpfs {
                let parts: Vec<&str> = spec.split(':').collect();
                let is_mode = |s: &str| s == "ro" || s == "rw";
                let is_size = |s: &str| {
                    s.trim_end_matches(|c: char| c.is_ascii_alphabetic())
                        .parse::<u64>()
                        .is_ok()
                };
                let (dest, size, read_only) = match parts.as_slice() {
                    [dest] => (*dest, None, false),
                    [dest, flag] if is_mode(flag) => (*dest, None, *flag == "ro"),
                    [dest, sz] if is_size(sz) => (*dest, Some((*sz).to_string()), false),
                    [dest, sz, flag] if is_size(sz) && is_mode(flag) => {
                        (*dest, Some((*sz).to_string()), *flag == "ro")
                    }
                    [_dest, bad] => {
                        return Err(NucleusError::ConfigError(format!(
                            "Invalid tmpfs second field '{}' in '{}': \
                             expected a size (e.g. 64M) or mode (ro|rw)",
                            bad, spec
                        )));
                    }
                    _ => {
                        return Err(NucleusError::ConfigError(format!(
                            "Invalid tmpfs format '{}', expected DEST[:SIZE][:ro|rw]",
                            spec
                        )));
                    }
                };
                if dest.is_empty() {
                    return Err(NucleusError::ConfigError(format!(
                        "Invalid tmpfs format '{}', expected DEST[:SIZE][:ro|rw]",
                        spec
                    )));
                }
                config = config.with_volume(VolumeMount {
                    source: VolumeSource::Tmpfs { size },
                    dest: PathBuf::from(dest),
                    read_only,
                });
            }

            // Environment variables
            const DANGEROUS_ENV_VARS: &[&str] = &[
                "LD_PRELOAD",
                "LD_LIBRARY_PATH",
                "LD_AUDIT",
                "LD_DEBUG",
                "LD_PROFILE",
            ];
            for spec in &env_vars {
                if let Some((key, value)) = spec.split_once('=') {
                    if DANGEROUS_ENV_VARS.contains(&key) {
                        return Err(NucleusError::ConfigError(format!(
                            "Environment variable '{}' is blocked (dynamic linker injection risk). \
                             This restriction applies in all modes.",
                            key
                        )));
                    }
                    config = config.with_env(key.to_string(), value.to_string());
                } else {
                    return Err(NucleusError::ConfigError(format!(
                        "Invalid env var format '{}', expected KEY=VALUE",
                        spec
                    )));
                }
            }

            // OCI lifecycle hooks
            if let Some(hooks_path) = hooks {
                let hooks_path = std::fs::canonicalize(&hooks_path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to canonicalize hooks path '{}': {}",
                        hooks_path, e
                    ))
                })?;
                let hooks_json = std::fs::read_to_string(&hooks_path).map_err(|e| {
                    NucleusError::ConfigError(format!(
                        "Failed to read hooks file '{}': {}",
                        hooks_path.display(),
                        e
                    ))
                })?;
                let oci_hooks: nucleus::security::OciHooks = serde_json::from_str(&hooks_json)
                    .map_err(|e| {
                        NucleusError::ConfigError(format!(
                            "Failed to parse hooks file '{}': {}",
                            hooks_path.display(),
                            e
                        ))
                    })?;
                config.hooks = Some(oci_hooks);
            }

            // PID file path — canonicalize parent to prevent symlink traversal
            if let Some(ref pid_path) = pid_file {
                let pid = PathBuf::from(pid_path);
                let canonical = if let Some(parent) = pid.parent() {
                    let canon_parent = std::fs::canonicalize(parent).map_err(|e| {
                        NucleusError::ConfigError(format!(
                            "Failed to canonicalize PID file parent '{}': {}",
                            parent.display(),
                            e
                        ))
                    })?;
                    canon_parent.join(pid.file_name().unwrap_or_default())
                } else {
                    pid
                };
                config = config.with_pid_file(canonical);
            }

            // Propagate --root to the container so it uses the correct state directory
            if let Some(ref root) = state_root {
                config = config.with_state_root(root.clone());
            }

            if !quiet_id {
                println!("{}", config.id);
            }

            let container = Container::new(config);
            let exit_code = container.run()?;

            std::process::exit(exit_code);
        }

        Commands::Compose(compose_cmd) => match compose_cmd {
            ComposeCommands::Validate { file } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                config.validate()?;
                let graph = DependencyGraph::resolve(&config)?;
                println!("Topology '{}' is valid", config.name);
                println!(
                    "Services ({}): {}",
                    config.services.len(),
                    config
                        .services
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!("Startup order: {}", graph.startup_order.join(" -> "));
                Ok(())
            }

            ComposeCommands::Plan { file } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                config.validate()?;
                let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
                let plan = plan_reconcile(&config, &state_mgr)?;

                println!("Reconciliation plan for topology '{}':", config.name);
                for (name, action) in &plan.actions {
                    let action_str = match action {
                        ReconcileAction::NoChange => "no change",
                        ReconcileAction::Start => "start",
                        ReconcileAction::Restart => "restart",
                        ReconcileAction::Stop => "stop",
                    };
                    println!("  {} -> {}", name, action_str);
                }
                Ok(())
            }

            ComposeCommands::Up { file, timeout } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                config.validate()?;
                let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
                let plan = plan_reconcile(&config, &state_mgr)?;

                println!("Bringing up topology '{}'...", config.name);
                execute_reconcile(&config, &plan, &state_mgr, timeout, state_root.as_deref())?;
                println!("Topology '{}' is up", config.name);
                Ok(())
            }

            ComposeCommands::Down { file, timeout } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                config.validate()?;
                let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;
                let graph = DependencyGraph::resolve(&config)?;

                println!("Tearing down topology '{}'...", config.name);
                for service_name in graph.shutdown_order() {
                    let container_name = format!("{}-{}", config.name, service_name);
                    if let Ok(state) = state_mgr.resolve_container(&container_name) {
                        if state.is_running() {
                            println!("Stopping {}...", container_name);
                            ContainerLifecycle::stop(&state, timeout)?;
                        }
                    }
                }
                println!("Topology '{}' is down", config.name);
                Ok(())
            }

            ComposeCommands::State { file } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                let state_mgr = ContainerStateManager::new_with_root(state_root.clone())?;

                println!(
                    "{:<25} {:<10} {:<10} {:<30}",
                    "SERVICE", "STATUS", "PID", "COMMAND"
                );

                for service_name in config.services.keys() {
                    let container_name = format!("{}-{}", config.name, service_name);
                    match state_mgr.resolve_container(&container_name) {
                        Ok(state) => {
                            let status = if state.is_running() {
                                state.status.to_string()
                            } else {
                                OciStatus::Stopped.to_string()
                            };
                            let cmd = state.command.join(" ");
                            let cmd_display = if cmd.len() > 28 {
                                format!("{}...", &cmd[..25])
                            } else {
                                cmd
                            };
                            println!(
                                "{:<25} {:<10} {:<10} {:<30}",
                                service_name, status, state.pid, cmd_display
                            );
                        }
                        Err(_) => {
                            println!(
                                "{:<25} {:<10} {:<10} {:<30}",
                                service_name, "Not found", "-", "-"
                            );
                        }
                    }
                }
                Ok(())
            }
        },

        Commands::Seccomp(seccomp_cmd) => match seccomp_cmd {
            SeccompCommands::Generate { trace_file, output } => {
                let profile = nucleus::security::generate_from_trace(&PathBuf::from(&trace_file))?;
                let json = serde_json::to_string_pretty(&profile)?;

                if let Some(out_path) = output {
                    std::fs::write(&out_path, &json)?;
                    eprintln!("Wrote seccomp profile to {}", out_path);
                } else {
                    println!("{}", json);
                }

                eprintln!(
                    "Profile contains {} syscalls",
                    profile.syscalls.first().map(|g| g.names.len()).unwrap_or(0)
                );
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_native_runtime_disables_gvisor() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        let config = config
            .apply_runtime_selection(RuntimeSelection::Native, false)
            .unwrap();
        assert!(
            !config.use_gvisor,
            "native runtime selection must disable gVisor"
        );
        assert_eq!(
            config.trust_level,
            TrustLevel::Trusted,
            "native runtime must set TrustLevel::Trusted"
        );
    }

    #[test]
    fn test_native_runtime_rejects_bundle_flag() {
        let config = ContainerConfig::try_new(None, vec!["/bin/sh".to_string()]).unwrap();
        let err = config
            .apply_runtime_selection(RuntimeSelection::Native, true)
            .unwrap_err();
        assert!(
            err.to_string().contains("requires gVisor"),
            "native runtime with --bundle must be rejected explicitly"
        );
    }

    #[test]
    fn test_resolve_systemd_credential_source() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let cred = dir.path().join("db-password");
        std::fs::write(&cred, "secret").unwrap();
        std::env::set_var("CREDENTIALS_DIRECTORY", dir.path());

        let resolved = resolve_systemd_credential_source("db-password").unwrap();
        assert_eq!(resolved, std::fs::canonicalize(&cred).unwrap());
        std::env::remove_var("CREDENTIALS_DIRECTORY");
    }

    #[test]
    fn test_resolve_systemd_credential_rejects_path_traversal() {
        let _guard = env_lock().lock().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        std::env::set_var("CREDENTIALS_DIRECTORY", dir.path());

        let err = resolve_systemd_credential_source("../db-password").unwrap_err();
        assert!(err.to_string().contains("Invalid systemd credential name"));
        std::env::remove_var("CREDENTIALS_DIRECTORY");
    }

    #[test]
    fn test_resolve_process_identity_named_user_defaults_primary_group() {
        let identity = resolve_process_identity(Some("root"), None, &[])
            .unwrap()
            .unwrap();
        assert_eq!(identity.uid, 0);
        assert_eq!(identity.gid, 0);
        assert!(identity.additional_gids.is_empty());
    }

    #[test]
    fn test_resolve_process_identity_numeric_user_requires_group() {
        let err = resolve_process_identity(Some("1000"), None, &[]).unwrap_err();
        assert!(err.to_string().contains("explicit --group"));
    }

    #[test]
    fn test_resolve_process_identity_deduplicates_additional_groups() {
        let identity = resolve_process_identity(
            Some("123"),
            Some("456"),
            &["456".to_string(), "789".to_string(), "789".to_string()],
        )
        .unwrap()
        .unwrap();
        assert_eq!(identity.uid, 123);
        assert_eq!(identity.gid, 456);
        assert_eq!(identity.additional_gids, vec![789]);
    }
}
