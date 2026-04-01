use anyhow::Result;
use clap::Parser;
use nucleus::checkpoint::CriuRuntime;
use nucleus::container::{
    parse_signal, Container, ContainerConfig, ContainerLifecycle, ContainerStateManager,
    HealthCheck, SecretMount, ServiceMode, TrustLevel,
};
use nucleus::filesystem::ContextMode;
use nucleus::isolation::attach::ContainerAttach;
use nucleus::isolation::NamespaceConfig;
use nucleus::network::{BridgeConfig, EgressPolicy, NetworkMode, PortForward};
use nucleus::resources::{IoDeviceLimit, ResourceLimits, ResourceStats};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "nucleus")]
#[command(about = "Extremely lightweight Docker alternative for agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Run a command in an isolated container
    Run {
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

        /// Enable swap (by default swap is disabled when --memory is set)
        #[arg(long)]
        swap: bool,

        /// Container runtime (default: native, or gvisor)
        #[arg(long, default_value = "native")]
        runtime: String,

        /// Run in rootless mode with user namespace
        #[arg(long)]
        rootless: bool,

        /// Use OCI bundle format (requires gVisor)
        #[arg(long)]
        oci: bool,

        /// Network mode: none, host, or bridge (default: none)
        #[arg(long, default_value = "none")]
        network: String,

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
        trust_level: String,

        /// Mount /proc writable (default is read-only for hardening)
        #[arg(long)]
        proc_rw: bool,

        /// Publish a port (format: HOST:CONTAINER or HOST:CONTAINER/PROTOCOL)
        #[arg(short = 'p', long = "publish")]
        publish: Vec<String>,

        /// Context population mode: copy or bind (default: copy)
        #[arg(long = "context-mode", default_value = "copy")]
        context_mode: String,

        /// Service mode: agent (default) or production (strict security invariants)
        #[arg(long, default_value = "agent")]
        service_mode: String,

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

        /// Set environment variable: KEY=VALUE (repeatable)
        #[arg(short = 'e', long = "env")]
        env_vars: Vec<String>,

        /// Enable sd_notify integration (pass NOTIFY_SOCKET into container)
        #[arg(long)]
        sd_notify: bool,

        /// Command to run in container
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// List running containers
    Ps {
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

    /// Remove a stopped container
    Rm {
        /// Container ID, name, or ID prefix
        container: String,

        /// Force remove (stop if running)
        #[arg(short, long)]
        force: bool,
    },

    /// Send a signal to a container
    Kill {
        /// Container ID, name, or ID prefix
        container: String,

        /// Signal to send (default: SIGKILL)
        #[arg(short, long, default_value = "KILL")]
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
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Ps { all } => {
            let state_mgr = ContainerStateManager::new()?;

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
                    "Running"
                } else {
                    "Stopped"
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

                let id_display = if state.id.len() > 12 {
                    &state.id[..12]
                } else {
                    &state.id
                };

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
            let state_mgr = ContainerStateManager::new()?;

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
            let state_mgr = ContainerStateManager::new()?;
            let state = state_mgr.resolve_container(&container)?;
            ContainerLifecycle::stop(&state, timeout)?;
            println!("{}", state.id);
            Ok(())
        }

        Commands::Rm { container, force } => {
            let state_mgr = ContainerStateManager::new()?;
            let state = state_mgr.resolve_container(&container)?;
            ContainerLifecycle::remove(&state_mgr, &state, force)?;
            println!("{}", state.id);
            Ok(())
        }

        Commands::Kill { container, signal } => {
            let state_mgr = ContainerStateManager::new()?;
            let state = state_mgr.resolve_container(&container)?;
            let sig = parse_signal(&signal)?;
            ContainerLifecycle::kill_container(&state, sig)?;
            println!("{}", state.id);
            Ok(())
        }

        Commands::Attach { container, command } => {
            let state_mgr = ContainerStateManager::new()?;
            let state = state_mgr.resolve_container(&container)?;
            let cmd = if command.is_empty() {
                vec!["/bin/sh".to_string()]
            } else {
                command
            };
            let exit_code = ContainerAttach::attach(&state, cmd)?;
            std::process::exit(exit_code);
        }

        Commands::Checkpoint {
            container,
            output,
            leave_running,
        } => {
            let state_mgr = ContainerStateManager::new()?;
            let state = state_mgr.resolve_container(&container)?;
            let criu = CriuRuntime::new()?;
            criu.checkpoint(&state, &PathBuf::from(&output), leave_running)?;
            println!("Checkpoint saved to {}", output);
            Ok(())
        }

        Commands::Restore { input } => {
            let criu = CriuRuntime::new()?;
            let pid = criu.restore(&PathBuf::from(&input))?;
            println!("Restored container with PID {}", pid);
            Ok(())
        }

        Commands::Run {
            name,
            context,
            memory,
            cpus,
            cpu_weight,
            io_limits,
            pids,
            swap,
            hostname,
            runtime,
            rootless,
            oci,
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
            env_vars,
            sd_notify,
            command,
        } => {
            if command.is_empty() {
                eprintln!("Error: No command specified");
                std::process::exit(1);
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

            for io_spec in &io_limits {
                let io_limit = IoDeviceLimit::parse(io_spec)?;
                limits = limits.with_io_limit(io_limit);
                info!("I/O limit: {}", io_spec);
            }

            if swap {
                limits = limits.with_swap_enabled();
                info!("Swap enabled");
            }

            // Parse network mode
            let net_mode = match network.as_str() {
                "none" => NetworkMode::None,
                "host" => NetworkMode::Host,
                "bridge" => {
                    let mut bridge_config = if dns.is_empty() {
                        // Agent mode gets public DNS by default; production must configure explicitly
                        if service_mode == "production" {
                            BridgeConfig::default()
                        } else {
                            BridgeConfig::default().with_public_dns()
                        }
                    } else {
                        BridgeConfig::default().with_dns(dns.clone())
                    };
                    // Parse port forwards
                    for spec in &publish {
                        let pf = PortForward::parse(spec)
                            .map_err(|e| anyhow::anyhow!("Invalid port forward: {}", e))?;
                        bridge_config.port_forwards.push(pf);
                    }
                    NetworkMode::Bridge(bridge_config)
                }
                other => {
                    eprintln!(
                        "Unknown network mode: {}. Use none, host, or bridge.",
                        other
                    );
                    std::process::exit(1);
                }
            };

            // Parse context mode
            let ctx_mode = match context_mode.as_str() {
                "copy" => ContextMode::Copy,
                "bind" => ContextMode::BindMount,
                other => {
                    eprintln!("Unknown context mode: {}. Use copy or bind.", other);
                    std::process::exit(1);
                }
            };

            // Parse trust level
            let trust = match trust_level.as_str() {
                "trusted" => TrustLevel::Trusted,
                "untrusted" => TrustLevel::Untrusted,
                other => {
                    eprintln!("Unknown trust level: {}. Use trusted or untrusted.", other);
                    std::process::exit(1);
                }
            };

            // Parse service mode
            let svc_mode = match service_mode.as_str() {
                "agent" => ServiceMode::Agent,
                "production" => ServiceMode::Production,
                other => {
                    eprintln!("Unknown service mode: {}. Use agent or production.", other);
                    std::process::exit(1);
                }
            };

            // Build configuration
            let mut config = ContainerConfig::new(name, command)
                .with_limits(limits)
                .with_namespaces(NamespaceConfig::all())
                .with_network(net_mode)
                .with_context_mode(ctx_mode)
                .with_allow_host_network(allow_host_network)
                .with_allow_degraded_security(allow_degraded_security)
                .with_allow_chroot_fallback(allow_chroot_fallback)
                .with_trust_level(trust)
                .with_proc_readonly(!proc_rw)
                .with_service_mode(svc_mode)
                .with_sd_notify(sd_notify);

            if let Some(ctx) = context {
                config = config.with_context(PathBuf::from(ctx));
            }

            if let Some(host) = hostname {
                validate_hostname(&host)?;
                config = config.with_hostname(Some(host));
            }

            if runtime == "gvisor" {
                config = config.with_gvisor(true);
                if !oci {
                    info!("Security hardening: enabling OCI bundle mode for gVisor runtime");
                    config = config.with_oci_bundle();
                }
            }

            if rootless {
                info!("Enabling rootless mode");
                config = config.with_rootless();
            }

            if oci {
                info!("Enabling OCI bundle mode");
                config = config.with_oci_bundle();
            }

            // Rootfs path
            if let Some(rootfs_dir) = rootfs {
                config = config.with_rootfs_path(PathBuf::from(rootfs_dir));
            }

            // Egress policy
            if !egress_allow.is_empty() {
                let policy = EgressPolicy::default()
                    .with_allowed_cidrs(egress_allow)
                    .with_allowed_tcp_ports(egress_tcp_ports)
                    .with_allowed_udp_ports(egress_udp_ports);
                config = config.with_egress_policy(policy);
            }

            // Health check
            if let Some(cmd) = health_cmd {
                let hc = HealthCheck {
                    command: vec!["/bin/sh".to_string(), "-c".to_string(), cmd],
                    interval: std::time::Duration::from_secs(health_interval.unwrap_or(30)),
                    retries: health_retries.unwrap_or(3),
                    start_period: std::time::Duration::from_secs(
                        health_start_period.unwrap_or(5),
                    ),
                    timeout: std::time::Duration::from_secs(5),
                };
                config = config.with_health_check(hc);
            }

            // Secrets
            for spec in &secrets {
                let parts: Vec<&str> = spec.splitn(2, ':').collect();
                if parts.len() != 2 {
                    eprintln!(
                        "Invalid secret format '{}', expected SOURCE:DEST",
                        spec
                    );
                    std::process::exit(1);
                }
                config = config.with_secret(SecretMount {
                    source: PathBuf::from(parts[0]),
                    dest: PathBuf::from(parts[1]),
                    mode: 0o400,
                });
            }

            // Environment variables
            for spec in &env_vars {
                if let Some((key, value)) = spec.split_once('=') {
                    config = config.with_env(key.to_string(), value.to_string());
                } else {
                    eprintln!(
                        "Invalid env var format '{}', expected KEY=VALUE",
                        spec
                    );
                    std::process::exit(1);
                }
            }

            println!("{}", config.id);

            let container = Container::new(config);
            let exit_code = container.run()?;

            std::process::exit(exit_code);
        }
    }
}

fn validate_container_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 128 {
        anyhow::bail!("Invalid container name: must be 1-128 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        anyhow::bail!("Invalid container name: allowed characters are a-zA-Z0-9, '-', '_', '.'");
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty() || hostname.len() > 253 {
        anyhow::bail!("Invalid hostname: must be 1-253 characters");
    }

    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("Invalid hostname label: '{}'", label);
        }
        if label.starts_with('-') || label.ends_with('-') {
            anyhow::bail!(
                "Invalid hostname label '{}': cannot start or end with '-'",
                label
            );
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            anyhow::bail!(
                "Invalid hostname label '{}': allowed characters are a-zA-Z0-9 and '-'",
                label
            );
        }
    }

    Ok(())
}
