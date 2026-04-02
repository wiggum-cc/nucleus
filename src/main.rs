use anyhow::Result;
use clap::Parser;
use nucleus::checkpoint::CriuRuntime;
use nucleus::container::{
    parse_signal, Container, ContainerConfig, ContainerLifecycle, ContainerState,
    ContainerStateManager, HealthCheck, KernelLockdownMode, ReadinessProbe, SecretMount,
    ServiceMode, TrustLevel,
};
use nucleus::filesystem::ContextMode;
use nucleus::isolation::attach::ContainerAttach;
use nucleus::isolation::NamespaceConfig;
use nucleus::network::{BridgeConfig, EgressPolicy, NetworkMode, PortForward};
use nucleus::resources::{IoDeviceLimit, ResourceLimits, ResourceStats};
use nucleus::security::GVisorPlatform;
use nucleus::topology::{
    execute_reconcile, plan_reconcile, DependencyGraph, ReconcileAction, TopologyConfig,
};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

        /// Container runtime (default: gvisor, or native)
        #[arg(long, default_value = "gvisor")]
        runtime: String,

        /// Internal: suppress printing the container ID before execution
        #[arg(long, hide = true)]
        quiet_id: bool,

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
        seccomp_mode: String,

        /// Path to write seccomp trace log (NDJSON) when --seccomp-mode=trace
        #[arg(long = "seccomp-log")]
        seccomp_log: Option<String>,

        /// Request kernel logging for denied seccomp decisions when supported
        #[arg(long = "seccomp-log-denied")]
        seccomp_log_denied: bool,

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
        require_kernel_lockdown: Option<String>,

        /// gVisor platform backend: systrap, kvm, or ptrace
        #[arg(long = "gvisor-platform", default_value = "systrap")]
        gvisor_platform: String,

        /// Enable time namespace isolation
        #[arg(long = "time-namespace")]
        time_namespace: bool,

        /// Disable cgroup namespace isolation
        #[arg(long = "disable-cgroup-namespace")]
        disable_cgroup_namespace: bool,

        /// Internal: topology config hash for reconciliation diffing
        #[arg(long = "topology-config-hash", hide = true)]
        topology_config_hash: Option<u64>,

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

    /// Show topology status
    Ps {
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

fn main() -> Result<()> {
    init_tracing()?;

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

            if state.using_gvisor {
                return Err(anyhow::anyhow!(
                    "Container {} uses gVisor runtime; CRIU checkpoint is not supported \
                     (gVisor manages its own sandbox state)",
                    state.id
                ));
            }

            let criu = CriuRuntime::new()?;
            criu.checkpoint(&state, &PathBuf::from(&output), leave_running)?;
            println!("Checkpoint saved to {}", output);
            Ok(())
        }

        Commands::Restore { input } => {
            let criu = CriuRuntime::new()?;
            let input_path = PathBuf::from(&input);
            let pid = criu.restore(&input_path)?;

            // Register restored container in state manager so ps/stop/kill/attach work.
            // Generate a NEW container ID to avoid overwriting the original state file
            // (the original container may still be running with --leave-running).
            let metadata = nucleus::checkpoint::CheckpointMetadata::load(&input_path)?;
            let new_id = nucleus::container::generate_container_id();
            let new_name = format!("{}-restored", metadata.container_name);
            let state_mgr = ContainerStateManager::new()?;
            let state = ContainerState::new(
                new_id.clone(),
                new_name,
                pid,
                metadata.command,
                None, // memory limit unknown after restore
                None, // cpu limit unknown after restore
                metadata.using_gvisor,
                metadata.rootless,
                None, // cgroup path unknown after restore
            );
            state_mgr.save_state(&state)?;
            info!(
                "Registered restored container {} (was {}, PID {})",
                new_id, metadata.container_id, pid
            );

            println!("{}", new_id);
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
            quiet_id,
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
            readiness_exec,
            readiness_tcp,
            readiness_sd_notify,
            seccomp_profile,
            seccomp_profile_sha256,
            seccomp_mode,
            seccomp_log,
            seccomp_log_denied,
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
            topology_config_hash,
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
                    // Production mode requires explicit DNS to avoid silent empty resolv.conf
                    if service_mode == "production" && dns.is_empty() {
                        eprintln!(
                            "Error: Production mode with bridge networking requires explicit \
                             --dns servers"
                        );
                        std::process::exit(1);
                    }
                    let mut bridge_config = if dns.is_empty() {
                        BridgeConfig::default().with_public_dns()
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

            let required_lockdown = match require_kernel_lockdown.as_deref() {
                None => None,
                Some("integrity") => Some(KernelLockdownMode::Integrity),
                Some("confidentiality") => Some(KernelLockdownMode::Confidentiality),
                Some(other) => {
                    eprintln!(
                        "Unknown kernel lockdown mode: {}. Use integrity or confidentiality.",
                        other
                    );
                    std::process::exit(1);
                }
            };

            let gvisor_platform = match gvisor_platform.as_str() {
                "systrap" => GVisorPlatform::Systrap,
                "kvm" => GVisorPlatform::Kvm,
                "ptrace" => GVisorPlatform::Ptrace,
                other => {
                    eprintln!(
                        "Unknown gVisor platform: {}. Use systrap, kvm, or ptrace.",
                        other
                    );
                    std::process::exit(1);
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
            let mut config = ContainerConfig::new(name, command)
                .with_limits(limits)
                .with_namespaces(namespaces)
                .with_network(net_mode)
                .with_context_mode(ctx_mode)
                .with_allow_host_network(allow_host_network)
                .with_allow_degraded_security(allow_degraded_security)
                .with_allow_chroot_fallback(allow_chroot_fallback)
                .with_trust_level(trust)
                .with_proc_readonly(!proc_rw)
                .with_service_mode(svc_mode)
                .with_sd_notify(sd_notify)
                .with_seccomp_log_denied(seccomp_log_denied)
                .with_verify_context_integrity(verify_context_integrity)
                .with_verify_rootfs_attestation(verify_rootfs_attestation)
                .with_gvisor_platform(gvisor_platform);

            if let Some(mode) = required_lockdown {
                config = config.with_required_kernel_lockdown(mode);
            }

            if let Some(hash) = topology_config_hash {
                config = config.with_config_hash(hash);
            }

            if let Some(ctx) = context {
                config = config.with_context(PathBuf::from(ctx));
            }

            if let Some(host) = hostname {
                validate_hostname(&host)?;
                config = config.with_hostname(Some(host));
            }

            config = apply_runtime_selection(config, &runtime, oci)?;

            if rootless {
                info!("Enabling rootless mode");
                config = config.with_rootless();
            }

            // Rootfs path
            if let Some(rootfs_dir) = rootfs {
                config = config.with_rootfs_path(PathBuf::from(rootfs_dir));
            }

            // Seccomp profile and mode
            if let Some(profile_path) = seccomp_profile {
                config = config.with_seccomp_profile(PathBuf::from(profile_path));
            }
            if let Some(sha256) = seccomp_profile_sha256 {
                config = config.with_seccomp_profile_sha256(sha256);
            }
            match seccomp_mode.as_str() {
                "enforce" => {}
                "trace" => {
                    config = config.with_seccomp_mode(nucleus::container::SeccompMode::Trace);
                    if let Some(log_path) = seccomp_log {
                        config = config.with_seccomp_trace_log(PathBuf::from(log_path));
                    } else {
                        eprintln!("Error: --seccomp-log is required when --seccomp-mode=trace");
                        std::process::exit(1);
                    }
                }
                other => {
                    eprintln!(
                        "Error: Unknown seccomp mode '{}'; valid: enforce, trace",
                        other
                    );
                    std::process::exit(1);
                }
            }

            // Capability policy
            if let Some(path) = caps_policy {
                config = config.with_caps_policy(PathBuf::from(path));
            }
            if let Some(sha256) = caps_policy_sha256 {
                config = config.with_caps_policy_sha256(sha256);
            }

            // Landlock policy
            if let Some(path) = landlock_policy {
                config = config.with_landlock_policy(PathBuf::from(path));
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
            } else if service_mode == "production" {
                // Default deny-all egress for production services
                config = config.with_egress_policy(EgressPolicy::deny_all());
            }

            // Readiness probe (mutually exclusive options)
            {
                let probe_count = readiness_exec.is_some() as u8
                    + readiness_tcp.is_some() as u8
                    + readiness_sd_notify as u8;
                if probe_count > 1 {
                    eprintln!(
                        "Error: Only one readiness probe type may be set \
                         (--readiness-exec, --readiness-tcp, --readiness-sd-notify)"
                    );
                    std::process::exit(1);
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
                    eprintln!("Invalid secret format '{}', expected SOURCE:DEST", spec);
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
                    eprintln!("Invalid env var format '{}', expected KEY=VALUE", spec);
                    std::process::exit(1);
                }
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
                let state_mgr = ContainerStateManager::new()?;
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
                let state_mgr = ContainerStateManager::new()?;
                let plan = plan_reconcile(&config, &state_mgr)?;

                println!("Bringing up topology '{}'...", config.name);
                execute_reconcile(&config, &plan, &state_mgr, timeout)?;
                println!("Topology '{}' is up", config.name);
                Ok(())
            }

            ComposeCommands::Down { file, timeout } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                config.validate()?;
                let state_mgr = ContainerStateManager::new()?;
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

            ComposeCommands::Ps { file } => {
                let config = TopologyConfig::from_file(&PathBuf::from(&file))?;
                let state_mgr = ContainerStateManager::new()?;

                println!(
                    "{:<25} {:<10} {:<10} {:<30}",
                    "SERVICE", "STATUS", "PID", "COMMAND"
                );

                for service_name in config.services.keys() {
                    let container_name = format!("{}-{}", config.name, service_name);
                    match state_mgr.resolve_container(&container_name) {
                        Ok(state) => {
                            let status = if state.is_running() {
                                "Running"
                            } else {
                                "Stopped"
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
                let profile = nucleus::security::seccomp_generate::generate_from_trace(
                    &PathBuf::from(&trace_file),
                )?;
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

fn init_tracing() -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer();

    let otlp_endpoint = std::env::var("NUCLEUS_OTLP_ENDPOINT")
        .ok()
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
        .filter(|value| !value.trim().is_empty());

    if let Some(endpoint) = otlp_endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(endpoint.clone())
            .build()
            .map_err(|e| {
                anyhow::anyhow!("Failed to build OTLP exporter for {}: {}", endpoint, e)
            })?;

        let provider = SdkTracerProvider::builder()
            .with_resource(
                Resource::builder_empty()
                    .with_service_name("nucleus")
                    .build(),
            )
            .with_simple_exporter(exporter)
            .build();
        let tracer = provider.tracer("nucleus");

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
    }

    Ok(())
}

fn apply_runtime_selection(mut config: ContainerConfig, runtime: &str, oci: bool) -> Result<ContainerConfig> {
    match runtime {
        "native" => {
            if oci {
                anyhow::bail!("--oci requires gVisor runtime; use --runtime gvisor");
            }
            config = config.with_gvisor(false).with_trust_level(TrustLevel::Trusted);
        }
        "gvisor" => {
            config = config.with_gvisor(true);
            if !oci {
                info!("Security hardening: enabling OCI bundle mode for gVisor runtime");
            }
            config = config.with_oci_bundle();
        }
        other => {
            anyhow::bail!(
                "Unknown runtime '{}'; supported values are 'native' and 'gvisor'",
                other
            );
        }
    }

    Ok(config)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_runtime_disables_gvisor() {
        let config = ContainerConfig::new(None, vec!["/bin/sh".to_string()]);
        let config = apply_runtime_selection(config, "native", false).unwrap();
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
    fn test_native_runtime_rejects_oci_flag() {
        let config = ContainerConfig::new(None, vec!["/bin/sh".to_string()]);
        let err = apply_runtime_selection(config, "native", true).unwrap_err();
        assert!(
            err.to_string().contains("requires gVisor"),
            "native runtime with --oci must be rejected explicitly"
        );
    }
}
