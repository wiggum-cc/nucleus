use anyhow::Result;
use clap::Parser;
use nucleus::container::{Container, ContainerConfig, ContainerStateManager};
use nucleus::isolation::NamespaceConfig;
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
enum Commands {
    /// Run a command in an isolated container
    Run {
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

            // Print header
            println!(
                "{:<15} {:<10} {:<10} {:<10} {:<10} COMMAND",
                "CONTAINER ID", "PID", "STATUS", "RUNTIME", "ROOTLESS"
            );

            // Print each container
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

                println!(
                    "{:<15} {:<10} {:<10} {:<10} {:<10} {}",
                    &state.id[..state.id.len().min(15)],
                    state.pid,
                    status,
                    runtime,
                    rootless,
                    command_display
                );
            }

            Ok(())
        }

        Commands::Stats { container_id } => {
            let state_mgr = ContainerStateManager::new()?;

            let states = if let Some(id) = container_id {
                vec![state_mgr.load_state(&id)?]
            } else {
                state_mgr.list_running()?
            };

            if states.is_empty() {
                println!("No running containers found");
                return Ok(());
            }

            // Print header
            println!(
                "{:<15} {:<10} {:<15} {:<15} {:<10} {:<10} {:<10}",
                "CONTAINER ID", "CPU TIME", "MEM USAGE", "MEM LIMIT", "MEM %", "SWAP", "PIDS"
            );

            // Print stats for each container
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

                            println!(
                                "{:<15} {:<10} {:<15} {:<15} {:<10.2} {:<10} {:<10}",
                                &state.id[..state.id.len().min(15)],
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

        Commands::Run {
            context,
            memory,
            cpus,
            cpu_weight,
            io_limits,
            swap,
            hostname,
            runtime,
            rootless,
            oci,
            command,
        } => {
            if command.is_empty() {
                eprintln!("Error: No command specified");
                std::process::exit(1);
            }

            // Generate container ID
            let container_id = format!("{}", std::process::id());

            // Build resource limits
            let mut limits = ResourceLimits::unlimited();

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

            for io_spec in &io_limits {
                let io_limit = IoDeviceLimit::parse(io_spec)?;
                limits = limits.with_io_limit(io_limit);
                info!("I/O limit: {}", io_spec);
            }

            if swap {
                limits = limits.with_swap_enabled();
                info!("Swap enabled");
            }

            // Build configuration
            let mut config = ContainerConfig::new(container_id.clone(), command)
                .with_limits(limits)
                .with_namespaces(NamespaceConfig::all());

            if let Some(ctx) = context {
                config = config.with_context(PathBuf::from(ctx));
            }

            // Set hostname (default is container_id)
            if let Some(host) = hostname {
                config = config.with_hostname(Some(host));
            }

            if runtime == "gvisor" {
                config = config.with_gvisor(true);
            }

            // Enable rootless mode if requested
            if rootless {
                info!("Enabling rootless mode");
                config = config.with_rootless();
            }

            // Enable OCI bundle mode if requested
            if oci {
                info!("Enabling OCI bundle mode");
                config = config.with_oci_bundle();
            }

            // Run container
            let container = Container::new(config);
            let exit_code = container.run()?;

            std::process::exit(exit_code);
        }
    }
}
