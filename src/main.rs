use anyhow::Result;
use clap::Parser;
use nucleus::container::{Container, ContainerConfig};
use nucleus::isolation::NamespaceConfig;
use nucleus::resources::ResourceLimits;
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

        /// Container runtime (default: native, or gvisor)
        #[arg(long, default_value = "native")]
        runtime: String,

        /// Command to run in container
        #[arg(last = true)]
        command: Vec<String>,
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
        Commands::Run {
            context,
            memory,
            cpus,
            runtime,
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

            // Build configuration
            let mut config = ContainerConfig::new(container_id, command)
                .with_limits(limits)
                .with_namespaces(NamespaceConfig::all());

            if let Some(ctx) = context {
                config = config.with_context(PathBuf::from(ctx));
            }

            if runtime == "gvisor" {
                config = config.with_gvisor(true);
            }

            // Run container
            let container = Container::new(config);
            let exit_code = container.run()?;

            std::process::exit(exit_code);
        }
    }
}
