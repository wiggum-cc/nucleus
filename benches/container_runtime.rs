use criterion::{criterion_group, criterion_main, Criterion};
use nix::unistd::Uid;
use nucleus::container::{Container, ContainerConfig, TrustLevel};
use nucleus::filesystem::ContextMode;
use nucleus::isolation::NamespaceConfig;
use nucleus::resources::{Cgroup, ResourceLimits};
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

type BenchResult<T> = Result<T, Box<dyn std::error::Error>>;

const CPU_LOOP_SCRIPT: &str =
    "i=0; acc=0; while [ \"$i\" -lt 200000 ]; do acc=$((acc + (i % 97))); i=$((i + 1)); done; test \"$acc\" -ge 0";
const CONTEXT_SCAN_SCRIPT_TEMPLATE: &str =
    "total=0; for f in {PATH}/*; do bytes=$(wc -c < \"$f\"); total=$((total + bytes)); done; test \"$total\" -gt 0";

#[derive(Clone, Copy)]
enum Runner {
    HostDirect,
    Containerized,
}

impl Runner {
    fn label(self) -> &'static str {
        match self {
            Self::HostDirect => "host_direct",
            Self::Containerized => "containerized",
        }
    }
}

#[derive(Clone, Copy)]
enum Workload {
    Startup,
    CpuLoop,
    ContextScan,
}

impl Workload {
    fn host_script(self, context_dir: Option<&Path>) -> String {
        match self {
            Self::Startup => ":".to_string(),
            Self::CpuLoop => CPU_LOOP_SCRIPT.to_string(),
            Self::ContextScan => {
                let context_dir = context_dir.expect("context workload requires a fixture");
                context_scan_script(&shell_quote(context_dir))
            }
        }
    }

    fn container_script(self) -> String {
        match self {
            Self::Startup => ":".to_string(),
            Self::CpuLoop => CPU_LOOP_SCRIPT.to_string(),
            Self::ContextScan => context_scan_script("/context"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::CpuLoop => "cpu_loop",
            Self::ContextScan => "context_scan",
        }
    }
}

#[derive(Clone, Copy)]
enum ContextVariant {
    BindMount,
    Copy,
}

impl ContextVariant {
    fn label(self) -> &'static str {
        match self {
            Self::BindMount => "bind",
            Self::Copy => "copy",
        }
    }

    fn into_context_mode(self) -> ContextMode {
        match self {
            Self::BindMount => ContextMode::BindMount,
            Self::Copy => ContextMode::Copy,
        }
    }
}

#[derive(Clone)]
struct LimitProfile {
    label: &'static str,
    limits: Option<ResourceLimits>,
}

#[derive(Clone)]
struct Scenario {
    workload: Workload,
    context_variant: Option<ContextVariant>,
    limits: LimitProfile,
}

impl Scenario {
    fn group_name(&self) -> String {
        match self.context_variant {
            Some(context_variant) => format!(
                "container_runtime/{}/{}/{}",
                self.workload.label(),
                context_variant.label(),
                self.limits.label
            ),
            None => format!(
                "container_runtime/{}/{}",
                self.workload.label(),
                self.limits.label
            ),
        }
    }

    fn context_fixture(&self) -> Option<ContextFixture> {
        self.context_variant
            .map(|_| ContextFixture::new_flat(128, 64 * 1024))
    }

    fn measurement_time(&self) -> Duration {
        match self.workload {
            Workload::Startup => Duration::from_secs(4),
            Workload::CpuLoop => Duration::from_secs(10),
            Workload::ContextScan => Duration::from_secs(8),
        }
    }
}

struct ContextFixture {
    _tempdir: TempDir,
    path: PathBuf,
}

impl ContextFixture {
    fn new_flat(file_count: usize, file_size_bytes: usize) -> Self {
        let tempdir = TempDir::new().expect("failed to create context fixture");
        let path = tempdir.path().to_path_buf();
        let data = vec![0x5Au8; file_size_bytes];

        for index in 0..file_count {
            std::fs::write(path.join(format!("file_{index:03}.dat")), &data)
                .expect("failed to write context fixture file");
        }

        Self {
            _tempdir: tempdir,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn shell_quote(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    format!("'{}'", rendered.replace('\'', "'\"'\"'"))
}

fn context_scan_script(path: &str) -> String {
    CONTEXT_SCAN_SCRIPT_TEMPLATE.replace("{PATH}", path)
}

fn unlimited_profile() -> LimitProfile {
    LimitProfile {
        label: "unlimited",
        limits: None,
    }
}

fn constrained_profile() -> LimitProfile {
    let limits = ResourceLimits::unlimited()
        .with_memory("128M")
        .expect("valid memory limit")
        .with_cpu_cores(0.5)
        .expect("valid CPU limit")
        .with_pids(64)
        .expect("valid PID limit");

    LimitProfile {
        label: "half_core_128m",
        limits: Some(limits),
    }
}

fn benchmark_scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            workload: Workload::Startup,
            context_variant: None,
            limits: unlimited_profile(),
        },
        Scenario {
            workload: Workload::CpuLoop,
            context_variant: None,
            limits: unlimited_profile(),
        },
        Scenario {
            workload: Workload::CpuLoop,
            context_variant: None,
            limits: constrained_profile(),
        },
        Scenario {
            workload: Workload::ContextScan,
            context_variant: Some(ContextVariant::BindMount),
            limits: unlimited_profile(),
        },
        Scenario {
            workload: Workload::ContextScan,
            context_variant: Some(ContextVariant::Copy),
            limits: unlimited_profile(),
        },
        Scenario {
            workload: Workload::ContextScan,
            context_variant: Some(ContextVariant::Copy),
            limits: constrained_profile(),
        },
    ]
}

fn measure_iterations<F>(iters: u64, mut run_once: F) -> Duration
where
    F: FnMut() -> BenchResult<()>,
{
    let mut total = Duration::ZERO;

    for _ in 0..iters {
        let start = Instant::now();
        run_once().unwrap();
        total += start.elapsed();
    }

    total
}

fn ensure_status_success(label: &str, status: ExitStatus) -> BenchResult<()> {
    if status.success() {
        return Ok(());
    }

    match (status.code(), status.signal()) {
        (Some(code), _) => Err(format!("{label} exited with status {code}").into()),
        (None, Some(signal)) => Err(format!("{label} terminated by signal {signal}").into()),
        _ => Err(format!("{label} failed without an exit status").into()),
    }
}

fn run_host_direct(scenario: &Scenario, context: Option<&ContextFixture>) -> BenchResult<()> {
    let script = scenario
        .workload
        .host_script(context.map(ContextFixture::path));

    match &scenario.limits.limits {
        Some(limits) => run_host_direct_with_limits(&script, limits),
        None => run_host_direct_unlimited(&script),
    }
}

fn run_host_direct_unlimited(script: &str) -> BenchResult<()> {
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    ensure_status_success("host workload", status)
}

fn run_host_direct_with_limits(script: &str, limits: &ResourceLimits) -> BenchResult<()> {
    let gated_script = format!("IFS= read -r _; {script}");
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(&gated_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let cgroup_name = format!("nucleus-bench-host-{}", child.id());
    let mut cgroup = Cgroup::create(&cgroup_name)?;
    cgroup.set_limits(limits)?;
    cgroup.attach_process(child.id())?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("limited host workload missing stdin pipe")?;
    stdin.write_all(b"start\n")?;
    drop(stdin);

    let status = child.wait()?;
    ensure_status_success("host workload", status)?;
    cgroup.cleanup()?;
    Ok(())
}

fn run_containerized(scenario: &Scenario, context: Option<&ContextFixture>) -> BenchResult<()> {
    let command = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        scenario.workload.container_script(),
    ];

    let limits = scenario
        .limits
        .limits
        .clone()
        .unwrap_or_else(ResourceLimits::unlimited);

    let mut config = ContainerConfig::try_new(None, command)?
        .with_limits(limits)
        .with_namespaces(NamespaceConfig::minimal())
        .with_gvisor(false)
        .with_trust_level(TrustLevel::Trusted)
        .with_allow_degraded_security(true)
        .with_allow_chroot_fallback(true);

    if let Some(context_variant) = scenario.context_variant {
        let context = context.expect("context workload requires a fixture");
        config = config
            .with_context(context.path().to_path_buf())
            .with_context_mode(context_variant.into_context_mode());
    }

    let exit_code = Container::new(config).run()?;
    if exit_code == 0 {
        Ok(())
    } else {
        Err(format!("container workload exited with status {exit_code}").into())
    }
}

fn run_scenario(
    runner: Runner,
    scenario: &Scenario,
    context: Option<&ContextFixture>,
) -> BenchResult<()> {
    match runner {
        Runner::HostDirect => run_host_direct(scenario, context),
        Runner::Containerized => run_containerized(scenario, context),
    }
}

fn container_runtime(c: &mut Criterion) {
    if !Uid::effective().is_root() {
        eprintln!("Skipping container_runtime benchmark: requires root for namespaces and cgroups");
        return;
    }

    for scenario in benchmark_scenarios() {
        let group_name = scenario.group_name();
        let context = scenario.context_fixture().map(Arc::new);
        let mut group = c.benchmark_group(group_name);
        group.sample_size(10);
        group.warm_up_time(Duration::from_secs(1));
        group.measurement_time(scenario.measurement_time());

        for runner in [Runner::HostDirect, Runner::Containerized] {
            let scenario = scenario.clone();
            let context = context.clone();

            group.bench_function(runner.label(), move |b| {
                let context = context.clone();
                b.iter_custom(|iters| {
                    measure_iterations(iters, || {
                        run_scenario(runner, &scenario, context.as_deref())
                    })
                });
            });
        }

        group.finish();
    }
}

criterion_group!(benches, container_runtime);
criterion_main!(benches);
