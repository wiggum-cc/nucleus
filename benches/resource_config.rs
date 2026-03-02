use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use nucleus::container::ContainerState;
use nucleus::resources::{IoDeviceLimit, ResourceLimits, ResourceStats};
use nucleus::security::OciConfig;
use std::fs;
use tempfile::TempDir;

fn parse_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_memory");
    for (label, input) in [
        ("bytes", "1048576"),
        ("K", "1024K"),
        ("M", "512M"),
        ("G", "2G"),
        ("T", "1T"),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(label), &input, |b, &input| {
            b.iter(|| ResourceLimits::parse_memory(input).unwrap());
        });
    }
    group.finish();
}

fn limits_builder_chain(c: &mut Criterion) {
    let io_spec = "8:0 riops=1000 wbps=10485760";

    c.bench_function("limits_builder_chain", |b| {
        b.iter(|| {
            let io_limit = IoDeviceLimit::parse(io_spec).unwrap();
            ResourceLimits::unlimited()
                .with_memory("512M")
                .unwrap()
                .with_cpu_cores(2.0)
                .unwrap()
                .with_cpu_weight(100)
                .unwrap()
                .with_pids(1024)
                .unwrap()
                .with_io_limit(io_limit)
        });
    });
}

fn io_device_limit_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("io_device_limit_parse");
    for (label, spec) in [
        ("1_param", "8:0 riops=1000"),
        ("2_params", "8:0 riops=1000 wbps=10485760"),
        ("4_params", "8:0 riops=100 wiops=200 rbps=300 wbps=400"),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(label), &spec, |b, &spec| {
            b.iter(|| IoDeviceLimit::parse(spec).unwrap());
        });
    }
    group.finish();
}

fn resource_stats_from_mock_cgroup(c: &mut Criterion) {
    c.bench_function("resource_stats_from_mock_cgroup", |b| {
        b.iter_with_setup(
            || {
                let dir = TempDir::new().unwrap();
                let p = dir.path();
                fs::write(p.join("memory.current"), "104857600\n").unwrap();
                fs::write(p.join("memory.max"), "536870912\n").unwrap();
                fs::write(p.join("memory.swap.current"), "0\n").unwrap();
                fs::write(
                    p.join("cpu.stat"),
                    "usage_usec 5000000\nuser_usec 3000000\nsystem_usec 2000000\n",
                )
                .unwrap();
                fs::write(p.join("pids.current"), "42\n").unwrap();
                dir
            },
            |dir| {
                ResourceStats::from_cgroup(dir.path().to_str().unwrap()).unwrap();
            },
        );
    });
}

fn oci_config_build_and_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("oci_config_build_and_serialize");

    group.bench_function("build", |b| {
        b.iter(|| {
            let limits = ResourceLimits::unlimited()
                .with_memory("512M")
                .unwrap()
                .with_cpu_cores(2.0)
                .unwrap()
                .with_pids(1024)
                .unwrap();
            OciConfig::new(
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "echo hello".to_string(),
                ],
                Some("bench-container".to_string()),
            )
            .with_resources(&limits)
        });
    });

    group.bench_function("serialize", |b| {
        let limits = ResourceLimits::unlimited()
            .with_memory("512M")
            .unwrap()
            .with_cpu_cores(2.0)
            .unwrap()
            .with_pids(1024)
            .unwrap();
        let config = OciConfig::new(
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hello".to_string(),
            ],
            Some("bench-container".to_string()),
        )
        .with_resources(&limits);

        b.iter(|| serde_json::to_string_pretty(&config).unwrap());
    });

    group.finish();
}

fn container_state_serde(c: &mut Criterion) {
    c.bench_function("container_state_serde", |b| {
        let state = ContainerState::new(
            "bench-container-001".to_string(),
            "bench-container-001".to_string(),
            12345,
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hello".to_string(),
            ],
            Some(512 * 1024 * 1024),
            Some(2000),
            false,
            true,
            Some("/sys/fs/cgroup/nucleus-bench".to_string()),
        );

        b.iter(|| {
            let json = serde_json::to_string(&state).unwrap();
            let _: ContainerState = serde_json::from_str(&json).unwrap();
        });
    });
}

criterion_group!(
    benches,
    parse_memory,
    limits_builder_chain,
    io_device_limit_parse,
    resource_stats_from_mock_cgroup,
    oci_config_build_and_serialize,
    container_state_serde
);
criterion_main!(benches);
