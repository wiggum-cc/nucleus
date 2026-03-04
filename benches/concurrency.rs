use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use nucleus::container::ContainerState;
use nucleus::filesystem::ContextPopulator;
use nucleus::resources::{ResourceLimits, ResourceStats};
use nucleus::security::{OciConfig, SeccompManager};
use std::fs;
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

fn create_mock_cgroup(dir: &std::path::Path) {
    fs::write(dir.join("memory.current"), "104857600\n").unwrap();
    fs::write(dir.join("memory.max"), "536870912\n").unwrap();
    fs::write(dir.join("memory.swap.current"), "0\n").unwrap();
    fs::write(
        dir.join("cpu.stat"),
        "usage_usec 5000000\nuser_usec 3000000\nsystem_usec 2000000\n",
    )
    .unwrap();
    fs::write(dir.join("pids.current"), "42\n").unwrap();
}

fn create_flat_tree(dir: &std::path::Path, count: usize) {
    let data = vec![0xABu8; 1024];
    for i in 0..count {
        fs::write(dir.join(format!("file_{i}.dat")), &data).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Concurrent seccomp filter compilation
// ---------------------------------------------------------------------------

fn concurrent_seccomp_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_seccomp_compile");
    for threads in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{threads}t")),
            &threads,
            |b, &threads| {
                b.iter(|| {
                    thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|_| s.spawn(|| SeccompManager::compile_minimal_filter().unwrap()))
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Concurrent resource limit parsing
// ---------------------------------------------------------------------------

fn concurrent_parse_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_parse_memory");
    let inputs = ["1048576", "1024K", "512M", "2G", "1T"];
    for threads in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{threads}t")),
            &threads,
            |b, &threads| {
                b.iter(|| {
                    thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|i| {
                                let input = inputs[i % inputs.len()];
                                s.spawn(move || {
                                    for _ in 0..100 {
                                        ResourceLimits::parse_memory(input).unwrap();
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Concurrent cgroup stats reading (independent mock cgroups)
// ---------------------------------------------------------------------------

fn concurrent_cgroup_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_cgroup_stats");
    for threads in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{threads}t")),
            &threads,
            |b, &threads| {
                b.iter_with_setup(
                    || {
                        // Each thread gets its own mock cgroup directory
                        let dirs: Vec<_> = (0..threads)
                            .map(|_| {
                                let dir = TempDir::new().unwrap();
                                create_mock_cgroup(dir.path());
                                dir
                            })
                            .collect();
                        dirs
                    },
                    |dirs| {
                        thread::scope(|s| {
                            let handles: Vec<_> = dirs
                                .iter()
                                .map(|dir| {
                                    let path = dir.path().to_str().unwrap().to_string();
                                    s.spawn(move || ResourceStats::from_cgroup(&path).unwrap())
                                })
                                .collect();
                            for h in handles {
                                h.join().unwrap();
                            }
                        });
                    },
                );
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Concurrent cgroup stats on shared directory (contention)
// ---------------------------------------------------------------------------

fn concurrent_cgroup_stats_shared(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_cgroup_stats_shared");
    for threads in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{threads}t")),
            &threads,
            |b, &threads| {
                b.iter_with_setup(
                    || {
                        let dir = TempDir::new().unwrap();
                        create_mock_cgroup(dir.path());
                        dir
                    },
                    |dir| {
                        let path = dir.path().to_str().unwrap();
                        thread::scope(|s| {
                            let handles: Vec<_> = (0..threads)
                                .map(|_| s.spawn(|| ResourceStats::from_cgroup(path).unwrap()))
                                .collect();
                            for h in handles {
                                h.join().unwrap();
                            }
                        });
                    },
                );
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Concurrent OCI config build + serialize
// ---------------------------------------------------------------------------

fn concurrent_oci_config(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_oci_config");
    for threads in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{threads}t")),
            &threads,
            |b, &threads| {
                b.iter(|| {
                    thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|i| {
                                s.spawn(move || {
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
                                            format!("echo container-{i}"),
                                        ],
                                        Some(format!("bench-{i}")),
                                    )
                                    .with_resources(&limits);
                                    serde_json::to_string_pretty(&config).unwrap()
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Concurrent container state serde
// ---------------------------------------------------------------------------

fn concurrent_state_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_state_serde");
    for threads in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{threads}t")),
            &threads,
            |b, &threads| {
                // Pre-build states
                let states: Arc<Vec<_>> = Arc::new(
                    (0..threads)
                        .map(|i| {
                            ContainerState::new(
                                format!("bench-{i}"),
                                format!("bench-{i}"),
                                (10000 + i) as u32,
                                vec![
                                    "/bin/sh".to_string(),
                                    "-c".to_string(),
                                    "echo hello".to_string(),
                                ],
                                Some(512 * 1024 * 1024),
                                Some(2000),
                                false,
                                true,
                                Some(format!("/sys/fs/cgroup/nucleus-bench-{i}")),
                            )
                        })
                        .collect(),
                );

                b.iter(|| {
                    let states = Arc::clone(&states);
                    thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|i| {
                                let states = &states;
                                s.spawn(move || {
                                    let json = serde_json::to_string(&states[i]).unwrap();
                                    let _: ContainerState = serde_json::from_str(&json).unwrap();
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Concurrent state file I/O (save + load, separate containers)
// ---------------------------------------------------------------------------

fn concurrent_state_file_io(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_state_file_io");
    for threads in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{threads}t")),
            &threads,
            |b, &threads| {
                b.iter_with_setup(
                    || {
                        let dir = TempDir::new().unwrap();
                        let states: Vec<_> = (0..threads)
                            .map(|i| {
                                ContainerState::new(
                                    format!("bench-{i}"),
                                    format!("bench-{i}"),
                                    (10000 + i) as u32,
                                    vec!["/bin/sh".to_string()],
                                    Some(512 * 1024 * 1024),
                                    Some(2000),
                                    false,
                                    true,
                                    None,
                                )
                            })
                            .collect();
                        (dir, states)
                    },
                    |(dir, states)| {
                        let dir_path = dir.path();
                        thread::scope(|s| {
                            let handles: Vec<_> = states
                                .iter()
                                .map(|state| {
                                    s.spawn(|| {
                                        let path =
                                            dir_path.join(format!("{}.json", state.id));
                                        let json =
                                            serde_json::to_string_pretty(state).unwrap();
                                        fs::write(&path, &json).unwrap();
                                        let loaded = fs::read_to_string(&path).unwrap();
                                        let _: ContainerState =
                                            serde_json::from_str(&loaded).unwrap();
                                    })
                                })
                                .collect();
                            for h in handles {
                                h.join().unwrap();
                            }
                        });
                    },
                );
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Concurrent context population (independent src/dst pairs)
// ---------------------------------------------------------------------------

fn concurrent_context_populate(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_context_populate");
    group.sample_size(30);
    for threads in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{threads}t")),
            &threads,
            |b, &threads| {
                b.iter_with_setup(
                    || {
                        (0..threads)
                            .map(|_| {
                                let src = TempDir::new().unwrap();
                                let dst = TempDir::new().unwrap();
                                create_flat_tree(src.path(), 50);
                                (src, dst)
                            })
                            .collect::<Vec<_>>()
                    },
                    |pairs| {
                        thread::scope(|s| {
                            let handles: Vec<_> = pairs
                                .iter()
                                .map(|(src, dst)| {
                                    s.spawn(|| {
                                        let populator = ContextPopulator::new(
                                            src.path(),
                                            dst.path().join("out"),
                                        );
                                        populator.populate().unwrap();
                                    })
                                })
                                .collect();
                            for h in handles {
                                h.join().unwrap();
                            }
                        });
                    },
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    concurrent_seccomp_compile,
    concurrent_parse_memory,
    concurrent_cgroup_stats,
    concurrent_cgroup_stats_shared,
    concurrent_oci_config,
    concurrent_state_serde,
    concurrent_state_file_io,
    concurrent_context_populate
);
criterion_main!(benches);
