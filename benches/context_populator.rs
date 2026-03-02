use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use nucleus::filesystem::ContextPopulator;
use std::fs;
use tempfile::TempDir;

/// Create a flat directory with `count` files of `size_bytes` each.
fn create_flat_tree(dir: &std::path::Path, count: usize, size_bytes: usize) {
    let data = vec![0xABu8; size_bytes];
    for i in 0..count {
        fs::write(dir.join(format!("file_{i}.dat")), &data).unwrap();
    }
}

/// Create a deep directory tree with `depth` levels, `files_per_level` files at each level.
fn create_deep_tree(dir: &std::path::Path, depth: usize, files_per_level: usize) {
    let data = vec![0xABu8; 1024];
    let mut current = dir.to_path_buf();
    for d in 0..depth {
        for f in 0..files_per_level {
            fs::write(current.join(format!("file_{f}.dat")), &data).unwrap();
        }
        if d + 1 < depth {
            current = current.join(format!("level_{d}"));
            fs::create_dir(&current).unwrap();
        }
    }
}

fn context_populate_flat(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_populate_flat");
    for count in [10, 50, 100, 500, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter_with_setup(
                || {
                    let src = TempDir::new().unwrap();
                    let dst = TempDir::new().unwrap();
                    create_flat_tree(src.path(), count, 1024);
                    (src, dst)
                },
                |(src, dst)| {
                    let populator = ContextPopulator::new(src.path(), dst.path().join("out"));
                    populator.populate().unwrap();
                },
            );
        });
    }
    group.finish();
}

fn context_populate_deep(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_populate_deep");
    for depth in [1, 5, 10, 20, 50] {
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &depth| {
            b.iter_with_setup(
                || {
                    let src = TempDir::new().unwrap();
                    let dst = TempDir::new().unwrap();
                    create_deep_tree(src.path(), depth, 5);
                    (src, dst)
                },
                |(src, dst)| {
                    let populator = ContextPopulator::new(src.path(), dst.path().join("out"));
                    populator.populate().unwrap();
                },
            );
        });
    }
    group.finish();
}

fn context_populate_filesize(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_populate_filesize");
    for size_kb in [1, 10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size_kb}KB")),
            &size_kb,
            |b, &size_kb| {
                b.iter_with_setup(
                    || {
                        let src = TempDir::new().unwrap();
                        let dst = TempDir::new().unwrap();
                        create_flat_tree(src.path(), 20, size_kb * 1024);
                        (src, dst)
                    },
                    |(src, dst)| {
                        let populator = ContextPopulator::new(src.path(), dst.path().join("out"));
                        populator.populate().unwrap();
                    },
                );
            },
        );
    }
    group.finish();
}

fn context_exclusion_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("context_exclusion_overhead");

    // Clean tree: 100 normal files
    group.bench_function("clean_100_files", |b| {
        b.iter_with_setup(
            || {
                let src = TempDir::new().unwrap();
                let dst = TempDir::new().unwrap();
                create_flat_tree(src.path(), 100, 1024);
                (src, dst)
            },
            |(src, dst)| {
                let populator = ContextPopulator::new(src.path(), dst.path().join("out"));
                populator.populate().unwrap();
            },
        );
    });

    // Dirty tree: 100 normal files + 100 excludable files
    group.bench_function("dirty_100_plus_100_excluded", |b| {
        b.iter_with_setup(
            || {
                let src = TempDir::new().unwrap();
                let dst = TempDir::new().unwrap();
                let data = vec![0xABu8; 1024];
                // 100 normal files
                for i in 0..100 {
                    fs::write(src.path().join(format!("file_{i}.dat")), &data).unwrap();
                }
                // 100 excludable files (various excluded patterns)
                let excludable_names = [
                    ".git", "target", "node_modules", "__pycache__", ".DS_Store",
                    ".svn", ".env", ".ssh", ".gnupg", ".aws",
                ];
                for (i, name) in excludable_names.iter().enumerate() {
                    fs::create_dir(src.path().join(name)).unwrap();
                    for j in 0..9 {
                        // Fill each excluded dir with files
                        fs::write(
                            src.path().join(name).join(format!("inner_{j}.dat")),
                            &data,
                        )
                        .unwrap();
                    }
                    let _ = i; // suppress unused warning
                }
                // Also add excluded file patterns
                for i in 0..10 {
                    fs::write(src.path().join(format!("key_{i}.pem")), &data).unwrap();
                    fs::write(src.path().join(format!("file_{i}.swp")), &data).unwrap();
                }
                (src, dst)
            },
            |(src, dst)| {
                let populator = ContextPopulator::new(src.path(), dst.path().join("out"));
                populator.populate().unwrap();
            },
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    context_populate_flat,
    context_populate_deep,
    context_populate_filesize,
    context_exclusion_overhead
);
criterion_main!(benches);
