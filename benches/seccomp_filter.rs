use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use nucleus::security::SeccompManager;

fn seccomp_compile_minimal_filter(c: &mut Criterion) {
    c.bench_function("seccomp_compile_minimal_filter", |b| {
        b.iter(|| SeccompManager::compile_minimal_filter().unwrap());
    });
}

fn seccomp_compile_repeated(c: &mut Criterion) {
    let mut group = c.benchmark_group("seccomp_compile_repeated");
    for count in [1, 5, 10, 50] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                for _ in 0..count {
                    let _ = SeccompManager::compile_minimal_filter().unwrap();
                }
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    seccomp_compile_minimal_filter,
    seccomp_compile_repeated
);
criterion_main!(benches);
