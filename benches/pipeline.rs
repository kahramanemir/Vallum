// Placeholder — full benchmark implemented in Task 5.
use criterion::{criterion_group, criterion_main, Criterion};

fn pipeline_bench(_c: &mut Criterion) {}

criterion_group!(benches, pipeline_bench);
criterion_main!(benches);
