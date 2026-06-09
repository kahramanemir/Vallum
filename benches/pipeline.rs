// benches/pipeline.rs — criterion harness for the full pipeline.
//
// Run with: cargo bench
//
// Reports a token-savings table (raw → sanitized) and times each pipeline
// invocation per fixture. Each fixture is read from disk once at startup.

use std::path::Path;
use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, Criterion};

use vallum::config::AppConfig;
use vallum::{ansi, metrics, optimizer, scrubber, truncator, whitespace};

struct Fixture {
    label: &'static str,
    path: &'static str,
    cmd: &'static str,
    args: &'static [&'static str],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        label: "git_status_large",
        path: "benches/fixtures/git_status_large.txt",
        cmd: "git",
        args: &["status"],
    },
    Fixture {
        label: "cargo_build",
        path: "benches/fixtures/cargo_build.txt",
        cmd: "cargo",
        args: &["build"],
    },
    Fixture {
        label: "pytest_run",
        path: "benches/fixtures/pytest_run.txt",
        cmd: "pytest",
        args: &[],
    },
    Fixture {
        label: "npm_install",
        path: "benches/fixtures/npm_install.txt",
        cmd: "npm",
        args: &["install"],
    },
    Fixture {
        label: "minified_blob",
        path: "benches/fixtures/minified_blob.txt",
        cmd: "echo",
        args: &[],
    },
    Fixture {
        label: "rg_matches",
        path: "benches/fixtures/rg_matches.txt",
        cmd: "rg",
        args: &["parse"],
    },
    Fixture {
        label: "find_list",
        path: "benches/fixtures/find_list.txt",
        cmd: "find",
        args: &[".", "-type", "f"],
    },
];

fn load(path: &str) -> String {
    std::fs::read_to_string(Path::new(path))
        .unwrap_or_else(|e| panic!("missing fixture {path}: {e}"))
}

fn run_pipeline(raw: &str, cmd: &str, args: &[String], config: &AppConfig) -> String {
    let stripped = ansi::strip(raw);
    let processed = if metrics::estimate_tokens(&stripped) < config.pipeline.min_optimize_tokens {
        whitespace::collapse(&stripped)
    } else {
        let after_opt = match optimizer::dispatch(cmd, args, &stripped, &config.optimizer.disabled)
        {
            Some((out, _)) => out,
            None => stripped.clone(),
        };
        let collapsed = whitespace::collapse(&after_opt);
        truncator::smart_truncate(
            &collapsed,
            config.pipeline.head_lines,
            config.pipeline.tail_lines,
            config.pipeline.max_line_length,
        )
    };
    scrubber::sanitize(&processed, &[], false)
}

fn print_savings_report(config: &AppConfig) {
    eprintln!();
    eprintln!("Vallum — pipeline savings (heuristic estimator)");
    eprintln!("─────────────────────────────────────────────────");
    eprintln!(
        "{:<22} {:>10} {:>10} {:>8}",
        "fixture", "raw", "sanitized", "saved"
    );
    for f in FIXTURES {
        let raw = load(f.path);
        let args: Vec<String> = f.args.iter().map(|s| (*s).to_string()).collect();
        let sanitized = run_pipeline(&raw, f.cmd, &args, config);
        let raw_t = metrics::estimate_tokens(&raw);
        let san_t = metrics::estimate_tokens(&sanitized);
        let saved = raw_t.saturating_sub(san_t);
        let pct = if raw_t == 0 {
            0.0
        } else {
            (saved as f64 / raw_t as f64) * 100.0
        };
        eprintln!("{:<22} {:>10} {:>10} {:>7.1}%", f.label, raw_t, san_t, pct);
    }
    eprintln!();
}

fn report_once(config: &AppConfig) {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        print_savings_report(config);
    });
}

fn bench_pipeline(c: &mut Criterion) {
    let config = AppConfig::default();
    report_once(&config);

    let mut group = c.benchmark_group("pipeline");
    for f in FIXTURES {
        let raw = load(f.path);
        let args: Vec<String> = f.args.iter().map(|s| (*s).to_string()).collect();
        group.bench_function(f.label, |b| {
            b.iter(|| {
                let _ = run_pipeline(&raw, f.cmd, &args, &config);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
