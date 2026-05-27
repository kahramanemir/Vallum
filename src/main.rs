// src/main.rs
mod ansi;
mod audit;
mod cli;
mod config;
mod executor;
mod metrics;
mod optimizer;
mod scrubber;
mod stats;
mod tokenizer;
mod truncator;
mod whitespace;

use chrono::Local;
use clap::Parser;
use cli::{Cli, Commands};
use config::AppConfig;
use metrics::StatEntry;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
struct RunOutput<'a> {
    command: &'a str,
    args: &'a [String],
    exit_code: i32,
    optimizer: Option<&'a str>,
    tokens_before: usize,
    tokens_after: usize,
    sanitized_output: &'a str,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { json, cmd, args } => {
            let config = match AppConfig::load() {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Config Error: {}", e);
                    std::process::exit(1);
                }
            };

            let cmd_context = format!("{} {:?}", cmd, args);

            let (raw_output, exit_code) = match executor::execute_command(cmd, args) {
                Ok(output) => output,
                Err(e) => {
                    eprintln!("Proxy Error: {}", e);
                    std::process::exit(1);
                }
            };

            let tokens_before = metrics::estimate_tokens(&raw_output);

            // Raw log first — captures everything pre-pipeline.
            if config.audit.raw_enabled {
                let _ = audit::write_log(
                    "raw.local.log",
                    &cmd_context,
                    &raw_output,
                    config.audit.log_dir.as_deref(),
                );
            }

            // Pipeline: ANSI → (optimize → truncate, unless output is tiny) → scrub.
            let stripped = ansi::strip(&raw_output);

            let mut optimizer_name: Option<String> = None;
            let processed = if metrics::estimate_tokens(&stripped)
                < config.pipeline.min_optimize_tokens
            {
                // Small output: skip optimize/truncate; the security wrapper still applies.
                whitespace::collapse(&stripped)
            } else {
                let after_optimize = match optimizer::dispatch(cmd, args, &stripped) {
                    Some((out, name)) => {
                        optimizer_name = Some(name.to_string());
                        out
                    }
                    None => stripped.clone(),
                };
                let collapsed = whitespace::collapse(&after_optimize);
                truncator::smart_truncate(
                    &collapsed,
                    config.pipeline.head_lines,
                    config.pipeline.tail_lines,
                )
            };

            let sanitized = scrubber::sanitize(&processed, &config.scrubber.extra_secret_patterns);

            let tokens_after = metrics::estimate_tokens(&sanitized);

            // Sanitized log.
            if config.audit.sanitized_enabled {
                let _ = audit::write_log(
                    "sanitized.ai.log",
                    &cmd_context,
                    &sanitized,
                    config.audit.log_dir.as_deref(),
                );
            }

            // Stats entry — best effort, never blocks output.
            let entry = StatEntry {
                ts: Local::now().to_rfc3339(),
                cmd: cmd.clone(),
                args: args.clone(),
                tokens_before,
                tokens_after,
                optimizer: optimizer_name.clone(),
                exit_code,
            };
            metrics::append_stat(&entry);

            if *json {
                let payload = RunOutput {
                    command: cmd,
                    args,
                    exit_code,
                    optimizer: optimizer_name.as_deref(),
                    tokens_before,
                    tokens_after,
                    sanitized_output: &sanitized,
                };

                match serde_json::to_string(&payload) {
                    Ok(json_output) => println!("{}", json_output),
                    Err(e) => {
                        eprintln!("Proxy Error: failed to serialize JSON output: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                print!("{}", sanitized);
            }

            let _ = io::stdout().flush();
            std::process::exit(exit_code);
        }
        Commands::Stats { reset } => {
            let path = metrics::stats_path();
            if *reset {
                if let Err(e) = stats::reset(&path) {
                    eprintln!("Stats reset failed: {}", e);
                }
            } else {
                match stats::aggregate(&path) {
                    Ok(report) => stats::print_report(&report),
                    Err(e) => eprintln!("Could not read stats: {}", e),
                }
            }
        }
    }
}
