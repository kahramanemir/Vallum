// src/main.rs
mod ansi;
mod audit;
mod cli;
mod executor;
mod metrics;
mod optimizer;
mod scrubber;
mod stats;
mod truncator;
mod whitespace;

use chrono::Local;
use clap::Parser;
use cli::{Cli, Commands};
use metrics::StatEntry;

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { cmd, args } => {
            let cmd_context = format!("{} {:?}", cmd, args);

            let (raw_output, exit_code) = match executor::execute_command(cmd, args) {
                Ok(output) => (output, 0),
                Err(e) => {
                    eprintln!("Proxy Error: {}", e);
                    return;
                }
            };

            let tokens_before = metrics::estimate_tokens(&raw_output);

            // Raw log first — captures everything pre-pipeline.
            let _ = audit::write_log("raw.local.log", &cmd_context, &raw_output);

            // Pipeline: ANSI → optimize? → whitespace → truncate → scrub.
            let stripped = ansi::strip(&raw_output);

            let (after_optimize, optimizer_name) =
                match optimizer::dispatch(cmd, args, &stripped) {
                    Some((out, name)) => (out, Some(name.to_string())),
                    None => (stripped, None),
                };

            let collapsed = whitespace::collapse(&after_optimize);
            let truncated = truncator::smart_truncate(&collapsed, 50, 50);
            let sanitized = scrubber::sanitize(&truncated);

            let tokens_after = metrics::estimate_tokens(&sanitized);

            // Sanitized log.
            let _ = audit::write_log("sanitized.ai.log", &cmd_context, &sanitized);

            // Stats entry — best effort, never blocks output.
            let entry = StatEntry {
                ts: Local::now().to_rfc3339(),
                cmd: cmd.clone(),
                args: args.clone(),
                tokens_before,
                tokens_after,
                optimizer: optimizer_name,
                exit_code,
            };
            metrics::append_stat(&entry);

            print!("{}", sanitized);
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
