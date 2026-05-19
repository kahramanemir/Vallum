// src/main.rs
mod ansi;
mod audit;
mod cli;
mod executor;
mod metrics;
mod scrubber;
mod truncator;
mod whitespace;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { cmd, args } => {
            let cmd_context = format!("{} {:?}", cmd, args);
            match executor::execute_command(cmd, args) {
                Ok(output) => {
                    // Write Raw Log
                    let _ = audit::write_log("raw.local.log", &cmd_context, &output);

                    let truncated = truncator::smart_truncate(&output, 50, 50);
                    let sanitized = scrubber::sanitize(&truncated);

                    // Write Sanitized Log
                    let _ = audit::write_log("sanitized.ai.log", &cmd_context, &sanitized);

                    print!("{}", sanitized);
                },
                Err(e) => eprintln!("Proxy Error: {}", e),
            }
        }
    }
}
