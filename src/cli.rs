// src/cli.rs
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "vallum", version = "0.2", about = "AI CLI Proxy")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a command through the proxy
    Run {
        /// Emit structured JSON instead of plain text
        #[arg(long)]
        json: bool,
        /// The command to run
        cmd: String,
        /// Arguments for the command
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Show cumulative token savings report
    Stats {
        /// Delete all collected stats (prompts for confirmation)
        #[arg(long)]
        reset: bool,
    },
}
