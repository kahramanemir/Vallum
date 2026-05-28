// src/cli.rs
use clap::{Parser, Subcommand};


#[derive(Parser, Debug)]
#[command(name = "vallum", version = env!("CARGO_PKG_VERSION"), about = "AI CLI Proxy")]
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
        /// Block all output when a prompt injection is detected
        #[arg(long)]
        strict: bool,
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
    /// Run as a Claude Code PreToolUse hook (reads JSON from stdin)
    Hook,
    /// Install the Vallum PreToolUse hook in Claude Code's settings.json
    InstallHook {
        /// Install at user level (~/.claude/settings.json) — default
        #[arg(long)]
        user: bool,
        /// Install at project level (<cwd>/.claude/settings.json)
        #[arg(long)]
        project: bool,
        /// Replace an existing Vallum hook entry if present
        #[arg(long)]
        force: bool,
    },
    /// Remove the Vallum PreToolUse hook from Claude Code's settings.json
    UninstallHook {
        #[arg(long)]
        user: bool,
        #[arg(long)]
        project: bool,
    },
    /// Inspect or scaffold the Vallum config file
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Print the effective merged config as TOML
    Show,
    /// Write a commented default config to ~/.vallum/config.toml
    Init {
        /// Overwrite an existing config file
        #[arg(long)]
        force: bool,
    },
}
