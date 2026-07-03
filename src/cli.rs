//! Command-line argument parsing (`clap`) for the `vallum` subcommands.

use clap::{Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser, Debug)]
#[command(name = "vallum", version = env!("CARGO_PKG_VERSION"), about = "AI CLI Proxy")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a command through the proxy
    #[command(after_help = "\
Examples:
  vallum run git status
  vallum run -- sh -c 'make 2>&1 | tail -20'
  vallum run -- cargo test --workspace

Put `--` before the command when it has flags of its own, so they are not
parsed as vallum's.")]
    Run {
        /// Emit structured JSON instead of plain text
        #[arg(long)]
        json: bool,
        /// Block all output when a prompt injection is detected
        #[arg(long)]
        strict: bool,
        /// Mirror raw child output to ~/.vallum/live.log as lines arrive
        #[arg(long)]
        tee: bool,
        /// Internal: the guardrail has already ruled on this command (set by the
        /// hook when it re-wraps an approved command through `vallum run`), so
        /// skip re-evaluating the policy. Hidden; not a user-facing knob.
        #[arg(long = "policy-approved", hide = true)]
        policy_approved: bool,
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
        /// Install at project level (.claude/settings.json in the current directory)
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
    /// Run install/health self-checks (config, hook, PATH, log dir)
    Doctor,
    /// Print a shell completion script to stdout
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: Shell,
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
