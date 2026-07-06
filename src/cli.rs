//! Command-line argument parsing (`clap`) for the `vallum` subcommands.

use clap::{Parser, Subcommand};
use clap_complete::Shell;

/// Agents Vallum can speak a pre-exec hook protocol for.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentArg {
    /// Claude Code (`PreToolUse`; rewrites approved commands through `vallum run`)
    Claude,
    /// Codex CLI (`PreToolUse`; verdicts only, Ask fails closed)
    Codex,
    /// Cursor (`beforeShellExecution`; verdicts only, native ask)
    Cursor,
    /// Gemini CLI (`BeforeTool`; verdicts only, Ask fails closed)
    Gemini,
}

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
    /// Run as an agent pre-exec guardrail hook (reads JSON from stdin)
    Hook {
        /// Which agent's hook protocol to speak
        #[arg(long, value_enum, default_value_t = AgentArg::Claude)]
        agent: AgentArg,
    },
    /// Install the Vallum pre-exec hook into an agent's config
    InstallHook {
        /// Which agent to install for
        #[arg(long, value_enum, default_value_t = AgentArg::Claude)]
        agent: AgentArg,
        /// Install at user level (default)
        #[arg(long)]
        user: bool,
        /// Install at project level (Claude Code only)
        #[arg(long)]
        project: bool,
        /// Replace an existing Vallum hook entry if present
        #[arg(long)]
        force: bool,
    },
    /// Remove the Vallum pre-exec hook from an agent's config
    UninstallHook {
        /// Which agent to uninstall from
        #[arg(long, value_enum, default_value_t = AgentArg::Claude)]
        agent: AgentArg,
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
