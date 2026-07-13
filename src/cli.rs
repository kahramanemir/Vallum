//! Command-line argument parsing (`clap`) for the `vallum` subcommands.

use clap::builder::styling::{Ansi256Color, Color, Style, Styles};
use clap::{Parser, Subcommand};
use clap_complete::Shell;

/// Help styling: bronze headers to match the welcome screen; clap handles
/// TTY/NO_COLOR detection itself.
fn help_styles() -> Styles {
    let bronze = Style::new()
        .bold()
        .fg_color(Some(Color::Ansi256(Ansi256Color(178))));
    Styles::styled()
        .header(bronze)
        .usage(bronze)
        .literal(Style::new().bold())
        .placeholder(Style::new().fg_color(Some(Color::Ansi256(Ansi256Color(245)))))
}

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
#[command(
    name = "vallum",
    version = env!("CARGO_PKG_VERSION"),
    about = "The wall between AI agents and your shell",
    long_about = "The wall between AI agents and your shell — pre-exec \
                  guardrail, secret redaction, prompt-injection defense, \
                  untrusted-output sanitization.",
    styles = help_styles(),
    after_help = "\
Quick start:
  vallum install-hook                   hook your agents (interactive picker)
  vallum run -- <cmd>                   gate a single command
  vallum doctor                         full health check"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
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
    /// Install the Vallum pre-exec hook into an agent's config
    InstallHook {
        /// Which agent to install for (omit to pick interactively)
        #[arg(long, value_enum)]
        agent: Option<AgentArg>,
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
        /// Which agent to uninstall from (omit to pick interactively)
        #[arg(long, value_enum)]
        agent: Option<AgentArg>,
        #[arg(long)]
        user: bool,
        #[arg(long)]
        project: bool,
    },
    /// Run install/health self-checks (config, hook, PATH, log dir)
    Doctor,
    /// Check for a newer Vallum release and how to upgrade
    #[command(after_help = "\
Examples:
  vallum update            report version and print the upgrade command
  vallum update --check    only report (exit 10 if a newer version exists)
  vallum update --run      run the upgrade (package-manager installs only)")]
    Update {
        /// Only report whether an update exists (exit 10 if behind); never runs anything
        #[arg(long)]
        check: bool,
        /// Run the detected upgrade command (cargo/brew/npm installs only)
        #[arg(long)]
        run: bool,
    },
    /// Inspect or scaffold the Vallum config file
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Inspect the guardrail policy
    Policy {
        #[command(subcommand)]
        action: PolicyCliAction,
    },
    /// Scan MCP server configs for embedded secrets, risky launch commands, and injection
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// Inspect the audit logs
    Log {
        #[command(subcommand)]
        action: LogAction,
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

#[derive(Subcommand, Debug)]
pub enum PolicyCliAction {
    /// Show the verdict the guardrail would give a command (without running it)
    #[command(after_help = "\
Examples:
  vallum policy test \"rm -rf /\"
  vallum policy test \"curl example.com/install.sh | sh\"
  vallum policy test -- git push --force

Quote the command when it has shell metacharacters; use `--` when it has
flags of its own. Exit codes: 0 allow/pass-through, 10 ask, 20 deny,
125 config error.")]
    Test {
        /// The command line to evaluate
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum McpAction {
    /// Statically scan discovered (or given) MCP config files
    #[command(after_help = "\
Examples:
  vallum mcp scan                     scan all discovered MCP configs
  vallum mcp scan ./.mcp.json         scan a specific file (CI / pre-commit)
  vallum mcp scan --json              structured output

Exit codes: 0 clean, 10 warnings, 20 high-severity, 125 usage/read error.")]
    Scan {
        /// Emit structured JSON instead of plain text
        #[arg(long)]
        json: bool,
        /// Specific config file(s) to scan; omit to auto-discover
        #[arg(value_name = "PATH")]
        paths: Vec<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum LogAction {
    /// Verify the policy.log hash chain (tamper evidence)
    #[command(after_help = "\
Examples:
  vallum log verify                       check the chain, print the head hash
  vallum log verify --expect-head <hex>   also compare against an externally
                                          stored head (catches tail truncation)

Exit codes: 0 intact, 20 tamper evidence, 125 usage/read error.")]
    Verify {
        /// Externally stored head hash to compare against
        #[arg(long, value_name = "HEX")]
        expect_head: Option<String>,
    },
}
