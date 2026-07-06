// src/main.rs
use chrono::Local;
use clap::{CommandFactory, Parser};
use clap_complete::generate;
use serde::Serialize;
use std::io::{self, Write};
use vallum::cli::{Cli, Commands, ConfigAction};
use vallum::config::AppConfig;
use vallum::install_hook::{self, Level};
use vallum::metrics::{self, StatEntry};
use vallum::{ansi, audit, executor, hook, optimizer, scrubber, stats, truncator, whitespace};

#[derive(Serialize)]
struct RunOutput<'a> {
    command: &'a str,
    args: &'a [String],
    exit_code: i32,
    optimizer: Option<&'a str>,
    tokens_before: usize,
    tokens_after: usize,
    sanitized_output: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'a vallum::policy::PolicyVerdict>,
}

/// Whether stdin is an interactive terminal (drives direct-mode Ask prompting).
fn atty_stdin() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Prompt on the controlling terminal and read one line. Returns None on error.
fn prompt_tty(reason: &str) -> Option<String> {
    use std::io::{BufRead, Write};
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    write!(tty, "[vallum] {reason} — proceed? [y/N] ").ok()?;
    tty.flush().ok()?;
    let mut reader = std::io::BufReader::new(tty);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    Some(line)
}

/// Emit a block result and exit 125. In JSON mode, serialize a RunOutput with
/// the policy verdict; otherwise print a stderr message.
fn emit_block(
    json: bool,
    verdict: &vallum::policy::PolicyVerdict,
    cmd: &str,
    args: &[String],
) -> ! {
    if json {
        let payload = RunOutput {
            command: cmd,
            args,
            exit_code: 125,
            optimizer: None,
            tokens_before: 0,
            tokens_after: 0,
            sanitized_output: "[BLOCKED BY POLICY]\n",
            policy: Some(verdict),
        };
        if let Ok(s) = serde_json::to_string(&payload) {
            println!("{s}");
        }
    } else {
        eprintln!("[vallum] blocked: {}", verdict.reason);
    }
    std::process::exit(125);
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run {
            json,
            strict,
            tee,
            policy_approved,
            cmd,
            args,
        } => {
            let config = match AppConfig::load() {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("Config Error: {}", e);
                    std::process::exit(125);
                }
            };

            // --- Guardrail: evaluate the command before running it. ---
            // `--policy-approved` means the hook already ruled on this exact
            // command and re-wrapped it through `vallum run`; re-evaluating here
            // would double-gate (and, being non-interactive, fail closed on an
            // already-approved Ask), so we skip.
            if config.security.guardrail && !*policy_approved {
                // Unreachable Err: AppConfig::load() -> validate() already
                // compiled every user regex, so a failure here means config
                // drift. Fail closed rather than silently running ungated.
                let policy = match vallum::policy::Policy::compile(&config.policy) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Config Error: policy failed to compile: {}", e);
                        std::process::exit(125);
                    }
                };
                let command_line = if args.is_empty() {
                    cmd.clone()
                } else {
                    format!("{} {}", cmd, args.join(" "))
                };
                let verdict = policy.evaluate(&command_line);
                match verdict.action {
                    vallum::policy::PolicyAction::Allow => {}
                    vallum::policy::PolicyAction::Deny => {
                        vallum::policy::audit::log_verdict(
                            &verdict,
                            &command_line,
                            "direct",
                            &config,
                        );
                        emit_block(*json, &verdict, cmd, args);
                    }
                    vallum::policy::PolicyAction::Ask => {
                        // Record the Ask once, whether it proceeds or blocks.
                        vallum::policy::audit::log_verdict(
                            &verdict,
                            &command_line,
                            "direct",
                            &config,
                        );
                        let assume_yes = config.security.assume_yes
                            || std::env::var("VALLUM_ASSUME_YES")
                                .map(|v| v == "1")
                                .unwrap_or(false);
                        let decision = if assume_yes {
                            vallum::policy::AskDecision::Proceed
                        } else if !*json && atty_stdin() {
                            let resp = prompt_tty(&verdict.reason);
                            vallum::policy::resolve_ask(false, true, resp.as_deref())
                        } else {
                            vallum::policy::resolve_ask(false, false, None)
                        };
                        if decision == vallum::policy::AskDecision::Blocked {
                            emit_block(*json, &verdict, cmd, args);
                        }
                    }
                }
            }

            let tee_path = if *tee {
                dirs::home_dir().map(|h| h.join(".vallum").join("live.log"))
            } else {
                None
            };

            let (raw_output, exit_code) = match executor::execute_command(
                cmd,
                args,
                config.pipeline.max_output_bytes,
                config.pipeline.timeout_secs,
                tee_path.as_deref(),
            ) {
                Ok(output) => output,
                Err(e) => {
                    eprintln!("Proxy Error: {}", e);
                    std::process::exit(125);
                }
            };

            let strict = *strict || config.security.strict;
            let extra = scrubber::compile_rules(&config.scrubber.extra_secret_patterns);
            let entropy = config.scrubber.entropy;
            let normalize = config.scrubber.normalize;
            let safe_cmd = scrubber::redact(cmd, &extra, entropy, normalize);
            let safe_args: Vec<String> = args
                .iter()
                .map(|a| scrubber::redact(a, &extra, entropy, normalize))
                .collect();
            let cmd_context = format!("{} {:?}", safe_cmd, safe_args);

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
                let after_optimize =
                    match optimizer::dispatch(cmd, args, &stripped, &config.optimizer.disabled) {
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
                    config.pipeline.max_line_length,
                )
            };

            let sanitized = scrubber::sanitize(&processed, &extra, strict, entropy, normalize);

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
                cmd: safe_cmd.clone(),
                args: safe_args.clone(),
                tokens_before,
                tokens_after,
                optimizer: optimizer_name.clone(),
                exit_code,
            };
            metrics::append_stat(&entry);

            if *json {
                let payload = RunOutput {
                    command: &safe_cmd,
                    args: &safe_args,
                    exit_code,
                    optimizer: optimizer_name.as_deref(),
                    tokens_before,
                    tokens_after,
                    sanitized_output: &sanitized,
                    policy: None,
                };

                match serde_json::to_string(&payload) {
                    Ok(json_output) => println!("{}", json_output),
                    Err(e) => {
                        eprintln!("Proxy Error: failed to serialize JSON output: {}", e);
                        std::process::exit(125);
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
        Commands::Hook { agent } => {
            let code = match agent {
                vallum::cli::AgentArg::Claude => hook::claude::run(),
            };
            std::process::exit(code);
        }
        Commands::InstallHook {
            user,
            project,
            force,
        } => {
            let level = match resolve_level(*user, *project) {
                Ok(l) => l,
                Err(msg) => {
                    eprintln!("{msg}");
                    std::process::exit(125);
                }
            };
            match install_hook::install(level, *force) {
                Ok(msg) => println!("{msg}"),
                Err(e) => {
                    eprintln!("install-hook: {e}");
                    std::process::exit(125);
                }
            }
        }
        Commands::UninstallHook { user, project } => {
            let level = match resolve_level(*user, *project) {
                Ok(l) => l,
                Err(msg) => {
                    eprintln!("{msg}");
                    std::process::exit(125);
                }
            };
            match install_hook::uninstall(level) {
                Ok(msg) => println!("{msg}"),
                Err(e) => {
                    eprintln!("uninstall-hook: {e}");
                    std::process::exit(125);
                }
            }
        }
        Commands::Config { action } => match action {
            ConfigAction::Show => {
                let config = match AppConfig::load() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Config Error: {e}");
                        std::process::exit(125);
                    }
                };
                match toml::to_string_pretty(&config) {
                    Ok(s) => print!("{s}"),
                    Err(e) => {
                        eprintln!("config show: serialize failed: {e}");
                        std::process::exit(125);
                    }
                }
            }
            ConfigAction::Init { force } => match config_init(*force) {
                Ok(msg) => println!("{msg}"),
                Err(e) => {
                    eprintln!("config init: {e}");
                    std::process::exit(125);
                }
            },
        },
        Commands::Doctor => {
            std::process::exit(vallum::doctor::run());
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(*shell, &mut cmd, "vallum", &mut std::io::stdout());
        }
    }
}

fn resolve_level(user: bool, project: bool) -> Result<Level, String> {
    match (user, project) {
        (true, true) => Err("--user and --project are mutually exclusive".to_string()),
        (false, true) => Ok(Level::Project),
        _ => Ok(Level::User), // default
    }
}

const DEFAULT_CONFIG_TOML: &str = r#"# ~/.vallum/config.toml — Vallum configuration

[audit]
# log_dir = "/tmp/vallum-logs"  # override log directory (default: ~/.vallum/logs)
raw_enabled = false              # raw, unredacted logging is opt-in
sanitized_enabled = true

[pipeline]
head_lines = 50
tail_lines = 50
min_optimize_tokens = 50
max_output_bytes = 10485760      # 10 MiB capture cap
timeout_secs = 300               # child timeout; 0 disables
max_line_length = 2000           # truncate single lines longer than this; 0 disables

[scrubber]
entropy = true                   # context-gated entropy redaction of credential-ish values
normalize = true                 # strip invisible/bidi chars + fold homoglyphs for injection matching
# extra_secret_patterns = [
#   { pattern = "token-[0-9]+", replacement = "token-***" }
# ]

[security]
strict = false                   # block output if a prompt injection is detected

[optimizer]
disabled = []                    # optimizer names to turn off (e.g. ["npm","docker"])
"#;

fn config_init(force: bool) -> Result<String, String> {
    let path = vallum::config::config_path_from_env_or_default();
    if path.exists() && !force {
        return Ok(format!(
            "{} already exists; pass --force to overwrite.",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    write_private(&path, DEFAULT_CONFIG_TOML)?;
    Ok(format!("Wrote default config → {}", path.display()))
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, contents: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))
}
