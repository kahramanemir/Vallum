//! `vallum doctor` — install/health self-checks (config, hook, `PATH`, log dir).

// src/doctor.rs — `vallum doctor`: a self-check of the local install.
//
// Each check is a pure-ish function over explicit inputs so it can be unit
// tested with temp paths; `run()` wires them to the real environment and
// `render()` formats the report. The process exits non-zero only when a check
// hard-fails (a Warn — e.g. hook not installed — is informational).

use crate::config::AppConfig;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    fn glyph(self) -> &'static str {
        match self {
            Status::Ok => "✓",
            Status::Warn => "!",
            Status::Fail => "✗",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

impl Check {
    fn new(name: &str, status: Status, detail: impl Into<String>) -> Self {
        Check {
            name: name.to_string(),
            status,
            detail: detail.into(),
        }
    }
}

/// Load and validate the config at `path`. A missing file is fine (built-in
/// defaults apply); a present-but-broken file is a hard fail.
pub fn check_config(path: &Path) -> Check {
    if !path.exists() {
        return Check::new(
            "config",
            Status::Ok,
            format!("no file at {} — using built-in defaults", path.display()),
        );
    }
    match AppConfig::from_path(path) {
        Ok(cfg) => Check::new(
            "config",
            Status::Ok,
            format!(
                "{} loaded ({} extra secret pattern(s))",
                path.display(),
                cfg.scrubber.extra_secret_patterns.len()
            ),
        ),
        Err(e) => Check::new("config", Status::Fail, e),
    }
}

/// Warn when `[optimizer] disabled` names something that is not a real
/// optimizer — a silent typo there would leave an optimizer unexpectedly on.
pub fn check_optimizer_names(disabled: &[String], known: &[&str]) -> Check {
    let unknown: Vec<&str> = disabled
        .iter()
        .filter(|d| !known.iter().any(|k| k == &d.as_str()))
        .map(|s| s.as_str())
        .collect();
    if unknown.is_empty() {
        Check::new(
            "optimizer names",
            Status::Ok,
            format!("{} disabled, all recognized", disabled.len()),
        )
    } else {
        Check::new(
            "optimizer names",
            Status::Warn,
            format!(
                "unknown name(s) in [optimizer] disabled: {} — valid: {}",
                unknown.join(", "),
                known.join(", ")
            ),
        )
    }
}

/// Report guardrail status and flag unknown `[policy] disabled` names.
pub fn check_guardrail(
    guardrail: bool,
    disabled: &[String],
    user_rule_count: usize,
    known: &[&str],
) -> Check {
    if !guardrail {
        return Check::new(
            "guardrail",
            Status::Warn,
            "off — dangerous-command gating disabled ([security] guardrail = false)",
        );
    }
    let unknown: Vec<&str> = disabled
        .iter()
        .filter(|d| !known.contains(&d.as_str()))
        .map(|d| d.as_str())
        .collect();
    if unknown.is_empty() {
        Check::new(
            "guardrail",
            Status::Ok,
            format!(
                "on — {} built-in rule(s), {} disabled, {} user rule(s)",
                known.len(),
                disabled.len(),
                user_rule_count
            ),
        )
    } else {
        Check::new(
            "guardrail",
            Status::Warn,
            format!(
                "on, but unknown name(s) in [policy] disabled: {} — valid: {}",
                unknown.join(", "),
                known.join(", ")
            ),
        )
    }
}

/// Report whether the Claude Code PreToolUse hook is installed. A missing or
/// hook-less settings file is a Warn (Vallum still works when invoked
/// directly); malformed JSON is a Fail.
pub fn check_hook(settings_path: &Path) -> Check {
    match crate::install_hook::read_settings(settings_path) {
        Ok(settings) => {
            if crate::install_hook::has_vallum_hook(&settings) {
                Check::new(
                    "hook (claude)",
                    Status::Ok,
                    format!("installed in {}", settings_path.display()),
                )
            } else {
                Check::new(
                    "hook (claude)",
                    Status::Warn,
                    format!(
                        "not installed in {} — run `vallum install-hook`",
                        settings_path.display()
                    ),
                )
            }
        }
        Err(e) => Check::new("hook (claude)", Status::Fail, e),
    }
}

/// Report hook status for one non-Claude agent. An absent agent config dir
/// means the agent itself is not on this machine — Ok/skip, not a warning.
/// Malformed JSON in an existing hooks file is a hard Fail (the hook may
/// silently never fire). `installed_note` qualifies a successful install with
/// an agent-side caveat Vallum cannot verify from here (e.g. Codex's hook
/// trust state).
pub fn check_agent_hook(
    label: &str,
    agent_dir: &Path,
    hooks_path: &Path,
    agent_flag: &str,
    has_hook: fn(&serde_json::Value) -> bool,
    installed_note: Option<&str>,
) -> Check {
    if !agent_dir.exists() {
        return Check::new(label, Status::Ok, "agent not detected — skipped");
    }
    match crate::install_hook::read_settings(hooks_path) {
        Ok(settings) => {
            if has_hook(&settings) {
                let detail = match installed_note {
                    Some(note) => format!("installed in {} — {note}", hooks_path.display()),
                    None => format!("installed in {}", hooks_path.display()),
                };
                Check::new(label, Status::Ok, detail)
            } else {
                Check::new(
                    label,
                    Status::Warn,
                    format!("not installed — run `vallum install-hook --agent {agent_flag}`"),
                )
            }
        }
        Err(e) => Check::new(label, Status::Fail, e),
    }
}

/// Confirm the log directory exists (creating it if needed) and is writable by
/// round-tripping a probe file.
pub fn check_log_dir(dir: &Path) -> Check {
    if let Err(e) = std::fs::create_dir_all(dir) {
        return Check::new(
            "log dir",
            Status::Fail,
            format!("cannot create {}: {e}", dir.display()),
        );
    }
    let probe = dir.join(".vallum-doctor-probe");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Check::new("log dir", Status::Ok, format!("{} writable", dir.display()))
        }
        Err(e) => Check::new(
            "log dir",
            Status::Fail,
            format!("{} not writable: {e}", dir.display()),
        ),
    }
}

/// Look for an executable named `exe` on the given PATH string. The installed
/// hook shells out to `vallum hook`, so a `vallum` binary that is not on PATH
/// means the hook would fail to run.
pub fn check_binary_on_path(path_var: &str, exe: &str) -> Check {
    let found = path_var
        .split(path_separator())
        .filter(|p| !p.is_empty())
        .map(|dir| Path::new(dir).join(exe))
        .find(|candidate| candidate.is_file());
    match found {
        Some(p) => Check::new(
            "binary",
            Status::Ok,
            format!("{} on PATH ({})", exe, p.display()),
        ),
        None => Check::new(
            "binary",
            Status::Warn,
            format!("`{exe}` not found on PATH — the Claude Code hook needs it there"),
        ),
    }
}

#[cfg(windows)]
fn path_separator() -> char {
    ';'
}

#[cfg(not(windows))]
fn path_separator() -> char {
    ':'
}

/// Resolve the effective log directory: explicit override, else ~/.vallum/logs.
fn resolve_log_dir(cfg: &AppConfig) -> PathBuf {
    cfg.audit
        .log_dir
        .clone()
        .unwrap_or_else(|| match dirs::home_dir() {
            Some(h) => h.join(".vallum").join("logs"),
            None => PathBuf::from("vallum-logs"),
        })
}

/// Render a report to a string. Returns the text and `true` if any check failed.
pub fn render(checks: &[Check]) -> (String, bool) {
    let mut out = String::from("Vallum — install check\n");
    out.push_str("─────────────────────────────────────────\n");
    let mut any_fail = false;
    for c in checks {
        if c.status == Status::Fail {
            any_fail = true;
        }
        out.push_str(&format!(
            "{} {:<16} {}\n",
            c.status.glyph(),
            c.name,
            c.detail
        ));
    }
    (out, any_fail)
}

/// Gather every check against the real environment, print the report, and
/// return the process exit code (0 unless a check hard-failed).
pub fn run() -> i32 {
    let config_path = crate::config::config_path_from_env_or_default();
    let config = AppConfig::from_path(&config_path).unwrap_or_default();

    let settings_path = crate::install_hook::settings_path(crate::install_hook::Level::User)
        .unwrap_or_else(|_| PathBuf::from(".claude/settings.json"));

    let path_var = std::env::var("PATH").unwrap_or_default();
    let exe = if cfg!(windows) {
        "vallum.exe"
    } else {
        "vallum"
    };

    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let checks = vec![
        check_config(&config_path),
        check_optimizer_names(&config.optimizer.disabled, &crate::optimizer::names()),
        check_guardrail(
            config.security.guardrail,
            &config.policy.disabled,
            config.policy.rules.len(),
            &crate::policy::builtin_names(),
        ),
        check_hook(&settings_path),
        check_agent_hook(
            "hook (cursor)",
            &home.join(".cursor"),
            &home.join(".cursor").join("hooks.json"),
            "cursor",
            crate::install_hook::cursor::has_hook,
            None,
        ),
        check_agent_hook(
            "hook (gemini)",
            &home.join(".gemini"),
            &home.join(".gemini").join("settings.json"),
            "gemini",
            crate::install_hook::gemini::has_hook,
            None,
        ),
        check_agent_hook(
            "hook (codex)",
            &home.join(".codex"),
            &home.join(".codex").join("hooks.json"),
            "codex",
            crate::install_hook::codex::has_hook,
            Some("requires one-time trust in Codex; until trusted, Codex silently skips it (needs codex >= 0.141)"),
        ),
        check_binary_on_path(&path_var, exe),
        check_log_dir(&resolve_log_dir(&config)),
    ];

    let (report, any_fail) = render(&checks);
    print!("{report}");
    if any_fail {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "vallum_doctor_{}_{}",
            tag,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn config_missing_is_ok() {
        let c = check_config(Path::new("/no/such/vallum/config.toml"));
        assert_eq!(c.status, Status::Ok);
        assert!(c.detail.contains("defaults"));
    }

    #[test]
    fn config_broken_is_fail() {
        let dir = temp_dir("badcfg");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[scrubber]\nextra_secret_patterns = [ { pattern = \"(\", replacement = \"x\" } ]\n",
        )
        .unwrap();
        let c = check_config(&path);
        assert_eq!(c.status, Status::Fail);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn optimizer_names_ok_and_warn() {
        let known = ["npm", "docker", "kubectl"];
        let ok = check_optimizer_names(&["npm".to_string()], &known);
        assert_eq!(ok.status, Status::Ok);

        let warn = check_optimizer_names(&["nope".to_string()], &known);
        assert_eq!(warn.status, Status::Warn);
        assert!(warn.detail.contains("nope"));
    }

    #[test]
    fn hook_states() {
        let dir = temp_dir("hook");
        // Missing file → Warn.
        let missing = dir.join("settings.json");
        assert_eq!(check_hook(&missing).status, Status::Warn);

        // Installed → Ok.
        std::fs::write(
            &missing,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"vallum hook"}]}]}}"#,
        )
        .unwrap();
        assert_eq!(check_hook(&missing).status, Status::Ok);

        // Malformed → Fail.
        std::fs::write(&missing, "{not json").unwrap();
        assert_eq!(check_hook(&missing).status, Status::Fail);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_dir_writable_is_ok() {
        let dir = temp_dir("logdir");
        let c = check_log_dir(&dir.join("logs"));
        assert_eq!(c.status, Status::Ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn binary_on_path_found_and_missing() {
        let dir = temp_dir("bin");
        let exe = dir.join("vallum");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        let found = check_binary_on_path(dir.to_str().unwrap(), "vallum");
        assert_eq!(found.status, Status::Ok);

        let missing = check_binary_on_path("/nonexistent-doctor-dir", "vallum");
        assert_eq!(missing.status, Status::Warn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_flags_failure_and_lists_all() {
        let checks = vec![
            Check::new("a", Status::Ok, "fine"),
            Check::new("b", Status::Fail, "broken"),
        ];
        let (text, any_fail) = render(&checks);
        assert!(any_fail);
        assert!(text.contains("a"));
        assert!(text.contains("b"));
        assert!(text.contains("broken"));
    }

    #[test]
    fn render_no_failure_when_all_ok_or_warn() {
        let checks = vec![
            Check::new("a", Status::Ok, "fine"),
            Check::new("b", Status::Warn, "heads up"),
        ];
        let (_text, any_fail) = render(&checks);
        assert!(!any_fail);
    }

    #[test]
    fn guardrail_on_reports_ok() {
        let c = check_guardrail(true, &[], 0, &["rm_rf_root"]);
        assert_eq!(c.status, Status::Ok);
        assert!(c.detail.contains("on"));
    }

    #[test]
    fn guardrail_off_warns() {
        let c = check_guardrail(false, &[], 0, &["rm_rf_root"]);
        assert_eq!(c.status, Status::Warn);
    }

    #[test]
    fn unknown_disabled_name_warns() {
        let c = check_guardrail(true, &["nope".to_string()], 0, &["rm_rf_root"]);
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("nope"));
    }

    fn vallum_cursor_has_hook(v: &serde_json::Value) -> bool {
        crate::install_hook::cursor::has_hook(v)
    }

    #[test]
    fn agent_hook_absent_agent_dir_is_ok_skip() {
        let dir = temp_dir("noagent");
        let c = check_agent_hook(
            "hook (cursor)",
            &dir.join("no-such-agent-dir"),
            &dir.join("no-such-agent-dir/hooks.json"),
            "cursor",
            vallum_cursor_has_hook,
            None,
        );
        assert_eq!(c.status, Status::Ok);
        assert!(c.detail.contains("not detected"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_hook_states() {
        let dir = temp_dir("agenthook");
        let agent_dir = dir.join(".cursor");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let hooks = agent_dir.join("hooks.json");

        // Agent present, hook missing → Warn with the install command.
        let c = check_agent_hook(
            "hook (cursor)",
            &agent_dir,
            &hooks,
            "cursor",
            vallum_cursor_has_hook,
            None,
        );
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("vallum install-hook --agent cursor"));

        // Installed → Ok.
        std::fs::write(
            &hooks,
            r#"{"version":1,"hooks":{"beforeShellExecution":[{"command":"vallum hook --agent cursor"}]}}"#,
        )
        .unwrap();
        let c = check_agent_hook(
            "hook (cursor)",
            &agent_dir,
            &hooks,
            "cursor",
            vallum_cursor_has_hook,
            None,
        );
        assert_eq!(c.status, Status::Ok);

        // Malformed → Fail.
        std::fs::write(&hooks, "{not json").unwrap();
        let c = check_agent_hook(
            "hook (cursor)",
            &agent_dir,
            &hooks,
            "cursor",
            vallum_cursor_has_hook,
            None,
        );
        assert_eq!(c.status, Status::Fail);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_hook_installed_note_is_appended_only_when_installed() {
        let dir = temp_dir("agenthooknote");
        let agent_dir = dir.join(".codex");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let hooks = agent_dir.join("hooks.json");

        // Not installed → Warn, note absent (it only qualifies an install).
        let c = check_agent_hook(
            "hook (codex)",
            &agent_dir,
            &hooks,
            "codex",
            crate::install_hook::codex::has_hook,
            Some("requires one-time trust in Codex"),
        );
        assert_eq!(c.status, Status::Warn);
        assert!(!c.detail.contains("one-time trust"));

        // Installed → Ok, note appended after the path.
        std::fs::write(
            &hooks,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"vallum hook --agent codex"}]}]}}"#,
        )
        .unwrap();
        let c = check_agent_hook(
            "hook (codex)",
            &agent_dir,
            &hooks,
            "codex",
            crate::install_hook::codex::has_hook,
            Some("requires one-time trust in Codex"),
        );
        assert_eq!(c.status, Status::Ok);
        assert!(c.detail.contains("installed in"));
        assert!(c.detail.contains("requires one-time trust in Codex"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
