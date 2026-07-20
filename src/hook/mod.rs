//! Pre-exec guardrail hooks: shared Allow/Ask/Deny decision core plus
//! per-agent stdin/stdout protocol codecs.

pub mod claude;
pub mod codex;
pub mod cursor;
pub mod gemini;

use crate::config::AppConfig;
use crate::policy::{Policy, PolicyAction};
use std::io::Read;

/// First-word list of interactive TUI commands. These ARE policy-evaluated,
/// but a clean Allow becomes PassThrough instead of a rewrite: Vallum's
/// executor captures stdout and would break the interactive TTY they need.
pub(crate) const TUI_SKIP: &[&str] = &[
    "vim", "vi", "nano", "less", "more", "top", "htop", "tmux", "screen",
];

/// Agent-neutral policy verdict for one command line.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Not our concern — let the agent's normal flow proceed (emit nothing).
    PassThrough,
    /// Vallum has no objection.
    Allow,
    /// Policy wants explicit user confirmation.
    Ask { reason: String, rule_name: String },
    /// Policy refuses the command.
    Deny { reason: String, rule_name: String },
}

/// `NAME=value` shell-prefix assignment (also what `env` takes as args).
fn is_env_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// The word TUI detection keys on: the first word after leading `NAME=value`
/// assignments and `sudo`/`doas`/`env` wrappers (with their flags). Without
/// this, `sudo vim x` or `env LESS= less x` would be rewritten into the
/// output-capturing executor and break the interactive TTY the command needs.
/// Wrapper flags that take a separate value (`sudo -u alice`, `env -u NAME`)
/// consume the next word; anything more exotic falls through to the wrapped
/// (non-TUI) path, which is the pre-existing behavior.
fn tui_head(trimmed: &str) -> Option<&str> {
    let mut words = trimmed.split_whitespace().peekable();
    while let Some(w) = words.next() {
        if is_env_assignment(w) {
            continue;
        }
        match w {
            "sudo" | "doas" | "env" => {
                while let Some(f) = words.peek().copied() {
                    if !f.starts_with('-') {
                        break;
                    }
                    words.next();
                    if matches!(f, "-u" | "-g" | "--unset") {
                        words.next();
                    }
                }
            }
            _ => return Some(w),
        }
    }
    None
}

/// True when the command's first word is the Vallum binary itself: the
/// literal `vallum` (PATH-resolved), or a path that canonicalizes to the
/// same executable running this process (`/usr/bin/vallum`, a Homebrew
/// symlink, …). A file that merely *shares the name* — `./vallum`, a decoy
/// `/tmp/x/vallum` — stays gated: pass-through skips the guardrail, so it
/// must never be grantable by naming alone.
fn is_vallum_head(head: &str) -> bool {
    if head == "vallum" {
        return true;
    }
    if !head.contains('/') {
        return false;
    }
    match (
        std::fs::canonicalize(head),
        std::env::current_exe().and_then(std::fs::canonicalize),
    ) {
        (Ok(h), Ok(me)) => h == me,
        _ => false,
    }
}

/// Shared pass-through gates (empty command, Vallum-binary head) plus policy
/// evaluation; TUI-headed commands are evaluated but never rewritten.
/// Every codec funnels through here.
pub fn decide(command: &str, policy: Option<&Policy>) -> Verdict {
    let trimmed = command.trim_start();
    if trimmed.is_empty() {
        return Verdict::PassThrough;
    }
    let head = trimmed.split_whitespace().next().unwrap_or("");
    if is_vallum_head(head) {
        // Self-protection carve-out: the blanket pass-through must not cover
        // the subcommands that disable Vallum itself. Everything else stays
        // pass-through (`vallum run` re-gates in the child; scan/stats/doctor
        // are read-only).
        let sub = trimmed
            .split_whitespace()
            .skip(1)
            .find(|w| !w.starts_with('-'));
        if let Some(sub) = sub {
            if sub == "unlock" || sub == "uninstall-hook" {
                return Verdict::Ask {
                    reason: "Clearing Vallum's lockdown or uninstalling its hook \
                             (guardrail self-disable)"
                        .to_string(),
                    rule_name: "vallum_self_disable".to_string(),
                };
            }
        }
        return Verdict::PassThrough;
    }
    // TUI-headed commands ARE evaluated (a `less /etc/shadow` must be able to
    // ask/deny); the TUI list only suppresses the rewrite on a clean Allow,
    // because wrapping these commands in the output-capturing executor would
    // break the interactive TTY they need. Detection looks through leading
    // assignments and sudo/doas/env wrappers (`sudo vim x` is vim-headed).
    let is_tui = tui_head(trimmed).is_some_and(|h| TUI_SKIP.contains(&h));
    if let Some(p) = policy {
        let v = p.evaluate(command);
        match v.action {
            PolicyAction::Deny => {
                return Verdict::Deny {
                    reason: v.reason,
                    rule_name: v.rule_name,
                }
            }
            PolicyAction::Ask => {
                return Verdict::Ask {
                    reason: v.reason,
                    rule_name: v.rule_name,
                }
            }
            PolicyAction::Allow => {}
        }
    }
    if is_tui {
        Verdict::PassThrough
    } else {
        Verdict::Allow
    }
}

/// The breaker-aware funnel every enforcement point calls. Order matters:
/// empty and `vallum`-headed commands pass through BEFORE the trip check so
/// `vallum unlock` stays reachable while locked (the pass-through only
/// skips the rewrite — the executed binary is Vallum itself, and a wrapped
/// `vallum run` re-enters this gate in the child process).
pub fn gate(command: &str, policy: Option<&Policy>, cfg: &AppConfig) -> Verdict {
    let trimmed = command.trim_start();
    let head = trimmed.split_whitespace().next().unwrap_or("");
    if trimmed.is_empty() || is_vallum_head(head) {
        return decide(command, policy);
    }
    if let Some(trip) = crate::breaker::active_trip(cfg) {
        return Verdict::Deny {
            reason: crate::breaker::trip_reason(&trip),
            rule_name: "circuit_breaker".to_string(),
        };
    }
    let verdict = decide(command, policy);
    if matches!(verdict, Verdict::Ask { .. } | Verdict::Deny { .. }) {
        crate::breaker::record_and_check(cfg);
    }
    verdict
}

/// Read all of stdin. None on read error — codecs exit 0 silently.
pub(crate) fn read_stdin() -> Option<String> {
    let mut buf = String::new();
    std::io::stdin().lock().read_to_string(&mut buf).ok()?;
    Some(buf)
}

/// Load config and compile the policy under the hook's fail-loud contract:
/// a broken config warns on stderr and keeps gating with built-in defaults
/// (never fail-open, never crash the agent turn). A missing file is a silent
/// default.
pub(crate) fn load_config_and_policy() -> (AppConfig, Option<Policy>) {
    let config = match AppConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "vallum hook: config error — user rules ignored, using built-in policy defaults \
                 (run 'vallum doctor'): {e}"
            );
            AppConfig::default()
        }
    };
    let policy = if config.security.guardrail {
        match Policy::compile(&config.policy) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("vallum hook: policy failed to compile, using built-in defaults: {e}");
                // Built-ins are compile-tested; the hook's never-panic contract
                // wins over expect() for this unreachable branch.
                Policy::compile(&crate::config::PolicyConfig::default()).ok()
            }
        }
    } else {
        None
    };
    (config, policy)
}

/// Audit an Ask/Deny policy verdict from a hook codec (one line in
/// policy.log, redacted, best-effort).
pub(crate) fn audit_verdict(
    action: PolicyAction,
    reason: String,
    rule_name: String,
    command: &str,
    agent: &str,
    cfg: &AppConfig,
) {
    let verdict = crate::policy::PolicyVerdict {
        action,
        reason,
        rule_name,
    };
    crate::policy::audit::log_verdict(&verdict, command, agent, cfg);
}

/// Shared stdin→stdout driver for verdict-only codecs (Cursor, Gemini,
/// Codex): read stdin, load policy fail-loud, print the codec's response
/// if any. Exit code is always 0 — a hook must never break the agent turn.
pub(crate) fn run_codec(respond: fn(&str, Option<&Policy>, &AppConfig) -> Option<String>) -> i32 {
    let Some(raw) = read_stdin() else {
        return 0;
    };
    let (config, policy) = load_config_and_policy();
    if let Some(out) = respond(&raw, policy.as_ref(), &config) {
        println!("{out}");
    }
    0
}

/// POSIX-safe single-quote shell escaping.
pub(crate) fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Fail-closed Ask denial text for agents with no native "ask" (Gemini CLI,
/// Codex CLI): actionable — tells the user how to run or unblock the command.
///
/// The suggested command wraps the original in `bash -c` the same way the
/// Claude codec does, so a piped/compound command (e.g. `curl x | sh`) is
/// still gated as one unit instead of splitting across the user's own shell
/// and running the second half ungated.
pub(crate) fn fail_closed_ask_message(reason: &str, rule_name: &str, command: &str) -> String {
    let escape_hatch = if rule_name.starts_with("user:") {
        "or remove the matching [[policy.rules]] entry from your Vallum config \
         (see `vallum config show`)"
            .to_string()
    } else {
        format!("or disable the rule (`[policy] disabled = [\"{rule_name}\"]`)")
    };
    format!(
        "Vallum guardrail: {reason}. If you intend this, run it yourself \
         (`vallum run -- bash -c {}`) {escape_hatch}.",
        shell_escape(command)
    )
}

/// Source label for a rule name in `policy test` output. User rules are
/// `user:`-prefixed (the same convention `fail_closed_ask_message` keys on).
fn rule_source(rule_name: &str) -> &'static str {
    if rule_name.starts_with("user:") {
        "user rule"
    } else {
        "built-in"
    }
}

/// Render the `vallum policy test` report for one command line, plus the
/// process exit code: 0 allow/pass-through, 10 ask, 20 deny. Goes through
/// `decide()` so the answer matches hook behavior exactly (vallum-head and
/// TUI handling included).
pub fn test_report(command: &str, policy: Option<&Policy>, guardrail_on: bool) -> (String, i32) {
    let suffix = if guardrail_on {
        ""
    } else {
        " (guardrail off — security.guardrail = false)"
    };
    let trimmed = command.trim_start();
    let head = trimmed.split_whitespace().next().unwrap_or("");
    match decide(command, policy) {
        Verdict::PassThrough => {
            let label = if trimmed.is_empty() {
                "PASS-THROUGH (empty command)"
            } else if is_vallum_head(head) {
                "PASS-THROUGH (vallum wrapper command)"
            } else {
                "PASS-THROUGH (TUI command, no policy objection)"
            };
            (format!("{label}{suffix}\n"), 0)
        }
        Verdict::Allow => (format!("ALLOW{suffix}\n"), 0),
        Verdict::Ask { reason, rule_name } => (
            format!(
                "ASK [{rule_name}] ({})\n  {reason}\n",
                rule_source(&rule_name)
            ),
            10,
        ),
        Verdict::Deny { reason, rule_name } => (
            format!(
                "DENY [{rule_name}] ({})\n  {reason}\n",
                rule_source(&rule_name)
            ),
            20,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyConfig;

    fn guardrail() -> Policy {
        Policy::compile(&PolicyConfig::default()).unwrap()
    }

    /// Cfg whose breaker state lives in an isolated temp dir.
    fn breaker_cfg(tag: &str) -> (AppConfig, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "vallum_gate_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = AppConfig::default();
        cfg.audit.log_dir = Some(dir.clone());
        (cfg, dir)
    }

    fn lock_now(dir: &std::path::Path) {
        let until = (chrono::Local::now() + chrono::Duration::seconds(300)).to_rfc3339();
        std::fs::write(dir.join("breaker.state"), format!("locked {until}\n")).unwrap();
    }

    #[test]
    fn gate_denies_everything_while_tripped() {
        let (cfg, dir) = breaker_cfg("deny_all");
        lock_now(&dir);
        match gate("git status", Some(&guardrail()), &cfg) {
            Verdict::Deny { rule_name, reason } => {
                assert_eq!(rule_name, "circuit_breaker");
                assert!(reason.contains("vallum unlock"), "{reason}");
            }
            other => panic!("expected breaker deny, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_passes_vallum_and_empty_through_while_tripped() {
        let (cfg, dir) = breaker_cfg("passthrough");
        lock_now(&dir);
        // `vallum unlock` still bypasses the breaker (stays reachable while
        // locked) but now surfaces as the self-disable Ask instead of a silent
        // pass-through — the user confirms, and the unwrapped binary runs.
        match gate("vallum unlock", Some(&guardrail()), &cfg) {
            Verdict::Ask { rule_name, .. } => assert_eq!(rule_name, "vallum_self_disable"),
            other => panic!("expected self-disable Ask, got {other:?}"),
        }
        // Other vallum subcommands and empty commands still pass straight
        // through, breaker or not.
        assert_eq!(
            gate("vallum run ls", Some(&guardrail()), &cfg),
            Verdict::PassThrough
        );
        assert_eq!(gate("   ", Some(&guardrail()), &cfg), Verdict::PassThrough);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_records_ask_verdicts_and_trips_at_threshold() {
        let (mut cfg, dir) = breaker_cfg("records");
        cfg.security.breaker_threshold = 3;
        // 3 Ask verdicts: each returned unchanged; the 3rd writes the lock.
        for _ in 0..3 {
            match gate("rm -rf /", Some(&guardrail()), &cfg) {
                Verdict::Ask { .. } => {}
                other => panic!("expected Ask, got {other:?}"),
            }
        }
        // Next command — benign — is now denied.
        match gate("git status", Some(&guardrail()), &cfg) {
            Verdict::Deny { rule_name, .. } => assert_eq!(rule_name, "circuit_breaker"),
            other => panic!("expected breaker deny, got {other:?}"),
        }
        // The trip is in policy.log for forensics.
        let log = std::fs::read_to_string(dir.join("policy.log")).unwrap();
        assert!(log.contains("circuit_breaker"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_allow_verdicts_never_count() {
        let (mut cfg, dir) = breaker_cfg("allow_free");
        cfg.security.breaker_threshold = 1;
        for _ in 0..5 {
            assert_eq!(gate("git status", Some(&guardrail()), &cfg), Verdict::Allow);
        }
        assert!(!dir.join("breaker.state").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_disabled_breaker_is_inert() {
        let (mut cfg, dir) = breaker_cfg("disabled");
        cfg.security.circuit_breaker = false;
        lock_now(&dir);
        assert_eq!(gate("git status", Some(&guardrail()), &cfg), Verdict::Allow);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decide_gates_empty_tui_and_vallum_head() {
        assert_eq!(decide("", Some(&guardrail())), Verdict::PassThrough);
        assert_eq!(decide("   ", Some(&guardrail())), Verdict::PassThrough);
        assert_eq!(
            decide("vim /etc/passwd", Some(&guardrail())),
            Verdict::PassThrough
        );
        assert_eq!(
            decide("vallum run ls", Some(&guardrail())),
            Verdict::PassThrough
        );
    }

    /// Temp dir holding a file named `vallum`: either a symlink to THIS
    /// running executable (the only thing that should count as the real
    /// binary) or an unrelated decoy file.
    fn vallum_named_file(tag: &str, link_to_self: bool) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!(
            "vallum_head_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("vallum");
        if link_to_self {
            std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &bin).unwrap();
        } else {
            std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        }
        let head = bin.to_string_lossy().into_owned();
        (dir, head)
    }

    #[test]
    fn path_qualified_real_vallum_passes_through_even_while_tripped() {
        let (bin_dir, head) = vallum_named_file("real", true);
        assert_eq!(
            decide(&format!("{head} run ls"), Some(&guardrail())),
            Verdict::PassThrough
        );
        let (cfg, dir) = breaker_cfg("real_head");
        lock_now(&dir);
        // A path-qualified REAL vallum is recognized as vallum-head, so it
        // bypasses the breaker; `unlock` reaches the user as the self-disable
        // Ask (contrast the decoy below, which the breaker denies).
        match gate(&format!("{head} unlock"), Some(&guardrail()), &cfg) {
            Verdict::Ask { rule_name, .. } => assert_eq!(rule_name, "vallum_self_disable"),
            other => panic!("expected self-disable Ask, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&bin_dir);
    }

    #[test]
    fn path_named_vallum_but_different_file_is_still_gated() {
        let (bin_dir, head) = vallum_named_file("decoy", false);
        assert_eq!(
            decide(&format!("{head} run ls"), Some(&guardrail())),
            Verdict::Allow
        );
        let (cfg, dir) = breaker_cfg("decoy_head");
        lock_now(&dir);
        match gate(&format!("{head} unlock"), Some(&guardrail()), &cfg) {
            Verdict::Deny { rule_name, .. } => assert_eq!(rule_name, "circuit_breaker"),
            other => panic!("expected breaker deny for decoy vallum, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&bin_dir);
    }

    #[test]
    fn nonexistent_vallum_path_is_still_gated() {
        assert_eq!(
            decide("/nonexistent/bin/vallum run ls", Some(&guardrail())),
            Verdict::Allow
        );
    }

    #[test]
    fn decide_maps_policy_verdicts() {
        assert_eq!(decide("git status", Some(&guardrail())), Verdict::Allow);
        match decide("rm -rf /", Some(&guardrail())) {
            Verdict::Ask { reason, rule_name } => {
                assert!(reason.contains("force-delete"));
                assert_eq!(rule_name, "rm_rf_root");
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn decide_without_policy_allows() {
        assert_eq!(decide("rm -rf /", None), Verdict::Allow);
    }

    #[test]
    fn ask_message_names_rule_command_and_escape_hatch() {
        let m = fail_closed_ask_message("force push", "git_push_force", "git push --force");
        assert!(m.contains("Vallum guardrail: force push"));
        assert!(m.contains("vallum run -- bash -c 'git push --force'"));
        assert!(m.contains("[policy] disabled = [\"git_push_force\"]"));
    }

    #[test]
    fn ask_message_user_rule_advises_config_edit() {
        let m = fail_closed_ask_message("denied in test", "user:SECRETDROP", "echo SECRETDROP");
        assert!(!m.contains("[policy] disabled"));
        assert!(m.contains("[[policy.rules]]"));
    }

    #[test]
    fn decide_tui_matching_a_rule_now_asks() {
        match decide("less /etc/shadow", Some(&guardrail())) {
            Verdict::Ask { rule_name, .. } => assert_eq!(rule_name, "read_sensitive_creds"),
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn decide_tui_matching_a_deny_rule_denies() {
        use crate::config::PolicyRuleConfig;
        let p = Policy::compile(&PolicyConfig {
            rules: vec![PolicyRuleConfig {
                pattern: "less /prod/secrets".into(),
                action: "deny".into(),
                reason: "denied in test".into(),
            }],
            allow: vec![],
            disabled: vec![],
        })
        .unwrap();
        match decide("less /prod/secrets", Some(&p)) {
            Verdict::Deny { reason, .. } => assert!(reason.contains("denied in test")),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn decide_wrapped_tui_passes_through() {
        // Wrapper-prefixed TUI commands would break their TTY if rewritten.
        assert_eq!(
            decide("sudo vim /etc/hosts", Some(&guardrail())),
            Verdict::PassThrough
        );
        assert_eq!(
            decide("sudo -u alice vim notes.txt", Some(&guardrail())),
            Verdict::PassThrough
        );
        assert_eq!(
            decide("env LESS= less notes.txt", Some(&guardrail())),
            Verdict::PassThrough
        );
        assert_eq!(
            decide("LESS=-R less notes.txt", Some(&guardrail())),
            Verdict::PassThrough
        );
    }

    #[test]
    fn decide_wrapped_tui_still_policy_gated() {
        match decide("sudo less /etc/shadow", Some(&guardrail())) {
            Verdict::Ask { rule_name, .. } => assert_eq!(rule_name, "read_sensitive_creds"),
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn decide_wrapped_non_tui_stays_wrapped() {
        // `sudo git status` is not TUI-headed; the normal rewrite path applies.
        assert_eq!(
            decide("sudo git status", Some(&guardrail())),
            Verdict::Allow
        );
    }

    #[test]
    fn tui_head_resolves_through_wrappers() {
        assert_eq!(tui_head("vim x"), Some("vim"));
        assert_eq!(tui_head("sudo vim x"), Some("vim"));
        assert_eq!(tui_head("sudo -E -u alice vim x"), Some("vim"));
        assert_eq!(tui_head("env LESS= less x"), Some("less"));
        assert_eq!(tui_head("env -i FOO=1 less x"), Some("less"));
        assert_eq!(tui_head("A=1 B=2 top"), Some("top"));
        // Not an assignment: '=' with a non-identifier prefix is a command word.
        assert_eq!(tui_head("./weird=name x"), Some("./weird=name"));
        assert_eq!(tui_head("sudo"), None);
    }

    #[test]
    fn decide_tui_with_no_objection_still_passes_through() {
        assert_eq!(
            decide("vim notes.txt", Some(&guardrail())),
            Verdict::PassThrough
        );
        // Guardrail off: byte-identical to v0.7.0 — TUI passes through.
        assert_eq!(decide("less /etc/shadow", None), Verdict::PassThrough);
    }

    #[test]
    fn vallum_head_self_disable_asks_other_subcommands_pass() {
        let p = Policy::compile(&crate::config::PolicyConfig::default()).unwrap();
        for cmd in ["vallum unlock", "vallum uninstall-hook --agent codex"] {
            match decide(cmd, Some(&p)) {
                Verdict::Ask { rule_name, .. } => {
                    assert_eq!(rule_name, "vallum_self_disable", "{cmd}")
                }
                other => panic!("{cmd}: expected Ask, got {other:?}"),
            }
        }
        for cmd in ["vallum stats", "vallum run -- ls", "vallum doctor"] {
            assert!(
                matches!(decide(cmd, Some(&p)), Verdict::PassThrough),
                "{cmd}"
            );
        }
    }

    #[test]
    fn test_report_covers_all_verdicts() {
        let g = guardrail();
        let (s, c) = test_report("git status", Some(&g), true);
        assert_eq!((s.as_str(), c), ("ALLOW\n", 0));

        let (s, c) = test_report("rm -rf /", Some(&g), true);
        assert!(s.starts_with("ASK [rm_rf_root] (built-in)\n  "));
        assert_eq!(c, 10);

        use crate::config::PolicyRuleConfig;
        let deny = Policy::compile(&PolicyConfig {
            rules: vec![PolicyRuleConfig {
                pattern: "BLOCKME".into(),
                action: "deny".into(),
                reason: "blocked in test".into(),
            }],
            allow: vec![],
            disabled: vec![],
        })
        .unwrap();
        let (s, c) = test_report("echo BLOCKME", Some(&deny), true);
        assert!(s.starts_with("DENY [user:BLOCKME] (user rule)\n  blocked in test"));
        assert_eq!(c, 20);

        let (s, c) = test_report("vallum run ls", Some(&g), true);
        assert_eq!(
            (s.as_str(), c),
            ("PASS-THROUGH (vallum wrapper command)\n", 0)
        );

        let (s, c) = test_report("vim notes.txt", Some(&g), true);
        assert_eq!(
            (s.as_str(), c),
            ("PASS-THROUGH (TUI command, no policy objection)\n", 0)
        );

        let (s, c) = test_report("rm -rf /", None, false);
        assert_eq!(
            (s.as_str(), c),
            ("ALLOW (guardrail off — security.guardrail = false)\n", 0)
        );
    }
}
