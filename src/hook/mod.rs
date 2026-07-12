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

/// Shared pass-through gates (empty command, `vallum` head) plus policy
/// evaluation; TUI-headed commands are evaluated but never rewritten.
/// Every codec funnels through here.
pub fn decide(command: &str, policy: Option<&Policy>) -> Verdict {
    let trimmed = command.trim_start();
    if trimmed.is_empty() {
        return Verdict::PassThrough;
    }
    let head = trimmed.split_whitespace().next().unwrap_or("");
    if head == "vallum" {
        return Verdict::PassThrough;
    }
    // TUI-headed commands ARE evaluated (a `less /etc/shadow` must be able to
    // ask/deny); the TUI list only suppresses the rewrite on a clean Allow,
    // because wrapping these commands in the output-capturing executor would
    // break the interactive TTY they need.
    let is_tui = TUI_SKIP.contains(&head);
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
            } else if head == "vallum" {
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
            disabled: vec![],
        })
        .unwrap();
        match decide("less /prod/secrets", Some(&p)) {
            Verdict::Deny { reason, .. } => assert!(reason.contains("denied in test")),
            other => panic!("expected Deny, got {other:?}"),
        }
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
