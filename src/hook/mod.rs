//! Pre-exec guardrail hooks: shared Allow/Ask/Deny decision core plus
//! per-agent stdin/stdout protocol codecs.

pub mod claude;

use crate::config::AppConfig;
use crate::policy::{Policy, PolicyAction};
use std::io::Read;

/// First-word skip list. Commands whose head matches one of these are passed
/// through unchanged because Vallum's executor captures stdout and would break
/// the interactive TTY they need.
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

/// Shared pass-through gates (empty command, TUI skip list, `vallum` head)
/// plus policy evaluation. Every codec funnels through here.
pub fn decide(command: &str, policy: Option<&Policy>) -> Verdict {
    let trimmed = command.trim_start();
    if trimmed.is_empty() {
        return Verdict::PassThrough;
    }
    let head = trimmed.split_whitespace().next().unwrap_or("");
    if TUI_SKIP.contains(&head) || head == "vallum" {
        return Verdict::PassThrough;
    }
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
    Verdict::Allow
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
                assert!(reason.contains("root or home"));
                assert_eq!(rule_name, "rm_rf_root");
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn decide_without_policy_allows() {
        assert_eq!(decide("rm -rf /", None), Verdict::Allow);
    }
}
