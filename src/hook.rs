//! Claude Code `PreToolUse` hook: rewrite Bash tool calls to run through `vallum run`.

// src/hook.rs — Claude Code PreToolUse hook implementation.
use crate::policy::{Policy, PolicyAction};
use serde::Deserialize;
use serde::Serialize;
use std::io::Read;

#[derive(Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: HookToolInput,
}

#[derive(Deserialize, Default)]
struct HookToolInput {
    #[serde(default)]
    command: String,
}

#[derive(Serialize)]
struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookSpecificOutput,
}

#[derive(Serialize)]
struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'static str,
    #[serde(
        rename = "permissionDecisionReason",
        skip_serializing_if = "Option::is_none"
    )]
    reason: Option<String>,
    #[serde(rename = "updatedInput", skip_serializing_if = "Option::is_none")]
    updated_input: Option<UpdatedInput>,
}

#[derive(Serialize)]
struct UpdatedInput {
    command: String,
}

/// First-word skip list. Commands whose head matches one of these are passed
/// through unchanged because Vallum's executor captures stdout and would break
/// the interactive TTY they need.
const TUI_SKIP: &[&str] = &[
    "vim", "vi", "nano", "less", "more", "top", "htop", "tmux", "screen",
];

/// Result of `rewrite_decision`: what the hook should tell Claude Code to do
/// with this `PreToolUse` invocation.
#[derive(Debug)]
pub enum HookDecision {
    /// Not our concern — let Claude Code's normal flow proceed (emit no JSON).
    PassThrough,
    /// Rewrite to run through vallum, permission "allow".
    Allow { command: String },
    /// Rewrite + ask the user (permission "ask").
    Ask { command: String, reason: String },
    /// Refuse (permission "deny", no rewrite).
    Deny { reason: String },
}

/// Decide whether to rewrite, and whether the pre-exec policy allows, asks
/// about, or denies the command. Policy is evaluated on the ORIGINAL command,
/// before it is wrapped for `vallum run`.
pub fn rewrite_decision(tool_name: &str, command: &str, policy: Option<&Policy>) -> HookDecision {
    if tool_name != "Bash" {
        return HookDecision::PassThrough;
    }
    let trimmed = command.trim_start();
    if trimmed.is_empty() {
        return HookDecision::PassThrough;
    }
    let head = trimmed.split_whitespace().next().unwrap_or("");
    if TUI_SKIP.contains(&head) || head == "vallum" {
        return HookDecision::PassThrough;
    }
    let wrapped = format!("vallum run -- bash -c {}", shell_escape(command));
    if let Some(p) = policy {
        let v = p.evaluate(command);
        match v.action {
            PolicyAction::Deny => return HookDecision::Deny { reason: v.reason },
            PolicyAction::Ask => {
                return HookDecision::Ask {
                    command: wrapped,
                    reason: v.reason,
                }
            }
            PolicyAction::Allow => {}
        }
    }
    HookDecision::Allow { command: wrapped }
}

/// POSIX-safe single-quote shell escaping.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Entry point invoked from main: read stdin JSON, decide, write stdout JSON,
/// return the exit code (always 0 — even malformed input is silently allowed).
pub fn run() -> i32 {
    let mut buf = String::new();
    if std::io::stdin().lock().read_to_string(&mut buf).is_err() {
        return 0;
    }
    let input: HookInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(_) => return 0, // malformed input: allow normal flow
    };

    let config = crate::config::AppConfig::load().unwrap_or_default();
    let policy = if config.security.guardrail {
        Policy::compile(&config.policy).ok()
    } else {
        None
    };

    let decision = rewrite_decision(&input.tool_name, &input.tool_input.command, policy.as_ref());

    let out = match decision {
        HookDecision::PassThrough => return 0,
        HookDecision::Allow { command } => HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: "allow",
            reason: None,
            updated_input: Some(UpdatedInput { command }),
        },
        HookDecision::Ask { command, reason } => {
            let verdict = crate::policy::PolicyVerdict {
                action: PolicyAction::Ask,
                reason: reason.clone(),
                rule_name: String::new(),
            };
            crate::policy::audit::log_verdict(&verdict, &input.tool_input.command, &config);
            HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "ask",
                reason: Some(reason),
                updated_input: Some(UpdatedInput { command }),
            }
        }
        HookDecision::Deny { reason } => {
            let verdict = crate::policy::PolicyVerdict {
                action: PolicyAction::Deny,
                reason: reason.clone(),
                rule_name: String::new(),
            };
            crate::policy::audit::log_verdict(&verdict, &input.tool_input.command, &config);
            HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                reason: Some(reason),
                updated_input: None,
            }
        }
    };

    if let Ok(s) = serde_json::to_string(&HookOutput {
        hook_specific_output: out,
    }) {
        println!("{}", s);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PolicyConfig;
    use crate::policy::Policy;

    fn guardrail() -> Policy {
        Policy::compile(&PolicyConfig::default()).unwrap()
    }

    #[test]
    fn allow_rewrites_plain_command() {
        let d = rewrite_decision("Bash", "git status", Some(&guardrail()));
        match d {
            HookDecision::Allow { command } => {
                assert_eq!(command, "vallum run -- bash -c 'git status'")
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn dangerous_command_asks_with_reason() {
        let d = rewrite_decision("Bash", "rm -rf /", Some(&guardrail()));
        match d {
            HookDecision::Ask { command, reason } => {
                assert_eq!(command, "vallum run -- bash -c 'rm -rf /'");
                assert!(reason.contains("root or home"));
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn guardrail_off_always_allows() {
        let d = rewrite_decision("Bash", "rm -rf /", None);
        match d {
            HookDecision::Allow { command } => {
                assert_eq!(command, "vallum run -- bash -c 'rm -rf /'")
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn non_bash_and_tui_pass_through() {
        assert!(matches!(
            rewrite_decision("Edit", "git status", None),
            HookDecision::PassThrough
        ));
        assert!(matches!(
            rewrite_decision("Bash", "vim foo", Some(&guardrail())),
            HookDecision::PassThrough
        ));
        assert!(matches!(
            rewrite_decision("Bash", "vallum run x", None),
            HookDecision::PassThrough
        ));
        assert!(matches!(
            rewrite_decision("Bash", "", None),
            HookDecision::PassThrough
        ));
    }
}
