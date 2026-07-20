//! Codex CLI `PreToolUse` codec: verdicts only. No native ask, so Ask fails
//! closed as an actionable deny (P2). Upstream caveat: Codex currently
//! intercepts only "simple" shell calls — documented in the README.

use super::Verdict;
use crate::config::AppConfig;
use crate::policy::{Policy, PolicyAction};
use serde::Deserialize;
use serde::Serialize;

/// Shell tool names Codex reports for command execution. Verified against
/// live docs in the 2026-07-06 protocol research note: Codex uses "Bash".
const SHELL_TOOLS: &[&str] = &["Bash"];

#[derive(Deserialize)]
struct CodexInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: CodexToolInput,
}

#[derive(Deserialize, Default)]
struct CodexToolInput {
    #[serde(default)]
    command: String,
}

#[derive(Serialize)]
struct CodexOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: CodexHso,
}

#[derive(Serialize)]
struct CodexHso {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'static str,
    #[serde(rename = "permissionDecisionReason")]
    reason: String,
}

fn deny_json(reason: String) -> Option<String> {
    serde_json::to_string(&CodexOutput {
        hook_specific_output: CodexHso {
            hook_event_name: "PreToolUse",
            permission_decision: "deny",
            reason,
        },
    })
    .ok()
}

/// stdin JSON → stdout JSON. None means "no decision" (P1).
pub(crate) fn respond(raw: &str, policy: Option<&Policy>, cfg: &AppConfig) -> Option<String> {
    let input: CodexInput = serde_json::from_str(raw).ok()?;
    if !SHELL_TOOLS.contains(&input.tool_name.as_str()) {
        return None;
    }
    let command = &input.tool_input.command;
    match super::gate(command, policy, cfg) {
        Verdict::PassThrough | Verdict::Allow => None,
        Verdict::AllowDowngraded { marker, .. } => {
            crate::policy::audit::log_allow_downgrade(&marker, command, "codex", cfg);
            None
        }
        Verdict::Ask { reason, rule_name } => {
            let msg = super::fail_closed_ask_message(&reason, &rule_name, command);
            super::audit_verdict(PolicyAction::Ask, reason, rule_name, command, "codex", cfg);
            deny_json(msg)
        }
        Verdict::Deny { reason, rule_name } => {
            super::audit_verdict(
                PolicyAction::Deny,
                reason.clone(),
                rule_name,
                command,
                "codex",
                cfg,
            );
            deny_json(reason)
        }
    }
}

pub fn run() -> i32 {
    super::run_codec(respond)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PolicyConfig, PolicyRuleConfig};

    fn cfg_no_log() -> AppConfig {
        // Isolate breaker.state to a temp dir so gate()'s Ask/Deny recording
        // never touches the developer's real ~/.vallum.
        let dir = std::env::temp_dir().join(format!(
            "vallum_codex_codec_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut c = AppConfig::default();
        c.audit.sanitized_enabled = false;
        c.audit.log_dir = Some(dir);
        c
    }

    fn guardrail() -> Policy {
        Policy::compile(&PolicyConfig::default()).unwrap()
    }

    fn deny_policy() -> Policy {
        Policy::compile(&PolicyConfig {
            rules: vec![PolicyRuleConfig {
                pattern: "SECRETDROP".into(),
                action: "deny".into(),
                reason: "denied in test".into(),
            }],
            allow: vec![],
            disabled: vec![],
        })
        .unwrap()
    }

    #[test]
    fn allow_and_non_shell_emit_nothing() {
        assert_eq!(
            respond(
                r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#,
                Some(&guardrail()),
                &cfg_no_log()
            ),
            None
        );
        assert_eq!(
            respond(
                r#"{"tool_name":"apply_patch","tool_input":{"command":"rm -rf /"}}"#,
                Some(&guardrail()),
                &cfg_no_log()
            ),
            None
        );
    }

    #[test]
    fn ask_fails_closed_with_actionable_deny() {
        let out = respond(
            r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
            Some(&guardrail()),
            &cfg_no_log(),
        )
        .expect("ask must fail closed");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(reason.contains("Vallum guardrail:"));
        assert!(reason.contains("vallum run -- bash -c 'rm -rf /'"));
    }

    #[test]
    fn tui_ask_fails_closed_too() {
        let out = respond(
            r#"{"tool_name":"Bash","tool_input":{"command":"less /etc/shadow"}}"#,
            Some(&guardrail()),
            &cfg_no_log(),
        )
        .expect("TUI ask must fail closed");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn deny_maps_to_deny() {
        let out = respond(
            r#"{"tool_name":"Bash","tool_input":{"command":"echo SECRETDROP"}}"#,
            Some(&deny_policy()),
            &cfg_no_log(),
        )
        .expect("deny must emit a decision");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("denied in test"));
    }

    #[test]
    fn malformed_and_tui_emit_nothing() {
        assert_eq!(
            respond("{not json", Some(&guardrail()), &cfg_no_log()),
            None
        );
        assert_eq!(
            respond(
                r#"{"tool_name":"Bash","tool_input":{"command":"vim x"}}"#,
                Some(&guardrail()),
                &cfg_no_log()
            ),
            None
        );
    }

    #[test]
    fn guardrail_off_emits_no_decision() {
        assert_eq!(
            respond(
                r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#,
                None,
                &cfg_no_log()
            ),
            None
        );
    }
}
