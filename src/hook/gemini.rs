//! Gemini CLI `BeforeTool` codec: verdicts only. No native ask exists, so an
//! Ask verdict fails closed as an actionable deny (P2) — "no decision" would
//! silently become Allow under YOLO mode.

use super::Verdict;
use crate::config::AppConfig;
use crate::policy::{Policy, PolicyAction};
use serde::Deserialize;
use serde::Serialize;

#[derive(Deserialize)]
struct GeminiInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: GeminiToolInput,
}

#[derive(Deserialize, Default)]
struct GeminiToolInput {
    #[serde(default)]
    command: String,
}

#[derive(Serialize)]
struct GeminiOutput {
    decision: &'static str,
    reason: String,
    #[serde(rename = "systemMessage")]
    system_message: String,
}

fn deny_json(reason: String) -> Option<String> {
    serde_json::to_string(&GeminiOutput {
        decision: "deny",
        system_message: reason.clone(),
        reason,
    })
    .ok()
}

/// stdin JSON → stdout JSON. None means "no decision" (P1).
pub(crate) fn respond(raw: &str, policy: Option<&Policy>, cfg: &AppConfig) -> Option<String> {
    let input: GeminiInput = serde_json::from_str(raw).ok()?;
    if input.tool_name != "run_shell_command" {
        return None;
    }
    let command = &input.tool_input.command;
    match super::decide(command, policy) {
        Verdict::PassThrough | Verdict::Allow => None,
        Verdict::Ask { reason, rule_name } => {
            let msg = super::fail_closed_ask_message(&reason, &rule_name, command);
            super::audit_verdict(PolicyAction::Ask, reason, rule_name, command, "gemini", cfg);
            deny_json(msg)
        }
        Verdict::Deny { reason, rule_name } => {
            super::audit_verdict(
                PolicyAction::Deny,
                reason.clone(),
                rule_name,
                command,
                "gemini",
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
        let mut c = AppConfig::default();
        c.audit.sanitized_enabled = false;
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
            disabled: vec![],
        })
        .unwrap()
    }

    #[test]
    fn allow_emits_nothing() {
        let out = respond(
            r#"{"tool_name":"run_shell_command","tool_input":{"command":"git status"}}"#,
            Some(&guardrail()),
            &cfg_no_log(),
        );
        assert_eq!(out, None);
    }

    #[test]
    fn non_shell_tool_emits_nothing() {
        let out = respond(
            r#"{"tool_name":"write_file","tool_input":{"command":"rm -rf /"}}"#,
            Some(&guardrail()),
            &cfg_no_log(),
        );
        assert_eq!(out, None);
    }

    #[test]
    fn ask_fails_closed_with_actionable_deny() {
        // P2: no native ask — deny, and tell the user the way through.
        let out = respond(
            r#"{"tool_name":"run_shell_command","tool_input":{"command":"rm -rf /"}}"#,
            Some(&guardrail()),
            &cfg_no_log(),
        )
        .expect("ask must fail closed");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "deny");
        let reason = v["reason"].as_str().unwrap();
        assert!(reason.contains("Vallum guardrail:"));
        assert!(reason.contains("vallum run -- rm -rf /"));
        assert!(reason.contains("[policy] disabled = [\"rm_rf_root\"]"));
    }

    #[test]
    fn deny_maps_to_deny() {
        let out = respond(
            r#"{"tool_name":"run_shell_command","tool_input":{"command":"echo SECRETDROP"}}"#,
            Some(&deny_policy()),
            &cfg_no_log(),
        )
        .expect("deny must emit a decision");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "deny");
        assert!(v["reason"].as_str().unwrap().contains("denied in test"));
    }

    #[test]
    fn malformed_and_tui_emit_nothing() {
        assert_eq!(
            respond("{not json", Some(&guardrail()), &cfg_no_log()),
            None
        );
        assert_eq!(
            respond(
                r#"{"tool_name":"run_shell_command","tool_input":{"command":"vim x"}}"#,
                Some(&guardrail()),
                &cfg_no_log()
            ),
            None
        );
    }
}
