//! Cursor `beforeShellExecution` codec: verdicts only, native ask (P1: an
//! Allow emits nothing so Cursor's own permission flow still runs).

use super::Verdict;
use crate::config::AppConfig;
use crate::policy::{Policy, PolicyAction};
use serde::Deserialize;
use serde::Serialize;

#[derive(Deserialize)]
struct CursorInput {
    #[serde(default)]
    command: String,
}

#[derive(Serialize)]
struct CursorOutput {
    // Field names verified live 2026-07-06: Cursor expects snake_case
    // (user_message/agent_message), not the camelCase in older blog posts.
    permission: &'static str,
    user_message: String,
    agent_message: String,
}

fn decision_json(permission: &'static str, reason: String) -> Option<String> {
    serde_json::to_string(&CursorOutput {
        permission,
        user_message: reason.clone(),
        agent_message: reason,
    })
    .ok()
}

/// stdin JSON → stdout JSON. None means "no decision": emit nothing and let
/// Cursor's normal flow proceed (P1).
pub(crate) fn respond(raw: &str, policy: Option<&Policy>, cfg: &AppConfig) -> Option<String> {
    let input: CursorInput = serde_json::from_str(raw).ok()?;
    match super::gate(&input.command, policy, cfg) {
        Verdict::PassThrough | Verdict::Allow => None,
        Verdict::Ask { reason, rule_name } => {
            super::audit_verdict(
                PolicyAction::Ask,
                reason.clone(),
                rule_name,
                &input.command,
                "cursor",
                cfg,
            );
            decision_json("ask", reason)
        }
        Verdict::Deny { reason, rule_name } => {
            super::audit_verdict(
                PolicyAction::Deny,
                reason.clone(),
                rule_name,
                &input.command,
                "cursor",
                cfg,
            );
            decision_json("deny", reason)
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
            "vallum_cursor_codec_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut c = AppConfig::default();
        c.audit.sanitized_enabled = false; // unit tests must not write policy.log
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
            disabled: vec![],
        })
        .unwrap()
    }

    #[test]
    fn allow_emits_nothing() {
        // P1: no objection ⇒ no decision — Cursor's own approval flow proceeds.
        let out = respond(
            r#"{"command":"git status"}"#,
            Some(&guardrail()),
            &cfg_no_log(),
        );
        assert_eq!(out, None);
    }

    #[test]
    fn ask_maps_to_native_ask() {
        let out = respond(
            r#"{"command":"rm -rf /"}"#,
            Some(&guardrail()),
            &cfg_no_log(),
        )
        .expect("ask must emit a decision");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["permission"], "ask");
        assert!(v["user_message"].as_str().unwrap().contains("force-delete"));
        assert!(v["agent_message"]
            .as_str()
            .unwrap()
            .contains("force-delete"));
    }

    #[test]
    fn deny_maps_to_deny() {
        let out = respond(
            r#"{"command":"echo SECRETDROP"}"#,
            Some(&deny_policy()),
            &cfg_no_log(),
        )
        .expect("deny must emit a decision");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["permission"], "deny");
        assert!(v["user_message"]
            .as_str()
            .unwrap()
            .contains("denied in test"));
    }

    #[test]
    fn malformed_missing_and_tui_emit_nothing() {
        assert_eq!(
            respond("{not json", Some(&guardrail()), &cfg_no_log()),
            None
        );
        assert_eq!(respond("{}", Some(&guardrail()), &cfg_no_log()), None);
        assert_eq!(
            respond(
                r#"{"command":"vim /etc/passwd"}"#,
                Some(&guardrail()),
                &cfg_no_log()
            ),
            None
        );
    }

    #[test]
    fn guardrail_off_emits_nothing() {
        assert_eq!(
            respond(r#"{"command":"rm -rf /"}"#, None, &cfg_no_log()),
            None
        );
    }
}
