//! Claude Code `PreToolUse` codec: rewrite Bash tool calls through `vallum run`.

use super::Verdict;
use crate::config::AppConfig;
use crate::policy::{Policy, PolicyAction};
use serde::Deserialize;
use serde::Serialize;

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

/// Result of `rewrite_decision`: what the hook should tell Claude Code to do
/// with this `PreToolUse` invocation.
#[derive(Debug)]
pub enum HookDecision {
    /// Not our concern — let Claude Code's normal flow proceed (emit no JSON).
    PassThrough,
    /// Rewrite to run through vallum, permission "allow".
    Allow { command: String },
    /// Ask the user (permission "ask"); `command` is the rewrite to apply on
    /// approval, or `None` for TUI-headed commands, which must run unwrapped
    /// to keep their interactive TTY.
    Ask {
        command: Option<String>,
        reason: String,
        rule_name: String,
    },
    /// Refuse (permission "deny", no rewrite).
    Deny { reason: String, rule_name: String },
}

/// Decide whether to rewrite, and whether the pre-exec policy allows, asks
/// about, or denies the command. Policy is evaluated on the ORIGINAL command,
/// before it is wrapped for `vallum run`.
pub fn rewrite_decision(
    tool_name: &str,
    command: &str,
    policy: Option<&Policy>,
    cfg: &AppConfig,
) -> HookDecision {
    if !tool_name.eq_ignore_ascii_case("Bash") {
        return HookDecision::PassThrough;
    }
    // The hook is the single point of policy enforcement in hook mode. The
    // wrapped command carries `--policy-approved` so the inner `vallum run` does
    // NOT re-evaluate the policy — otherwise an approved Ask would be re-gated
    // and (non-interactively) fail closed, and a user rule matching the
    // `bash -c` wrapper could block even Allowed commands.
    let wrapped = format!(
        "vallum run --policy-approved -- bash -c {}",
        super::shell_escape(command)
    );
    match super::gate(command, policy, cfg) {
        Verdict::PassThrough => HookDecision::PassThrough,
        Verdict::Allow => HookDecision::Allow { command: wrapped },
        Verdict::Ask { reason, rule_name } => {
            let head = command.split_whitespace().next().unwrap_or("");
            let rewrite = if super::TUI_SKIP.contains(&head) {
                None
            } else {
                Some(wrapped)
            };
            HookDecision::Ask {
                command: rewrite,
                reason,
                rule_name,
            }
        }
        Verdict::Deny { reason, rule_name } => HookDecision::Deny { reason, rule_name },
    }
}

/// Entry point invoked from main: read stdin JSON, decide, write stdout JSON,
/// return the exit code (always 0 — even malformed input is silently allowed).
pub fn run() -> i32 {
    let Some(buf) = super::read_stdin() else {
        return 0;
    };
    let input: HookInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(_) => return 0, // malformed input: allow normal flow
    };

    let (config, policy) = super::load_config_and_policy();

    let decision = rewrite_decision(
        &input.tool_name,
        &input.tool_input.command,
        policy.as_ref(),
        &config,
    );

    let out = match decision {
        HookDecision::PassThrough => return 0,
        HookDecision::Allow { command } => HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: "allow",
            reason: None,
            updated_input: Some(UpdatedInput { command }),
        },
        HookDecision::Ask {
            command,
            reason,
            rule_name,
        } => {
            super::audit_verdict(
                PolicyAction::Ask,
                reason.clone(),
                rule_name,
                &input.tool_input.command,
                "claude",
                &config,
            );
            HookSpecificOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "ask",
                reason: Some(reason),
                updated_input: command.map(|c| UpdatedInput { command: c }),
            }
        }
        HookDecision::Deny { reason, rule_name } => {
            super::audit_verdict(
                PolicyAction::Deny,
                reason.clone(),
                rule_name,
                &input.tool_input.command,
                "claude",
                &config,
            );
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

    /// Cfg with breaker/audit state isolated to a temp dir (tests must not
    /// touch the developer's real ~/.vallum).
    fn isolated_cfg() -> crate::config::AppConfig {
        let dir = std::env::temp_dir().join(format!(
            "vallum_claude_codec_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = crate::config::AppConfig::default();
        cfg.audit.log_dir = Some(dir);
        cfg
    }

    #[test]
    fn allow_rewrites_plain_command() {
        let d = rewrite_decision("Bash", "git status", Some(&guardrail()), &isolated_cfg());
        match d {
            HookDecision::Allow { command } => {
                assert_eq!(
                    command,
                    "vallum run --policy-approved -- bash -c 'git status'"
                )
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn tool_name_match_is_case_insensitive() {
        // A different casing of the shell tool (e.g. a future rename to `bash`)
        // must still be gated, not silently passed through ungated.
        match rewrite_decision("bash", "rm -rf /", Some(&guardrail()), &isolated_cfg()) {
            HookDecision::Ask { .. } => {}
            other => panic!("expected Ask for lowercase tool name, got {other:?}"),
        }
    }

    #[test]
    fn dangerous_command_asks_with_reason() {
        let d = rewrite_decision("Bash", "rm -rf /", Some(&guardrail()), &isolated_cfg());
        match d {
            HookDecision::Ask {
                command, reason, ..
            } => {
                assert_eq!(
                    command,
                    Some("vallum run --policy-approved -- bash -c 'rm -rf /'".to_string())
                );
                assert!(reason.contains("force-delete"));
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    fn guardrail_with_deny() -> Policy {
        use crate::config::{PolicyConfig, PolicyRuleConfig};
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
    fn denied_command_returns_deny_no_rewrite() {
        let d = rewrite_decision(
            "Bash",
            "echo SECRETDROP",
            Some(&guardrail_with_deny()),
            &isolated_cfg(),
        );
        match d {
            HookDecision::Deny { reason, .. } => assert!(reason.contains("denied in test")),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn guardrail_off_always_allows() {
        let d = rewrite_decision("Bash", "rm -rf /", None, &isolated_cfg());
        match d {
            HookDecision::Allow { command } => {
                assert_eq!(
                    command,
                    "vallum run --policy-approved -- bash -c 'rm -rf /'"
                )
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn non_bash_and_tui_pass_through() {
        assert!(matches!(
            rewrite_decision("Edit", "git status", None, &isolated_cfg()),
            HookDecision::PassThrough
        ));
        assert!(matches!(
            rewrite_decision("Bash", "vim foo", Some(&guardrail()), &isolated_cfg()),
            HookDecision::PassThrough
        ));
        assert!(matches!(
            rewrite_decision("Bash", "vallum run x", None, &isolated_cfg()),
            HookDecision::PassThrough
        ));
        assert!(matches!(
            rewrite_decision("Bash", "", None, &isolated_cfg()),
            HookDecision::PassThrough
        ));
    }

    #[test]
    fn tui_ask_has_no_rewrite() {
        let d = rewrite_decision(
            "Bash",
            "less /etc/shadow",
            Some(&guardrail()),
            &isolated_cfg(),
        );
        match d {
            HookDecision::Ask {
                command, reason, ..
            } => {
                assert_eq!(command, None, "TUI ask must not rewrite (TTY)");
                assert!(reason.contains("shadow") || !reason.is_empty());
            }
            other => panic!("expected Ask, got {other:?}"),
        }
    }

    #[test]
    fn tripped_breaker_denies_benign_command() {
        let cfg = isolated_cfg();
        let dir = cfg.audit.log_dir.clone().unwrap();
        let until = (chrono::Local::now() + chrono::Duration::seconds(300)).to_rfc3339();
        std::fs::write(dir.join("breaker.state"), format!("locked {until}\n")).unwrap();
        match rewrite_decision("Bash", "git status", Some(&guardrail()), &cfg) {
            HookDecision::Deny { rule_name, reason } => {
                assert_eq!(rule_name, "circuit_breaker");
                assert!(reason.contains("vallum unlock"), "{reason}");
            }
            other => panic!("expected deny, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
