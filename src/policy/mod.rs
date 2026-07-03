//! Pre-exec command policy: evaluate a command line against dangerous-command
//! rules and return Allow / Ask / Deny. Plain-text regex matching over one
//! joined command line — no shell parsing (same posture as the scrubber).

use crate::config::PolicyConfig;
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Allow,
    Ask,
    Deny,
}

impl PolicyAction {
    /// Severity rank for "most-severe-wins": Deny(2) > Ask(1) > Allow(0).
    fn severity(self) -> u8 {
        match self {
            PolicyAction::Allow => 0,
            PolicyAction::Ask => 1,
            PolicyAction::Deny => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub name: String,
    pub pattern: Regex,
    pub action: PolicyAction,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyVerdict {
    pub action: PolicyAction,
    pub reason: String,
    pub rule_name: String,
}

impl PolicyVerdict {
    fn allow() -> Self {
        PolicyVerdict {
            action: PolicyAction::Allow,
            reason: String::new(),
            rule_name: String::new(),
        }
    }
}

pub struct Policy {
    pub rules: Vec<PolicyRule>,
}

impl Policy {
    /// Build the active rule set: enabled built-ins (minus `disabled`) plus the
    /// user's compiled rules. Invalid user regex → error.
    pub fn compile(cfg: &PolicyConfig) -> Result<Policy, String> {
        let mut rules: Vec<PolicyRule> = builtin_rules()
            .iter()
            .filter(|r| !cfg.disabled.iter().any(|d| d == &r.name))
            .cloned()
            .collect();
        for rc in &cfg.rules {
            let action = match rc.action.as_str() {
                "ask" => PolicyAction::Ask,
                "deny" => PolicyAction::Deny,
                other => return Err(format!("invalid policy action '{other}'")),
            };
            let pattern = Regex::new(&rc.pattern)
                .map_err(|e| format!("invalid policy regex '{}': {}", rc.pattern, e))?;
            rules.push(PolicyRule {
                name: format!("user:{}", rc.pattern),
                pattern,
                action,
                reason: rc.reason.clone(),
            });
        }
        Ok(Policy { rules })
    }

    /// Evaluate a joined command line. Most-severe matching rule wins; Allow if
    /// nothing matches.
    pub fn evaluate(&self, command_line: &str) -> PolicyVerdict {
        let mut best: Option<&PolicyRule> = None;
        for rule in &self.rules {
            if rule.pattern.is_match(command_line) {
                let take = match best {
                    None => true,
                    Some(b) => rule.action.severity() > b.action.severity(),
                };
                if take {
                    best = Some(rule);
                }
            }
        }
        match best {
            Some(r) => PolicyVerdict {
                action: r.action,
                reason: r.reason.clone(),
                rule_name: r.name.clone(),
            },
            None => PolicyVerdict::allow(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskDecision {
    Proceed,
    Blocked,
}

/// Pure resolver for a direct-mode `Ask` verdict. `response` is the trimmed tty
/// reply when we prompted (only meaningful with `is_tty`). No tty and no
/// `assume_yes` → fail-closed (Blocked).
pub fn resolve_ask(assume_yes: bool, is_tty: bool, response: Option<&str>) -> AskDecision {
    if assume_yes {
        return AskDecision::Proceed;
    }
    if is_tty {
        let yes = matches!(
            response.map(|r| r.trim().to_ascii_lowercase()).as_deref(),
            Some("y") | Some("yes")
        );
        return if yes {
            AskDecision::Proceed
        } else {
            AskDecision::Blocked
        };
    }
    AskDecision::Blocked
}

/// Built-in rule set. Task 3 fills this; Task 2 ships it empty so the engine
/// compiles and is testable with user rules only.
pub fn builtin_rules() -> &'static [PolicyRule] {
    static RULES: OnceLock<Vec<PolicyRule>> = OnceLock::new();
    RULES.get_or_init(Vec::new)
}

/// Names of the built-in rules, for `[policy] disabled` validation in doctor.
pub fn builtin_names() -> Vec<&'static str> {
    // Task 3 replaces this with the real names.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PolicyConfig, PolicyRuleConfig};

    fn user_cfg(pattern: &str, action: &str) -> PolicyConfig {
        PolicyConfig {
            rules: vec![PolicyRuleConfig {
                pattern: pattern.into(),
                action: action.into(),
                reason: "test reason".into(),
            }],
            disabled: vec![],
        }
    }

    #[test]
    fn no_match_is_allow() {
        let p = Policy::compile(&PolicyConfig::default()).unwrap();
        let v = p.evaluate("ls -la");
        assert_eq!(v.action, PolicyAction::Allow);
        assert!(v.rule_name.is_empty());
    }

    #[test]
    fn user_deny_rule_fires_with_reason() {
        let p = Policy::compile(&user_cfg(r"terraform\s+destroy", "deny")).unwrap();
        let v = p.evaluate("terraform destroy -auto-approve");
        assert_eq!(v.action, PolicyAction::Deny);
        assert_eq!(v.reason, "test reason");
    }

    #[test]
    fn most_severe_wins_deny_over_ask() {
        let cfg = PolicyConfig {
            rules: vec![
                PolicyRuleConfig {
                    pattern: "danger".into(),
                    action: "ask".into(),
                    reason: "a".into(),
                },
                PolicyRuleConfig {
                    pattern: "danger".into(),
                    action: "deny".into(),
                    reason: "d".into(),
                },
            ],
            disabled: vec![],
        };
        let p = Policy::compile(&cfg).unwrap();
        assert_eq!(p.evaluate("this is danger").action, PolicyAction::Deny);
    }

    #[test]
    fn compile_bad_regex_errors() {
        assert!(Policy::compile(&user_cfg("(", "ask")).is_err());
    }

    #[test]
    fn resolve_ask_truth_table() {
        assert_eq!(resolve_ask(true, false, None), AskDecision::Proceed);
        assert_eq!(resolve_ask(false, true, Some("y")), AskDecision::Proceed);
        assert_eq!(resolve_ask(false, true, Some("YES")), AskDecision::Proceed);
        assert_eq!(resolve_ask(false, true, Some("n")), AskDecision::Blocked);
        assert_eq!(resolve_ask(false, true, Some("")), AskDecision::Blocked);
        assert_eq!(resolve_ask(false, false, None), AskDecision::Blocked);
    }

    #[test]
    fn action_serializes_lowercase() {
        let v = PolicyVerdict {
            action: PolicyAction::Deny,
            reason: "r".into(),
            rule_name: "x".into(),
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"action\":\"deny\""), "got: {s}");
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn evaluate_never_panics(s in "[\\s\\S]{0,300}") {
            let p = Policy::compile(&PolicyConfig::default()).unwrap();
            let _ = p.evaluate(&s);
        }
    }
}
