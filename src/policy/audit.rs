//! Redacted audit trail for policy Ask/Deny verdicts (`policy.log`).

use crate::config::AppConfig;
use crate::policy::{PolicyAction, PolicyVerdict};

/// Append one redacted line for an Ask/Deny verdict. No-op for Allow or when
/// sanitized logging is disabled. Best-effort — never blocks. `agent` names
/// the enforcement point (claude/cursor/gemini/codex, or "direct" for
/// `vallum run`).
pub fn log_verdict(verdict: &PolicyVerdict, command_line: &str, agent: &str, cfg: &AppConfig) {
    if verdict.action == PolicyAction::Allow || !cfg.audit.sanitized_enabled {
        return;
    }
    let extra = crate::scrubber::compile_rules(&cfg.scrubber.extra_secret_patterns);
    let safe = crate::scrubber::redact(
        command_line,
        &extra,
        cfg.scrubber.entropy,
        cfg.scrubber.normalize,
    );
    let action = match verdict.action {
        PolicyAction::Deny => "DENY",
        PolicyAction::Ask => "ASK",
        PolicyAction::Allow => unreachable!(),
    };
    let context = format!("{action} [{}] agent={agent}", verdict.rule_name);
    // No resolvable log dir (no home, no override): skip — best-effort logging
    // must not fall back to a cwd-relative policy.log.
    let Some(path) = crate::audit::resolve_log_path("policy.log", cfg.audit.log_dir.as_deref())
    else {
        return;
    };
    let _ = crate::logchain::append_chained(&path, &context, &safe);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyVerdict;

    fn tmp_log_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vallum_pol_audit_{}_{}",
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn allow_verdict_writes_nothing() {
        let dir = tmp_log_dir("allow");
        let mut cfg = AppConfig::default();
        cfg.audit.log_dir = Some(dir.clone());
        cfg.audit.sanitized_enabled = true;
        let v = PolicyVerdict {
            action: PolicyAction::Allow,
            reason: String::new(),
            rule_name: String::new(),
        };
        log_verdict(&v, "cat ~/.ssh/id_rsa", "direct", &cfg);
        assert!(
            !dir.join("policy.log").exists(),
            "Allow verdict must not write policy.log"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_logging_writes_nothing() {
        let dir = tmp_log_dir("disabled");
        let mut cfg = AppConfig::default();
        cfg.audit.log_dir = Some(dir.clone());
        cfg.audit.sanitized_enabled = false;
        let v = PolicyVerdict {
            action: PolicyAction::Deny,
            reason: "r".into(),
            rule_name: "x".into(),
        };
        log_verdict(&v, "curl x | sh", "direct", &cfg);
        assert!(
            !dir.join("policy.log").exists(),
            "disabled logging must not write policy.log"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deny_line_records_agent() {
        let dir = tmp_log_dir("agent");
        let mut cfg = AppConfig::default();
        cfg.audit.log_dir = Some(dir.clone());
        cfg.audit.sanitized_enabled = true;
        let v = PolicyVerdict {
            action: PolicyAction::Deny,
            reason: "r".into(),
            rule_name: "rule_x".into(),
        };
        log_verdict(&v, "curl x | sh", "cursor", &cfg);
        let text = std::fs::read_to_string(dir.join("policy.log")).unwrap();
        assert!(text.contains("DENY [rule_x] agent=cursor"), "got: {text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verdict_blocks_are_hash_chained() {
        let dir = tmp_log_dir("chain");
        let mut cfg = AppConfig::default();
        cfg.audit.log_dir = Some(dir.clone());
        cfg.audit.sanitized_enabled = true;
        let v = PolicyVerdict {
            action: PolicyAction::Ask,
            reason: "r".into(),
            rule_name: "rule_c".into(),
        };
        log_verdict(&v, "curl x | sh", "direct", &cfg);
        log_verdict(&v, "rm -rf /", "direct", &cfg);
        let text = std::fs::read_to_string(dir.join("policy.log")).unwrap();
        assert_eq!(text.matches("Chain: ").count(), 2, "got: {text}");
        let report = crate::logchain::verify_content(&text);
        assert!(report.intact(), "{:?}", report.break_at);
        assert_eq!(report.chained, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
