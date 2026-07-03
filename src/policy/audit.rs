//! Redacted audit trail for policy Ask/Deny verdicts (`policy.log`).

use crate::config::AppConfig;
use crate::policy::{PolicyAction, PolicyVerdict};

/// Append one redacted line for an Ask/Deny verdict. No-op for Allow or when
/// sanitized logging is disabled. Best-effort — never blocks.
pub fn log_verdict(verdict: &PolicyVerdict, command_line: &str, cfg: &AppConfig) {
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
    let context = format!("{action} [{}]", verdict.rule_name);
    let _ = crate::audit::write_log("policy.log", &context, &safe, cfg.audit.log_dir.as_deref());
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
        log_verdict(&v, "cat ~/.ssh/id_rsa", &cfg);
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
        log_verdict(&v, "curl x | sh", &cfg);
        assert!(
            !dir.join("policy.log").exists(),
            "disabled logging must not write policy.log"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
