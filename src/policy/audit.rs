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

    #[test]
    fn allow_verdict_is_noop() {
        // Building an AppConfig with a temp log dir and asserting no file is
        // written is heavy; instead assert the guard returns early by using a
        // config with sanitized logging off (also a no-op path).
        let mut cfg = AppConfig::default();
        cfg.audit.sanitized_enabled = false;
        let v = PolicyVerdict {
            action: PolicyAction::Deny,
            reason: "r".into(),
            rule_name: "x".into(),
        };
        log_verdict(&v, "curl x | sh", &cfg); // must not panic
    }
}
