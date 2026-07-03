//! Configuration: loading, defaults, and validation of `~/.vallum/config.toml`.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const CONFIG_ENV_VAR: &str = "VALLUM_CONFIG";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AppConfig {
    pub audit: AuditConfig,
    pub pipeline: PipelineConfig,
    pub scrubber: ScrubberConfig,
    pub security: SecurityConfig,
    pub optimizer: OptimizerConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    pub log_dir: Option<PathBuf>,
    pub raw_enabled: bool,
    pub sanitized_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PipelineConfig {
    pub head_lines: usize,
    pub tail_lines: usize,
    pub min_optimize_tokens: usize,
    pub max_output_bytes: usize,
    pub timeout_secs: u64,
    pub max_line_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScrubberConfig {
    pub extra_secret_patterns: Vec<RedactionRule>,
    /// Context-gated entropy redaction of credential-ish assignment values.
    /// Default on; bare tokens (git SHAs, UUIDs) are never candidates.
    pub entropy: bool,
    /// Input normalization (strip invisible/bidi chars + shadow-fold homoglyphs
    /// for injection matching). Default on; `false` reverts to legacy behavior.
    pub normalize: bool,
}

impl Default for ScrubberConfig {
    fn default() -> Self {
        Self {
            extra_secret_patterns: Vec::new(),
            entropy: true,
            normalize: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Block the entire output when an injection is detected.
    pub strict: bool,
    /// Enable the pre-exec guardrail/policy layer. Default on; all built-in
    /// rules default to `ask`, so ordinary commands are unaffected.
    pub guardrail: bool,
    /// Auto-approve direct-mode `ask` verdicts (for scripts/CI). Also honored
    /// via the `VALLUM_ASSUME_YES=1` environment variable.
    pub assume_yes: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            strict: false,
            guardrail: true,
            assume_yes: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct OptimizerConfig {
    /// Names of optimizers to disable. All optimizers are on by default.
    /// Valid names: git_status, git_diff, git_log, cargo, pytest, npm,
    /// docker, go_test, make, kubectl, terraform, grep, file_list.
    /// `vallum doctor` warns about names here that match no optimizer.
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionRule {
    pub pattern: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PolicyConfig {
    /// Extra user rules, evaluated together with the built-ins.
    pub rules: Vec<PolicyRuleConfig>,
    /// Built-in rule names to disable. `vallum doctor` warns on unknown names.
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleConfig {
    pub pattern: String,
    /// "ask" | "deny" ("allow" is rejected — use [policy] disabled to suppress a built-in).
    pub action: String,
    pub reason: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_dir: None,
            raw_enabled: false,
            sanitized_enabled: true,
        }
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            head_lines: 50,
            tail_lines: 50,
            min_optimize_tokens: 50,
            max_output_bytes: 10 * 1024 * 1024,
            timeout_secs: 300,
            max_line_length: 2000,
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, String> {
        let path = config_path_from_env_or_default();
        Self::from_path(&path)
    }

    pub fn from_path(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {}", path.display(), e))?;
        let config: Self = toml::from_str(&raw)
            .map_err(|e| format!("failed to parse config {}: {}", path.display(), e))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        for rule in &self.scrubber.extra_secret_patterns {
            Regex::new(&rule.pattern)
                .map_err(|e| format!("invalid scrubber regex '{}': {}", rule.pattern, e))?;
        }
        for rule in &self.policy.rules {
            match rule.action.as_str() {
                "ask" | "deny" => {}
                "allow" => {
                    return Err(format!(
                        "policy rule action \"allow\" is not allowed (pattern '{}'); \
                         user rules may only \"ask\" or \"deny\" — use [policy] disabled \
                         to suppress a built-in",
                        rule.pattern
                    ))
                }
                other => {
                    return Err(format!(
                        "invalid policy rule action \"{}\" (pattern '{}'); expected \"ask\" or \"deny\"",
                        other, rule.pattern
                    ))
                }
            }
            Regex::new(&rule.pattern)
                .map_err(|e| format!("invalid policy regex '{}': {}", rule.pattern, e))?;
        }
        Ok(())
    }
}

pub fn config_path_from_env_or_default() -> PathBuf {
    if let Ok(path) = env::var(CONFIG_ENV_VAR) {
        PathBuf::from(path)
    } else if let Some(home) = dirs::home_dir() {
        home.join(".vallum").join("config.toml")
    } else {
        PathBuf::from("vallum-config.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn missing_config_uses_defaults() {
        let path = unique_temp_path("missing");
        let config = AppConfig::from_path(&path).unwrap();

        assert!(!config.audit.raw_enabled);
        assert!(config.audit.sanitized_enabled);
        assert_eq!(config.pipeline.head_lines, 50);
        assert_eq!(config.pipeline.tail_lines, 50);
        assert_eq!(config.pipeline.min_optimize_tokens, 50);
        assert_eq!(config.pipeline.max_output_bytes, 10 * 1024 * 1024);
        assert_eq!(config.pipeline.timeout_secs, 300);
        assert_eq!(config.pipeline.max_line_length, 2000);
        assert!(config.scrubber.extra_secret_patterns.is_empty());
    }

    #[test]
    fn parses_config_file_and_validates_regex() {
        let dir = unique_temp_path("valid");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(
            &path,
            format!(
                r#"
[audit]
log_dir = "{}"
raw_enabled = false
sanitized_enabled = true

[pipeline]
head_lines = 3
tail_lines = 2

[scrubber]
extra_secret_patterns = [{{ pattern = "token-[0-9]+", replacement = "token-***" }}]
"#,
                dir.join("logs").display()
            ),
        )
        .unwrap();

        let config = AppConfig::from_path(&path).unwrap();
        assert_eq!(config.audit.log_dir.as_ref().unwrap(), &dir.join("logs"));
        assert!(!config.audit.raw_enabled);
        assert!(config.audit.sanitized_enabled);
        assert_eq!(config.pipeline.head_lines, 3);
        assert_eq!(config.pipeline.tail_lines, 2);
        assert_eq!(config.scrubber.extra_secret_patterns.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_invalid_regex_in_config() {
        let dir = unique_temp_path("invalid");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(
            &path,
            r#"
[scrubber]
extra_secret_patterns = [ { pattern = "token-(", replacement = "token-***" } ]
"#,
        )
        .unwrap();

        let err = AppConfig::from_path(&path).unwrap_err();
        assert!(err.contains("invalid scrubber regex"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn security_strict_defaults_false_and_parses() {
        let def = AppConfig::default();
        assert!(!def.security.strict);

        let dir = unique_temp_path("security");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(&path, "[security]\nstrict = true\n").unwrap();
        let config = AppConfig::from_path(&path).unwrap();
        assert!(config.security.strict);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scrubber_entropy_defaults_true_and_parses_false() {
        assert!(AppConfig::default().scrubber.entropy);
        let parsed: AppConfig =
            toml::from_str("[scrubber]\nentropy = false\n").expect("valid toml");
        assert!(!parsed.scrubber.entropy);
    }

    #[test]
    fn scrubber_normalize_defaults_true_and_parses_false() {
        assert!(AppConfig::default().scrubber.normalize);
        let parsed: AppConfig =
            toml::from_str("[scrubber]\nnormalize = false\n").expect("valid toml");
        assert!(!parsed.scrubber.normalize);
    }

    #[test]
    fn optimizer_disabled_defaults_empty_and_parses() {
        assert!(AppConfig::default().optimizer.disabled.is_empty());

        let dir = unique_temp_path("optimizer");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(&path, "[optimizer]\ndisabled = [\"npm\", \"docker\"]\n").unwrap();
        let config = AppConfig::from_path(&path).unwrap();
        assert_eq!(
            config.optimizer.disabled,
            vec!["npm".to_string(), "docker".to_string()]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vallum_config_test_{}_{}", name, suffix))
    }

    fn write_tmp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vallum_cfg_{}_{}",
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn guardrail_defaults_on_assume_yes_off() {
        let cfg = AppConfig::default();
        assert!(cfg.security.guardrail);
        assert!(!cfg.security.assume_yes);
        assert!(cfg.policy.rules.is_empty());
        assert!(cfg.policy.disabled.is_empty());
    }

    #[test]
    fn policy_rule_parses_and_validates() {
        let p = write_tmp(
            "ok",
            "[[policy.rules]]\npattern = 'terraform\\s+destroy'\naction = \"deny\"\nreason = \"blocked\"\n",
        );
        let cfg = AppConfig::from_path(&p).unwrap();
        assert_eq!(cfg.policy.rules.len(), 1);
        assert_eq!(cfg.policy.rules[0].action, "deny");
    }

    #[test]
    fn policy_rule_allow_action_is_error() {
        let p = write_tmp(
            "allow",
            "[[policy.rules]]\npattern = 'x'\naction = \"allow\"\nreason = \"r\"\n",
        );
        let err = AppConfig::from_path(&p).unwrap_err();
        assert!(err.contains("allow"), "got: {err}");
    }

    #[test]
    fn policy_rule_bad_regex_is_error() {
        let p = write_tmp(
            "badre",
            "[[policy.rules]]\npattern = '('\naction = \"ask\"\nreason = \"r\"\n",
        );
        assert!(AppConfig::from_path(&p).is_err());
    }

    #[test]
    fn policy_rule_unknown_action_is_error() {
        let p = write_tmp(
            "unk",
            "[[policy.rules]]\npattern = 'x'\naction = \"warn\"\nreason = \"r\"\n",
        );
        let err = AppConfig::from_path(&p).unwrap_err();
        assert!(err.contains("warn") || err.contains("action"), "got: {err}");
    }
}
