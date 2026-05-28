// src/scrubber/secrets.rs
use crate::config::RedactionRule;
use regex::Regex;
use std::sync::OnceLock;

pub fn scrub_secrets(input: &str, extra_patterns: &[RedactionRule]) -> String {
    let mut scrubbed = input.to_string();

    for (regex, replacement) in secret_patterns() {
        scrubbed = regex.replace_all(&scrubbed, *replacement).to_string();
    }

    for rule in extra_patterns {
        let regex = Regex::new(&rule.pattern).expect("validated config regex");
        scrubbed = regex
            .replace_all(&scrubbed, rule.replacement.as_str())
            .to_string();
    }

    scrubbed
}

fn secret_patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----").unwrap(), "[REDACTED PRIVATE KEY]"),
            (Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+(?:\.[A-Za-z0-9\-_.+/=]+)?").unwrap(), "Bearer ***"),
            (Regex::new(r"github_pat_[A-Za-z0-9_]+").unwrap(), "github_pat_***"),
            (Regex::new(r"xox[baprs]-[A-Za-z0-9-]+").unwrap(), "xoxb-***"),
            // AWS access key id
            (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AKIA***"),
            // Google API key
            (Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(), "AIza***"),
            // Stripe live secret/restricted key
            (Regex::new(r"[sr]k_live_[0-9a-zA-Z]{16,}").unwrap(), "***_live_***"),
            // Anthropic key — MUST precede the broad sk- rule
            (Regex::new(r"sk-ant-[0-9A-Za-z\-_]{10,}").unwrap(), "sk-ant-***"),
            (Regex::new(r"sk-[a-zA-Z0-9\-]+").unwrap(), "sk-***"),
            (Regex::new(r"ghp_[a-zA-Z0-9]+").unwrap(), "ghp_***"),
            // DB connection string — mask only the password component
            (Regex::new(r"(?i)\b(\w+)://([^:@/\s]+):([^@/\s]+)@").unwrap(), "${1}://${2}:***@"),
            // .env-style assignment — keep key name, mask value (>= 6 chars to skip prose)
            // Case-sensitive uppercase keys with '=' or ':' (e.g. PASSWORD=x, API_KEY: x)
            (Regex::new(r#"\b(PASSWORD|PASSWD|SECRET|TOKEN|API[-_]?KEY)\s*[=:]\s*["']?[^\s"']{6,}"#).unwrap(), "${1}=***"),
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_secrets() {
        let input = concat!(
            "Here is my key: sk-",
            "proj-1234567890abcdef",
            " and my token: ghp_",
            "abcdefghijklmno"
        );
        let expected = "Here is my key: sk-*** and my token: ghp_***";
        assert_eq!(scrub_secrets(input, &[]), expected);
    }

    #[test]
    fn test_scrub_extended_secret_formats() {
        let input = concat!(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature\n",
            "GitHub fine-grained: github_pat_",
            "abcdefghijklmnopqrstuvwxyz1234567890\n",
            "Slack: xox",
            "b-123456789012-123456789012-abcdefghijklmnopqrstuvwx\n",
            "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\n"
        );

        let scrubbed = scrub_secrets(input, &[]);
        assert!(scrubbed.contains("Authorization: Bearer ***"));
        assert!(scrubbed.contains("github_pat_***"));
        assert!(scrubbed.contains("xoxb-***"));
        assert!(scrubbed.contains("[REDACTED PRIVATE KEY]"));
        assert!(!scrubbed.contains("signature"));
        assert!(!scrubbed.contains("abcdefghijklmnopqrstuvwx"));
        assert!(!scrubbed.contains("abc123"));
    }

    #[test]
    fn test_scrub_custom_secret_pattern() {
        let input = "custom token-12345";
        let scrubbed = scrub_secrets(
            input,
            &[RedactionRule {
                pattern: "token-[0-9]+".to_string(),
                replacement: "token-***".to_string(),
            }],
        );
        assert_eq!(scrubbed, "custom token-***");
    }

    #[test]
    fn test_scrub_new_secret_formats() {
        let cases = [
            ("AWS: AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
            ("Google: AIzaSyA1234567890abcdefghijklmnopqrstuvw", "AIzaSyA1234567890abcdefghijklmnopqrstuvw"),
            // Split literal so secret scanners don't flag this fake test fixture.
            (
                concat!("Stripe: sk_live_", "0123456789abcdefABCDEF99"),
                concat!("sk_live_", "0123456789abcdefABCDEF99"),
            ),
            ("Anthropic: sk-ant-api03-AbC123_def-456", "sk-ant-api03-AbC123_def-456"),
        ];
        for (input, raw) in cases {
            let scrubbed = scrub_secrets(input, &[]);
            assert!(!scrubbed.contains(raw), "raw secret leaked for input: {input} -> {scrubbed}");
        }
    }

    #[test]
    fn test_scrub_connection_string_password() {
        let input = "postgres://admin:s3cr3tP@ss@db.example.com:5432/app";
        let scrubbed = scrub_secrets(input, &[]);
        assert!(scrubbed.contains("postgres://admin:***@"), "got: {scrubbed}");
        assert!(!scrubbed.contains("s3cr3tP"));
    }

    #[test]
    fn test_scrub_env_assignment() {
        let input = "PASSWORD=hunter2supersecret\nAPI_KEY: abcdef123456ZZ";
        let scrubbed = scrub_secrets(input, &[]);
        assert!(!scrubbed.contains("hunter2supersecret"), "got: {scrubbed}");
        assert!(!scrubbed.contains("abcdef123456ZZ"), "got: {scrubbed}");
    }

    #[test]
    fn test_env_assignment_ignores_short_prose() {
        // "secret: the spec" — value too short / prose, should not be redacted.
        let input = "the secret: tip";
        let scrubbed = scrub_secrets(input, &[]);
        assert_eq!(scrubbed, input);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_scrub_secrets_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = scrub_secrets(&s, &[]);
        }

        #[test]
        fn prop_scrub_secrets_idempotent(s in "[\\s\\S]{0,500}") {
            let once = scrub_secrets(&s, &[]);
            let twice = scrub_secrets(&once, &[]);
            prop_assert_eq!(once, twice);
        }
    }
}
