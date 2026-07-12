// src/scrubber/secrets.rs
use super::CompiledRule;
use regex::Regex;
use std::sync::OnceLock;

pub fn scrub_secrets(input: &str, extra_patterns: &[CompiledRule], entropy: bool) -> String {
    let mut scrubbed = input.to_string();

    for (regex, replacement) in secret_patterns() {
        scrubbed = regex.replace_all(&scrubbed, *replacement).to_string();
    }

    for rule in extra_patterns {
        scrubbed = rule
            .regex
            .replace_all(&scrubbed, rule.replacement.as_str())
            .to_string();
    }

    if entropy {
        scrubbed = super::entropy::scrub_entropy_secrets(&scrubbed);
    }

    scrubbed
}

fn secret_patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----").unwrap(), "[REDACTED PRIVATE KEY]"),
            (Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+(?:\.[A-Za-z0-9\-_.+/=]+)?").unwrap(), "Bearer ***"),
            // Bare JSON Web Token (header.payload.signature, both halves base64url
            // of a JSON object so they begin `eyJ`). The Bearer rule above already
            // consumed any `Bearer <jwt>`, so this only fires on unprefixed tokens.
            (Regex::new(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(), "[REDACTED JWT]"),
            (Regex::new(r"github_pat_[A-Za-z0-9_]+").unwrap(), "github_pat_***"),
            // GitLab personal/project/group access token
            (Regex::new(r"glpat-[A-Za-z0-9_\-]{20,}").unwrap(), "glpat-***"),
            (Regex::new(r"xox[baprs]-[A-Za-z0-9-]+").unwrap(), "xoxb-***"),
            // AWS access key id. Canonical length is 16 trailing chars, but use
            // `{16,}` so an over-length look-alike is fully consumed rather than
            // leaking its tail past `***`. `{16,}` only ever extends an existing
            // match — it cannot match any string `{16}` did not — so it adds no
            // false positives.
            (Regex::new(r"AKIA[0-9A-Z]{16,}").unwrap(), "AKIA***"),
            // Google API key (see AKIA note on `{35,}` vs `{35}`).
            (Regex::new(r"AIza[0-9A-Za-z\-_]{35,}").unwrap(), "AIza***"),
            // Stripe live secret/restricted key
            (Regex::new(r"[sr]k_live_[0-9a-zA-Z]{16,}").unwrap(), "***_live_***"),
            // SendGrid API key
            (Regex::new(r"SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}").unwrap(), "SG.***"),
            // Twilio API key SID (SK + 32 hex)
            (Regex::new(r"\bSK[0-9a-fA-F]{32}\b").unwrap(), "SK***"),
            // npm automation/access token (see AKIA note on `{36,}` vs `{36}`).
            (Regex::new(r"npm_[A-Za-z0-9]{36,}").unwrap(), "npm_***"),
            // PyPI upload token
            (Regex::new(r"pypi-[A-Za-z0-9_\-]{16,}").unwrap(), "pypi-***"),
            // Hugging Face access token
            (Regex::new(r"hf_[A-Za-z0-9]{20,}").unwrap(), "hf_***"),
            // Slack incoming-webhook URL
            (Regex::new(r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+").unwrap(), "https://hooks.slack.com/services/***"),
            // Discord bot token (id.timestamp.hmac, distinctive segment lengths)
            (Regex::new(r"\b[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b").unwrap(), "[REDACTED DISCORD TOKEN]"),
            // Telegram bot token (numeric id : 35-char secret)
            (Regex::new(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b").unwrap(), "[REDACTED TELEGRAM TOKEN]"),
            // DigitalOcean PAT / OAuth / refresh token
            (Regex::new(r"do[opr]_v1_[a-f0-9]{64}").unwrap(), "do_v1_***"),
            // Shopify access token (app / shared-secret / custom-app / private-app)
            (Regex::new(r"shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}").unwrap(), "shp_***"),
            // Azure Storage account key in a connection string
            (Regex::new(r"(?i)AccountKey=[A-Za-z0-9+/]{80,}={0,2}").unwrap(), "AccountKey=***"),
            // Sentry DSN (embeds the project public key)
            (Regex::new(r"(?i)https://[0-9a-f]+@[\w.-]*sentry\.io/\d+").unwrap(), "[REDACTED SENTRY DSN]"),
            // age encryption secret key (bech32, uppercase)
            (Regex::new(r"AGE-SECRET-KEY-1[0-9A-Z]{20,}").unwrap(), "AGE-SECRET-KEY-***"),
            // Google OAuth access token
            (Regex::new(r"ya29\.[0-9A-Za-z_\-]{20,}").unwrap(), "ya29.***"),
            // Google OAuth client secret
            (Regex::new(r"GOCSPX-[0-9A-Za-z_\-]{20,}").unwrap(), "GOCSPX-***"),
            // Stripe webhook signing secret
            (Regex::new(r"whsec_[0-9a-zA-Z]{20,}").unwrap(), "whsec_***"),
            // GitHub OAuth / user-to-server / server-to-server / refresh tokens
            // (ghp_/github_pat_ are handled above)
            (Regex::new(r"(gh[ousr]_)[A-Za-z0-9]{20,}").unwrap(), "${1}***"),
            // New Relic license / user / browser keys
            (Regex::new(r"(NR(?:AK|AA|JS|BR)-)[A-Z0-9]{20,}").unwrap(), "${1}***"),
            // Anthropic key — MUST precede the broad sk- rule
            (Regex::new(r"sk-ant-[0-9A-Za-z\-_]{10,}").unwrap(), "sk-ant-***"),
            // OpenAI project key (contains underscores the broad sk- rule stops at)
            // — MUST precede the broad sk- rule.
            (Regex::new(r"sk-proj-[A-Za-z0-9_\-]{20,}").unwrap(), "sk-proj-***"),
            // Broad OpenAI-style `sk-` key. Requires >= 20 key chars so it does
            // NOT re-hit the short `sk-ant-`/`sk-proj-` prefix already left by
            // the provider rules above (which would double-mask to `sk-******`);
            // real bare `sk-` keys are far longer. (regex crate has no lookahead.)
            (Regex::new(r"sk-[a-zA-Z0-9\-]{20,}").unwrap(), "sk-***"),
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
        assert_eq!(scrub_secrets(input, &[], true), expected);
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

        let scrubbed = scrub_secrets(input, &[], true);
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
        use crate::config::RedactionRule;
        let input = "custom token-12345";
        let rules = super::super::compile_rules(&[RedactionRule {
            pattern: "token-[0-9]+".to_string(),
            replacement: "token-***".to_string(),
        }]);
        let scrubbed = scrub_secrets(input, &rules, true);
        assert_eq!(scrubbed, "custom token-***");
    }

    #[test]
    fn test_scrub_new_secret_formats() {
        let cases = [
            ("AWS: AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
            (
                "Google: AIzaSyA1234567890abcdefghijklmnopqrstuvw",
                "AIzaSyA1234567890abcdefghijklmnopqrstuvw",
            ),
            // Split literal so secret scanners don't flag this fake test fixture.
            (
                concat!("Stripe: sk_live_", "0123456789abcdefABCDEF99"),
                concat!("sk_live_", "0123456789abcdefABCDEF99"),
            ),
            (
                "Anthropic: sk-ant-api03-AbC123_def-456",
                "sk-ant-api03-AbC123_def-456",
            ),
        ];
        for (input, raw) in cases {
            let scrubbed = scrub_secrets(input, &[], true);
            assert!(
                !scrubbed.contains(raw),
                "raw secret leaked for input: {input} -> {scrubbed}"
            );
        }
    }

    #[test]
    fn test_scrub_additional_provider_formats() {
        // Each fixture is a fake credential; the secret half is split with
        // concat! so repo secret scanners don't flag this test.
        let cases = [
            ("GitLab: ", concat!("glpat-", "abcdef1234567890ABCDEF")),
            (
                "SendGrid: ",
                concat!(
                    "SG.",
                    "abcdefghij1234567890ab",
                    ".",
                    "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHI"
                ),
            ),
            (
                "Twilio: ",
                concat!("SK", "0123456789abcdef0123456789abcdef"),
            ),
            (
                "npm: ",
                concat!("npm_", "abcdefghijklmnopqrstuvwxyz0123456789"),
            ),
            ("PyPI: ", concat!("pypi-", "AgEIcHlwaS5vcmcCJD12345")),
            ("HF: ", concat!("hf_", "abcdefghijklmnopqrstuvwxyz")),
            (
                "OpenAI: ",
                concat!("sk-proj-", "abc_DEF-123ghi_JKL456mno789"),
            ),
        ];
        for (label, raw) in cases {
            let input = format!("{label}{raw}");
            let scrubbed = scrub_secrets(&input, &[], false);
            assert!(
                !scrubbed.contains(raw),
                "raw secret leaked for {label} -> {scrubbed}"
            );
        }
    }

    #[test]
    fn over_length_fixed_count_keys_do_not_leak_a_suffix() {
        // Exact-count patterns (AIza{35}, npm_{36}, AKIA{16}) consumed only the
        // canonical length; a longer look-alike leaked its tail past `***`
        // (e.g. `AIza***ab`). The whole credential-char run must be redacted.
        // Fixtures split with concat! so the repo secret scanner ignores them.
        let cases = [
            // AIza + 37 trailing chars (2 over the canonical 35)
            concat!("AIza", "0123456789abcdefghijklmnopqrstuvwxyzAB"),
            // npm_ + 38 trailing chars (2 over the canonical 36)
            concat!("npm_", "0123456789abcdefghijklmnopqrstuvwxyzABCD"),
            // AKIA + 18 trailing chars (2 over the canonical 16)
            concat!("AKIA", "0123456789ABCDEFGH"),
        ];
        for raw in cases {
            let scrubbed = scrub_secrets(raw, &[], false);
            assert!(
                scrubbed.ends_with("***") && !scrubbed.contains(&raw[raw.len() - 2..]),
                "over-length key leaked a suffix: {raw} -> {scrubbed}"
            );
        }
    }

    #[test]
    fn scrubs_more_provider_formats() {
        // Fixtures built with format!/repeat so there is no contiguous
        // real-looking secret (push-protection safe) and lengths are exact.
        let slack = format!(
            "https://hooks.slack.com/services/T{}/B{}/{}",
            "0".repeat(8),
            "1".repeat(8),
            "a".repeat(24)
        );
        let discord = format!("M{}.{}.{}", "a".repeat(23), "b".repeat(6), "c".repeat(27));
        let telegram = format!("{}:{}", "1".repeat(9), "a".repeat(35));
        let digitalocean = format!("dop_v1_{}", "a".repeat(64));
        let shopify = format!("shpat_{}", "a".repeat(32));
        let azure = format!("AccountKey={}==", "a".repeat(86));
        for raw in [&slack, &discord, &telegram, &digitalocean, &shopify, &azure] {
            let input = format!("token: {raw}");
            let scrubbed = scrub_secrets(&input, &[], false);
            assert!(
                !scrubbed.contains(raw.as_str()),
                "raw secret leaked: {input} -> {scrubbed}"
            );
        }
    }

    #[test]
    fn scrubs_provider_formats_batch_2() {
        // format!/repeat fixtures: no contiguous real-looking secret, exact lengths.
        let sentry = format!(
            "https://{}@o123456.ingest.sentry.io/7891011",
            "a".repeat(32)
        );
        let age = format!("AGE-SECRET-KEY-1{}", "A".repeat(58));
        let ya29 = format!("ya29.{}", "a".repeat(40));
        let gocspx = format!("GOCSPX-{}", "a".repeat(28));
        let whsec = format!("whsec_{}", "a".repeat(32));
        let gho = format!("gho_{}", "a".repeat(36));
        let nrak = format!("NRAK-{}", "A".repeat(27));
        for raw in [&sentry, &age, &ya29, &gocspx, &whsec, &gho, &nrak] {
            let input = format!("token: {raw}");
            let scrubbed = scrub_secrets(&input, &[], false);
            assert!(
                !scrubbed.contains(raw.as_str()),
                "raw secret leaked: {input} -> {scrubbed}"
            );
        }
        // Prefix-keeping replacements preserve the provider prefix.
        assert!(scrub_secrets(&gho, &[], false).contains("gho_***"));
        assert!(scrub_secrets(&nrak, &[], false).contains("NRAK-***"));
    }

    #[test]
    fn sk_ant_key_is_not_double_masked() {
        // The broad `sk-` rule must not re-hit the already-substituted
        // `sk-ant-***` and mangle it into `sk-******`.
        let input = concat!("sk-ant-", "api03-AbC123_def-456ghijklmno");
        let scrubbed = scrub_secrets(input, &[], false);
        assert!(scrubbed.contains("sk-ant-***"), "got: {scrubbed}");
        assert!(!scrubbed.contains("sk-******"), "double-masked: {scrubbed}");
    }

    #[test]
    fn test_scrub_bare_jwt() {
        // A three-part JWT with no Bearer prefix. Entropy off to prove the
        // format rule alone catches it.
        let jwt = concat!(
            "eyJhbGciOiJIUzI1NiJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.",
            "dummysignature_part-0123"
        );
        let input = format!("session token = {jwt}");
        let scrubbed = scrub_secrets(&input, &[], false);
        assert!(scrubbed.contains("[REDACTED JWT]"), "got: {scrubbed}");
        assert!(!scrubbed.contains("dummysignature"), "got: {scrubbed}");
    }

    #[test]
    fn test_twilio_sid_does_not_eat_prose() {
        // `SK` followed by non-hex / wrong length must pass through untouched.
        let input = "The SKILL value and SK123 are fine";
        assert_eq!(scrub_secrets(input, &[], false), input);
    }

    #[test]
    fn test_scrub_connection_string_password() {
        let input = "postgres://admin:s3cr3tP@ss@db.example.com:5432/app";
        let scrubbed = scrub_secrets(input, &[], true);
        assert!(
            scrubbed.contains("postgres://admin:***@"),
            "got: {scrubbed}"
        );
        assert!(!scrubbed.contains("s3cr3tP"));
    }

    #[test]
    fn test_scrub_env_assignment() {
        let input = "PASSWORD=hunter2supersecret\nAPI_KEY: abcdef123456ZZ";
        let scrubbed = scrub_secrets(input, &[], true);
        assert!(!scrubbed.contains("hunter2supersecret"), "got: {scrubbed}");
        assert!(!scrubbed.contains("abcdef123456ZZ"), "got: {scrubbed}");
    }

    #[test]
    fn test_env_assignment_ignores_short_prose() {
        // "secret: the spec" — value too short / prose, should not be redacted.
        let input = "the secret: tip";
        let scrubbed = scrub_secrets(input, &[], true);
        assert_eq!(scrubbed, input);
    }

    #[test]
    fn entropy_stage_can_be_disabled() {
        let input = "db_password=0123456789abcdef0123456789abcdef";
        assert_eq!(
            scrub_secrets(input, &[], true),
            "db_password=***",
            "entropy on must redact"
        );
        assert_eq!(
            scrub_secrets(input, &[], false),
            input,
            "entropy off must pass through"
        );
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_scrub_secrets_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = scrub_secrets(&s, &[], true);
        }

        #[test]
        fn prop_scrub_secrets_idempotent(s in "[\\s\\S]{0,500}") {
            let once = scrub_secrets(&s, &[], true);
            let twice = scrub_secrets(&once, &[], true);
            prop_assert_eq!(once, twice);
        }
    }
}
