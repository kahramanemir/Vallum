// src/scrubber/entropy.rs
//! Context-gated entropy redaction: the generic net behind the specific
//! secret patterns in `secrets.rs`.
//!
//! A token is redacted only when BOTH gates pass:
//! - **context gate** — it is the value of a credential-ish assignment
//!   (`key=value`, `key: value`, `"key": "value"`) whose key contains one of
//!   `KEY_VOCABULARY` as a case-insensitive substring;
//! - **entropy gate** — the value is at least `MIN_VALUE_LEN` chars and its
//!   Shannon entropy clears a charset-aware threshold (hex vs general).
//!
//! Bare high-entropy tokens (git SHAs, UUIDs, base64 blobs in logs) have no
//! assignment context and are never touched. Low-entropy values (prose,
//! `user:123`) never clear the entropy gate even in credential contexts.
//! Values containing `://` are skipped (connection-string passwords are
//! masked upstream by a dedicated pattern); values starting with `/` or
//! `./` are skipped (file paths).
//!
//! **Evasion mitigations:**
//! - Leading separator characters (`=`, `:`) and surrounding whitespace are
//!   stripped from the measured payload before entropy scoring. This prevents
//!   `key==value` / `key:=value` (double-separator) and `key="  <secret>  "`
//!   (padded quoted value) from flipping the charset class or depressing the
//!   score. The replacement still masks the entire captured value, so the
//!   output shape is unchanged.
//! - Pure-decimal values (numeric IDs, phone numbers) are deliberately
//!   exempt: they are excluded from the hex-charset class (which requires at
//!   least one `a-f` letter) and their maximum entropy (~3.32 bits/char)
//!   never reaches the general threshold of 4.5, so they always pass through
//!   unredacted.
//!
//! Known accepted side effects: keys like `author`, `monkey`, `cache_key`
//! become candidates via substring matching ("auth", "key"). This is
//! harmless — the entropy gate still applies — and deliberate: substring
//! matching catches `db_password`, `authToken`, `AWS_SECRET_ACCESS_KEY`,
//! `api-key` without enumerating every spelling.

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Values shorter than this are never redacted.
const MIN_VALUE_LEN: usize = 16;
/// Shannon entropy threshold (bits/char) for hex-only values.
const HEX_ENTROPY_THRESHOLD: f64 = 3.0;
/// Shannon entropy threshold (bits/char) for everything else.
const GENERAL_ENTROPY_THRESHOLD: f64 = 4.5;

/// Case-insensitive substrings that mark a key as credential-ish.
const KEY_VOCABULARY: &[&str] = &[
    "pass", "pwd", "secret", "token", "key", "auth", "cred", "session",
];

/// `key` (optionally quoted) + `=`/`:` separator + value (quoted string or
/// bare non-whitespace run). Quoted alternatives come first so a leading
/// quote is never parsed as part of a bare value.
fn assignment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?P<key>"[A-Za-z_][A-Za-z0-9_.-]*"|'[A-Za-z_][A-Za-z0-9_.-]*'|[A-Za-z_][A-Za-z0-9_.-]*)(?P<sep>\s*[=:]\s*)(?P<val>"[^"\n]+"|'[^'\n]+'|[^\s"']+)"#,
        )
        .unwrap()
    })
}

fn key_is_credential_ish(key: &str) -> bool {
    let k = key
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase();
    KEY_VOCABULARY.iter().any(|w| k.contains(w))
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, u32> = HashMap::new();
    let mut len = 0f64;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        len += 1.0;
    }
    if len == 0.0 {
        return 0.0;
    }
    counts
        .values()
        .map(|&n| {
            let p = f64::from(n) / len;
            -p * p.log2()
        })
        .sum()
}

fn value_is_high_entropy_secret(value: &str) -> bool {
    if value.chars().count() < MIN_VALUE_LEN {
        return false;
    }
    if value.contains("://") {
        return false; // URL; connection-string passwords are masked upstream
    }
    if value.starts_with('/') || value.starts_with("./") {
        return false; // file path
    }
    // Genuinely hex-looking: all hex digits AND at least one a-f letter.
    // Pure-decimal values (IDs, phone numbers) max out at ~3.32 bits/char
    // and must use the general threshold, which they effectively never
    // clear — numeric identifiers stay visible by design.
    let is_hex = value.chars().all(|c| c.is_ascii_hexdigit())
        && value.chars().any(|c| c.is_ascii_alphabetic());
    let threshold = if is_hex {
        HEX_ENTROPY_THRESHOLD
    } else {
        GENERAL_ENTROPY_THRESHOLD
    };
    shannon_entropy(value) >= threshold
}

#[allow(dead_code)] // used from secrets.rs in the next commit
pub fn scrub_entropy_secrets(input: &str) -> String {
    assignment_regex()
        .replace_all(input, |caps: &regex::Captures| {
            let key = &caps["key"];
            let sep = &caps["sep"];
            let val = &caps["val"];
            let (quote, inner) = match val.as_bytes().first() {
                Some(b'"') => ("\"", val.trim_matches('"')),
                Some(b'\'') => ("'", val.trim_matches('\'')),
                _ => ("", val),
            };
            // Measure the actual payload: strip stray leading separators
            // (key==value, key:=value) and surrounding whitespace inside
            // quotes — both otherwise flip the charset class and depress
            // the entropy score, which is an evasion vector.
            let inner = inner.trim_start_matches(['=', ':']).trim();
            if key_is_credential_ish(key) && value_is_high_entropy_secret(inner) {
                format!("{key}{sep}{quote}***{quote}")
            } else {
                caps[0].to_string()
            }
        })
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic, transparently synthetic high-entropy fixtures:
    // 32 hex chars, 16 symbols evenly distributed -> entropy = 4.0 >= 3.0.
    const HEX32: &str = "0123456789abcdef0123456789abcdef";
    // 32 unique base64-class chars -> entropy = 5.0 >= 4.5.
    const B64_32: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz012345";

    #[test]
    fn redacts_lowercase_password_assignment() {
        let input = format!("db_password={HEX32}");
        assert_eq!(scrub_entropy_secrets(&input), "db_password=***");
    }

    #[test]
    fn redacts_json_auth_token() {
        let input = format!(r#""authToken": "{B64_32}""#);
        assert_eq!(scrub_entropy_secrets(&input), r#""authToken": "***""#);
    }

    #[test]
    fn redacts_quoted_hex_secret_with_colon_separator() {
        let input = format!("secret: '{HEX32}'");
        assert_eq!(scrub_entropy_secrets(&input), "secret: '***'");
    }

    #[test]
    fn redacts_dashed_api_key() {
        let input = format!("api-key = {B64_32}");
        assert_eq!(scrub_entropy_secrets(&input), "api-key = ***");
    }

    #[test]
    fn leaves_bare_commit_sha_alone() {
        let input = "commit 9f86d081884c7d659a2feaa0c55ad015afc366b7";
        assert_eq!(scrub_entropy_secrets(input), input);
    }

    #[test]
    fn leaves_git_log_block_alone() {
        let input = "9f86d08 fix(optimizer): unwrap bash -c scripts\nac8541d fix(optimizer): tighten grouping\n";
        assert_eq!(scrub_entropy_secrets(input), input);
    }

    #[test]
    fn leaves_bare_uuid_alone() {
        let input = "id: 550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(scrub_entropy_secrets(input), input);
    }

    #[test]
    fn leaves_low_entropy_values_alone() {
        for input in [
            "cache_key=user:123",
            "password: hunter2",
            "password: hunter2supersecret",
            "author: Jane Doe <jane@example.com>",
        ] {
            assert_eq!(scrub_entropy_secrets(input), input, "{input}");
        }
    }

    #[test]
    fn url_and_path_guards() {
        for input in [
            "auth_url=https://example.com/oauth2/authorize?client=abcdef1234567890",
            "registry_token: https://registry.npmjs.org/some/long/package/path",
            "KEY_PATH=/home/user/.ssh/id_rsa_with_a_long_name",
            "token_file=./secrets/long_token_file_name.txt",
        ] {
            assert_eq!(scrub_entropy_secrets(input), input, "{input}");
        }
    }

    #[test]
    fn leaves_value_just_under_min_length() {
        // 15 unique chars would clear the entropy bar if the value were long enough.
        let input = "token=AbCdEfGhIjKlMnO";
        assert_eq!(scrub_entropy_secrets(input), input);
    }

    #[test]
    fn redaction_is_idempotent_on_its_own_output() {
        let input = format!("db_password={HEX32}");
        let once = scrub_entropy_secrets(&input);
        assert_eq!(scrub_entropy_secrets(&once), once);
    }

    use proptest::prelude::*;

    #[test]
    fn redacts_despite_double_separator() {
        // key==value and key:=value: the stray separator must not flip the
        // charset class and let the secret through.
        let out = scrub_entropy_secrets(&format!("password=={HEX32}"));
        assert!(!out.contains(HEX32), "got: {out}");
        let out = scrub_entropy_secrets(&format!("cfg_token:={HEX32}"));
        assert!(!out.contains(HEX32), "got: {out}");
    }

    #[test]
    fn redacts_padded_quoted_value() {
        let out = scrub_entropy_secrets(&format!("token=\"  {HEX32}  \""));
        assert!(!out.contains(HEX32), "got: {out}");
    }

    #[test]
    fn redacts_pwd_and_session_keys() {
        let out = scrub_entropy_secrets(&format!("db_pwd={HEX32}"));
        assert_eq!(out, "db_pwd=***");
        let out = scrub_entropy_secrets(&format!("sessionid={HEX32}"));
        assert_eq!(out, "sessionid=***");
    }

    #[test]
    fn leaves_pure_decimal_ids_alone() {
        // Numeric identifiers (IDs, phone numbers) must stay visible even in
        // credential-ish contexts.
        let input = "key=15551234567890123";
        assert_eq!(scrub_entropy_secrets(input), input);
    }

    proptest! {
        #[test]
        fn prop_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = scrub_entropy_secrets(&s);
        }

        #[test]
        fn prop_idempotent(s in "[\\s\\S]{0,500}") {
            let once = scrub_entropy_secrets(&s);
            let twice = scrub_entropy_secrets(&once);
            prop_assert_eq!(once, twice);
        }
    }
}
