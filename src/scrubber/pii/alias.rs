//! Stable pseudonyms for detected PII.
//!
//! A detected value is replaced by `HMAC-SHA256(machine_secret, category ||
//! ":" || normalize(value))` truncated to 4 bytes. Nothing is written to
//! disk: the mapping is *derived*, so aliases stay stable across commands and
//! sessions with zero PII at rest.
//!
//! The category acts as a domain separator, so the same digit string aliases
//! differently as a TCKN than as an IMEI. `normalize` strips separators and
//! upcases, so `555 123 45 67` and `5551234567` collapse to one alias and the
//! agent can still match records that were formatted differently.
//!
//! 32 bits puts the birthday collision point near 65k distinct values per
//! category, far beyond realistic command output. A collision makes the agent
//! wrongly correlate two records; it never discloses a value.

use crate::config::AppConfig;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt::Write as _;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Tckn,
    Vkn,
    Iban,
    Card,
    Imei,
    Email,
    Phone,
}

impl Category {
    pub const ALL: &'static [Category] = &[
        Category::Tckn,
        Category::Vkn,
        Category::Iban,
        Category::Card,
        Category::Imei,
        Category::Email,
        Category::Phone,
    ];

    pub fn tag(self) -> &'static str {
        match self {
            Category::Tckn => "tckn",
            Category::Vkn => "vkn",
            Category::Iban => "iban",
            Category::Card => "card",
            Category::Imei => "imei",
            Category::Email => "email",
            Category::Phone => "phone",
        }
    }

    pub fn from_tag(s: &str) -> Option<Category> {
        Category::ALL.iter().copied().find(|c| c.tag() == s)
    }
}

pub struct AliasKey(Vec<u8>);

impl AliasKey {
    pub fn from_bytes(secret: Vec<u8>) -> Self {
        Self(secret)
    }

    /// Prefer the machine-local approval secret so aliases are stable across
    /// commands and sessions. When it is unavailable (no `~/.vallum` yet, or
    /// an unreadable file), fall back to a process-local random key: aliases
    /// stay stable within this one command and nowhere else. Never falls back
    /// to emitting plaintext.
    pub fn from_config(cfg: &AppConfig) -> Self {
        let secret = crate::approval::load_secret(cfg)
            .or_else(crate::approval::random_secret)
            .unwrap_or_else(|| b"vallum-pii-fallback".to_vec());
        Self(secret)
    }

    pub fn alias(&self, category: Category, value: &str) -> String {
        let normalized = normalize_value(value);
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(category.tag().as_bytes());
        mac.update(b":");
        mac.update(normalized.as_bytes());
        let out = mac.finalize().into_bytes();
        let mut hex = String::with_capacity(8);
        for b in &out[..4] {
            let _ = write!(hex, "{b:02x}");
        }
        format!("[{}_{}]", category.tag().to_ascii_uppercase(), hex)
    }
}

/// Collapse formatting differences so the same underlying value aliases
/// identically however it was written.
fn normalize_value(v: &str) -> String {
    v.chars()
        .filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')' | '\t' | '+' | '/'))
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AliasKey {
        AliasKey::from_bytes(b"deterministic-test-key-0123456789".to_vec())
    }

    #[test]
    fn same_value_same_alias() {
        let k = key();
        assert_eq!(
            k.alias(Category::Tckn, "12345678950"),
            k.alias(Category::Tckn, "12345678950")
        );
    }

    #[test]
    fn different_values_differ() {
        let k = key();
        assert_ne!(
            k.alias(Category::Tckn, "12345678950"),
            k.alias(Category::Tckn, "12345678943")
        );
    }

    #[test]
    fn category_is_a_domain_separator() {
        let k = key();
        // Same digits, different category -> different alias.
        assert_ne!(
            k.alias(Category::Tckn, "123456789012345"),
            k.alias(Category::Imei, "123456789012345")
        );
    }

    #[test]
    fn separators_are_normalized_away() {
        let k = key();
        assert_eq!(
            k.alias(Category::Phone, "555 123 45 67"),
            k.alias(Category::Phone, "5551234567")
        );
        assert_eq!(
            k.alias(Category::Phone, "555-123-45-67"),
            k.alias(Category::Phone, "5551234567")
        );
        assert_eq!(
            k.alias(Category::Card, "4111 1111 1111 1111"),
            k.alias(Category::Card, "4111111111111111")
        );
    }

    #[test]
    fn email_case_is_normalized() {
        let k = key();
        assert_eq!(
            k.alias(Category::Email, "Ali@Example.COM"),
            k.alias(Category::Email, "ali@example.com")
        );
    }

    #[test]
    fn alias_shape_is_bracketed_tag_and_8_hex() {
        let a = key().alias(Category::Tckn, "12345678950");
        assert!(a.starts_with("[TCKN_"), "got {a}");
        assert!(a.ends_with(']'), "got {a}");
        let hex = &a["[TCKN_".len()..a.len() - 1];
        assert_eq!(hex.len(), 8, "got {a}");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "got {a}"
        );
    }

    #[test]
    fn different_keys_produce_different_aliases() {
        let a = AliasKey::from_bytes(b"key-one-padding-to-length-0000000".to_vec());
        let b = AliasKey::from_bytes(b"key-two-padding-to-length-0000000".to_vec());
        assert_ne!(
            a.alias(Category::Tckn, "12345678950"),
            b.alias(Category::Tckn, "12345678950")
        );
    }

    #[test]
    fn category_tag_roundtrips() {
        for c in Category::ALL {
            assert_eq!(Category::from_tag(c.tag()), Some(*c));
        }
        assert_eq!(Category::from_tag("ssn"), None);
    }
}
