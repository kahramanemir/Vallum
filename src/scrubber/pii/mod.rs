//! Privacy mode: checksum-validated PII detection and pseudonymous redaction.
//!
//! This is the deliberate complement of a decision documented in `entropy.rs`:
//! pure-decimal values are exempt there, because numeric identifiers must stay
//! visible in ordinary output. Every identifier this module targets is
//! pure-decimal, so it needs its own pass with its own gates.
//!
//! Off by default. See `docs/superpowers/specs/2026-07-25-pii-privacy-mode-design.md`.

pub mod alias;
pub mod detect;
pub mod gate;
pub mod span;
pub mod validate;

use crate::config::AppConfig;
use alias::{AliasKey, Category};

/// Everything the PII pass needs, built once per invocation.
pub struct PrivacyOptions {
    key: AliasKey,
    categories: Vec<Category>,
}

impl PrivacyOptions {
    pub fn from_config(cfg: &AppConfig) -> Self {
        Self {
            key: AliasKey::from_config(cfg),
            categories: cfg.privacy.active(),
        }
    }
}

/// Detect and pseudonymize PII. Runs after `secrets::scrub_secrets` so vendor
/// token patterns consume their matches first — a JWT or API key can contain
/// a Luhn-valid digit run, and letting the card detector reach it would chew
/// the middle out of an already-masked token.
pub fn scrub_pii(input: &str, opts: &PrivacyOptions) -> String {
    if opts.categories.is_empty() {
        return input.to_string();
    }
    let spans = span::resolve(detect::candidates(input, &opts.categories));
    span::apply(input, &spans, &opts.key)
}
