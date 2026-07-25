//! Privacy mode: checksum-validated PII detection and pseudonymous redaction.
//!
//! This is the deliberate complement of a decision documented in `entropy.rs`:
//! pure-decimal values are exempt there, because numeric identifiers must stay
//! visible in ordinary output. Every identifier this module targets is
//! pure-decimal, so it needs its own pass with its own gates.
//!
//! Off by default. See `docs/superpowers/specs/2026-07-25-pii-privacy-mode-design.md`.

pub mod alias;
pub mod validate;
