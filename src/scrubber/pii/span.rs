//! Candidate pooling and overlap resolution.
//!
//! Detectors do **not** run in sequence. TCKN and Turkish mobile numbers are
//! both 11 digits; IMEI, VKN and TCKN collide on digit runs too. Running
//! detectors one after another means whichever registered first eats the
//! other's matches, and the outcome depends on registration order.
//!
//! Instead every detector contributes candidate spans over the same input,
//! then conflicts are resolved once, here, by an explicit priority:
//!   1. checksum-validated beats unvalidated
//!   2. longer span beats shorter
//!   3. fixed detector priority breaks the rest
//!
//! Any overlap at all is a conflict — the loser is dropped whole. Emitting a
//! partially-redacted span would leak the uncovered tail.

use super::alias::{AliasKey, Category};

#[derive(Debug, Clone)]
pub struct Span {
    /// Byte offset, inclusive.
    pub start: usize,
    /// Byte offset, exclusive.
    pub end: usize,
    pub category: Category,
    pub validated: bool,
    /// Lower wins ties. Assigned per detector in `detect.rs`.
    pub priority: u8,
}

impl Span {
    fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Greedy non-overlapping selection in priority order.
pub fn resolve(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| {
        b.validated
            .cmp(&a.validated)
            .then(b.len().cmp(&a.len()))
            .then(a.priority.cmp(&b.priority))
            .then(a.start.cmp(&b.start))
    });

    let mut kept: Vec<Span> = Vec::new();
    for s in spans {
        if !kept.iter().any(|k| k.overlaps(&s)) {
            kept.push(s);
        }
    }
    kept.sort_by_key(|s| s.start);
    kept
}

/// Replace each span with its alias. `spans` must be non-overlapping and
/// sorted by `start` — i.e. the output of `resolve`.
pub fn apply(input: &str, spans: &[Span], key: &AliasKey) -> String {
    if spans.is_empty() {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    for s in spans {
        if s.start < cursor || s.end > input.len() {
            continue; // defensive: malformed span, leave the text alone
        }
        out.push_str(&input[cursor..s.start]);
        out.push_str(&key.alias(s.category, &input[s.start..s.end]));
        cursor = s.end;
    }
    out.push_str(&input[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrubber::pii::alias::{AliasKey, Category};

    fn span(start: usize, end: usize, category: Category, validated: bool, priority: u8) -> Span {
        Span {
            start,
            end,
            category,
            validated,
            priority,
        }
    }

    fn key() -> AliasKey {
        AliasKey::from_bytes(b"deterministic-test-key-0123456789".to_vec())
    }

    #[test]
    fn non_overlapping_spans_all_survive() {
        let out = resolve(vec![
            span(0, 5, Category::Tckn, true, 0),
            span(10, 15, Category::Card, true, 0),
        ]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn validated_beats_unvalidated_on_overlap() {
        // A phone candidate and a TCKN candidate over the same 11 digits.
        let out = resolve(vec![
            span(0, 11, Category::Phone, false, 6),
            span(0, 11, Category::Tckn, true, 0),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].category, Category::Tckn);
    }

    #[test]
    fn longer_beats_shorter_when_both_validated() {
        let out = resolve(vec![
            span(0, 10, Category::Vkn, true, 1),
            span(0, 15, Category::Imei, true, 4),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].category, Category::Imei);
    }

    #[test]
    fn priority_breaks_remaining_ties() {
        let out = resolve(vec![
            span(0, 11, Category::Phone, true, 6),
            span(0, 11, Category::Tckn, true, 0),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].category, Category::Tckn);
    }

    #[test]
    fn partial_overlap_drops_the_loser_entirely() {
        // Overlapping by one byte is still a conflict — never emit a partial
        // redaction that leaks the uncovered tail.
        let out = resolve(vec![
            span(0, 11, Category::Tckn, true, 0),
            span(10, 20, Category::Card, true, 3),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].category, Category::Tckn);
    }

    #[test]
    fn apply_replaces_in_order_and_preserves_surroundings() {
        let input = "id=12345678950 end";
        let spans = vec![span(3, 14, Category::Tckn, true, 0)];
        let out = apply(input, &spans, &key());
        assert!(out.starts_with("id="), "got {out}");
        assert!(out.ends_with(" end"), "got {out}");
        assert!(out.contains("[TCKN_"), "got {out}");
        assert!(!out.contains("12345678950"), "got {out}");
    }

    #[test]
    fn apply_handles_multiple_spans() {
        let input = "a 12345678950 b 12345678950 c";
        let spans = resolve(vec![
            span(2, 13, Category::Tckn, true, 0),
            span(16, 27, Category::Tckn, true, 0),
        ]);
        let out = apply(input, &spans, &key());
        assert!(!out.contains("12345678950"), "got {out}");
        // Same value -> same alias, twice.
        let first = out.find("[TCKN_").expect("first alias");
        let alias = &out[first..first + 15];
        assert_eq!(out.matches(alias).count(), 2, "got {out}");
    }

    #[test]
    fn apply_with_no_spans_is_identity() {
        assert_eq!(apply("untouched", &[], &key()), "untouched");
    }
}
