//! Candidate detection. Each detector pairs a deliberately loose regex with a
//! strict validator: the regex finds shapes, the validator decides. Loose
//! patterns are fine here precisely because nothing survives without passing
//! its checksum and, in `gate.rs`, the context gate.

use super::alias::Category;
use super::span::Span;
use super::validate;
use regex::Regex;
use std::sync::OnceLock;

fn digits_of(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect()
}

fn re_digits_11() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b[1-9][0-9]{10}\b").unwrap())
}

fn re_digits_10() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b[0-9]{10}\b").unwrap())
}

fn re_digits_15() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b[0-9]{15}\b").unwrap())
}

fn re_card() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b(?:[0-9][ -]?){12,18}[0-9]\b").unwrap())
}

fn re_iban() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b[A-Za-z]{2}[0-9]{2}(?:[ ]?[A-Za-z0-9]){11,32}\b").unwrap())
}

/// Issued IIN ranges we accept. Luhn alone admits 1 in 10 random digit runs;
/// requiring a real issuer prefix and a matching length is what makes the
/// card detector usable on developer output.
fn card_prefix_ok(d: &[u8]) -> bool {
    let len = d.len();
    let n2 = if d.len() >= 2 { d[0] * 10 + d[1] } else { 0 };
    match d[0] {
        4 => (13..=19).contains(&len),                           // Visa
        5 => (51..=55).contains(&n2) && len == 16,               // Mastercard
        3 => (n2 == 34 || n2 == 37) && len == 15,                // Amex
        6 => (n2 == 65 || n2 == 60) && (16..=19).contains(&len), // Discover
        2 => (22..=27).contains(&n2) && len == 16,               // Mastercard 2-series
        _ => false,
    }
}

/// Length of the valid IBAN at the start of `text`, if any.
///
/// IBANs are commonly printed in space-separated groups of four
/// (`GB82 WEST 1234 5698 7654 32`), so the candidate pattern has to allow
/// interior spaces — which lets a greedy match run past the real end and
/// swallow the following word. Walk back over trailing space-separated tokens
/// until the remainder validates, so both the compact and the grouped form
/// resolve to their true extent.
fn iban_valid_prefix(text: &str) -> Option<usize> {
    let mut end = text.len();
    loop {
        let cand = text[..end].trim_end();
        if cand.len() < 15 {
            return None;
        }
        let country = cand[..2].to_ascii_uppercase();
        let compact_len = cand.chars().filter(|c| !c.is_whitespace()).count();
        if validate::iban_mod97(cand) && validate::iban_length_ok(&country, compact_len) {
            return Some(cand.len());
        }
        match cand.rfind(' ') {
            Some(i) => end = i,
            None => return None,
        }
    }
}

pub fn candidates(input: &str, active: &[Category]) -> Vec<Span> {
    let mut out = Vec::new();
    let on = |c: Category| active.contains(&c);

    if on(Category::Tckn) {
        for m in re_digits_11().find_iter(input) {
            if validate::tckn(&digits_of(m.as_str())) {
                out.push(Span {
                    start: m.start(),
                    end: m.end(),
                    category: Category::Tckn,
                    validated: true,
                    priority: 0,
                });
            }
        }
    }

    if on(Category::Vkn) {
        for m in re_digits_10().find_iter(input) {
            if validate::vkn(&digits_of(m.as_str())) {
                out.push(Span {
                    start: m.start(),
                    end: m.end(),
                    category: Category::Vkn,
                    validated: true,
                    priority: 1,
                });
            }
        }
    }

    if on(Category::Iban) {
        for m in re_iban().find_iter(input) {
            if let Some(len) = iban_valid_prefix(m.as_str()) {
                out.push(Span {
                    start: m.start(),
                    end: m.start() + len,
                    category: Category::Iban,
                    validated: true,
                    priority: 2,
                });
            }
        }
    }

    if on(Category::Card) {
        for m in re_card().find_iter(input) {
            let d = digits_of(m.as_str());
            if !d.is_empty() && card_prefix_ok(&d) && validate::luhn(&d) {
                out.push(Span {
                    start: m.start(),
                    end: m.end(),
                    category: Category::Card,
                    validated: true,
                    priority: 3,
                });
            }
        }
    }

    if on(Category::Imei) {
        for m in re_digits_15().find_iter(input) {
            if validate::luhn(&digits_of(m.as_str())) {
                out.push(Span {
                    start: m.start(),
                    end: m.end(),
                    category: Category::Imei,
                    validated: true,
                    priority: 4,
                });
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrubber::pii::alias::Category;

    fn cats() -> Vec<Category> {
        Category::ALL.to_vec()
    }

    fn found(input: &str) -> Vec<(Category, String)> {
        candidates(input, &cats())
            .into_iter()
            .map(|s| (s.category, input[s.start..s.end].to_string()))
            .collect()
    }

    #[test]
    fn finds_valid_tckn() {
        let hits = found("kimlik: 12345678950 done");
        assert!(
            hits.iter()
                .any(|(c, v)| *c == Category::Tckn && v == "12345678950"),
            "got {hits:?}"
        );
    }

    #[test]
    fn ignores_invalid_tckn_checkdigits() {
        let hits = found("kimlik: 12345678951 done");
        assert!(
            !hits.iter().any(|(c, _)| *c == Category::Tckn),
            "got {hits:?}"
        );
    }

    #[test]
    fn finds_valid_card_with_and_without_spaces() {
        assert!(found("4111111111111111")
            .iter()
            .any(|(c, _)| *c == Category::Card));
        assert!(found("4111 1111 1111 1111")
            .iter()
            .any(|(c, _)| *c == Category::Card));
    }

    #[test]
    fn ignores_luhn_valid_run_without_a_known_iin() {
        // 9999999999999995 satisfies Luhn (sum 140) but 9 is not an issued
        // IIN range.
        assert!(validate::luhn(&digits_of("9999999999999995")));
        let hits = found("9999999999999995");
        assert!(
            !hits.iter().any(|(c, _)| *c == Category::Card),
            "got {hits:?}"
        );
    }

    #[test]
    fn finds_valid_iban() {
        let hits = found("iban GB82WEST12345698765432 ok");
        assert!(
            hits.iter().any(|(c, _)| *c == Category::Iban),
            "got {hits:?}"
        );
    }

    #[test]
    fn finds_grouped_iban_and_stops_at_its_true_end() {
        // Print format has interior spaces, so the candidate pattern can run
        // past the IBAN into the next word. The span must cover the IBAN and
        // nothing more.
        let input = "iban GB82 WEST 1234 5698 7654 32 ok";
        let spans = candidates(input, &cats());
        let iban = spans
            .iter()
            .find(|s| s.category == Category::Iban)
            .expect("iban span");
        assert_eq!(&input[iban.start..iban.end], "GB82 WEST 1234 5698 7654 32");
    }

    #[test]
    fn compact_iban_span_excludes_the_following_word() {
        let input = "iban GB82WEST12345698765432 ok";
        let spans = candidates(input, &cats());
        let iban = spans
            .iter()
            .find(|s| s.category == Category::Iban)
            .expect("iban span");
        assert_eq!(&input[iban.start..iban.end], "GB82WEST12345698765432");
    }

    #[test]
    fn ignores_tampered_iban() {
        let hits = found("iban GB82WEST12345698765433 ok");
        assert!(
            !hits.iter().any(|(c, _)| *c == Category::Iban),
            "got {hits:?}"
        );
    }

    #[test]
    fn respects_the_active_category_list() {
        let hits: Vec<Category> = candidates("kimlik: 12345678950", &[Category::Card])
            .into_iter()
            .map(|s| s.category)
            .collect();
        assert!(hits.is_empty(), "got {hits:?}");
    }

    #[test]
    fn spans_are_byte_accurate_for_multibyte_input() {
        let input = "müşteri kimliği 12345678950 kayıtlı";
        let spans = candidates(input, &cats());
        let tckn = spans
            .iter()
            .find(|s| s.category == Category::Tckn)
            .expect("tckn span");
        assert_eq!(&input[tckn.start..tckn.end], "12345678950");
    }
}
