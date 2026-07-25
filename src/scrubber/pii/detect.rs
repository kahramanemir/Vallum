//! Candidate detection. Each detector pairs a deliberately loose regex with a
//! strict validator: the regex finds shapes, the validator decides. Loose
//! patterns are fine here precisely because nothing survives without passing
//! its checksum and, in `gate.rs`, the context gate.

use super::alias::Category;
use super::gate;
use super::span::Span;
use super::validate;
use regex::Regex;
use std::sync::OnceLock;

/// Push a candidate unless the context gate rules it out — either because the
/// span sits inside a larger technical token, or because its category needs a
/// nearby key name and there is none.
fn push_gated(out: &mut Vec<Span>, input: &str, header: Option<&gate::HeaderContext>, span: Span) {
    if gate::is_suppressed(input, &span) {
        return;
    }
    if span.category.requires_key_context() && !gate::has_positive_context(input, &span, header) {
        return;
    }
    out.push(span);
}

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

fn re_email() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b").unwrap())
}

/// Phones are only ever recognized with an explicit anchor: a `+` country
/// code, or a leading `0` before a Turkish mobile block. A bare digit run is
/// never a phone — that rule is what keeps build IDs, epoch timestamps and
/// order numbers out of the candidate pool.
fn re_phone() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:\+[0-9]{1,3}[ \-]?|\b0)(?:[0-9][ \-]?){8,13}[0-9]\b").unwrap())
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
        end = cand.rfind(' ')?;
    }
}

pub fn candidates(input: &str, active: &[Category]) -> Vec<Span> {
    let mut out = Vec::new();
    let on = |c: Category| active.contains(&c);
    // Parsed once for the whole input: in tabular output the header names the
    // columns for every row below it, not just the first.
    let header = gate::detect_header(input);

    if on(Category::Tckn) {
        for m in re_digits_11().find_iter(input) {
            if validate::tckn(&digits_of(m.as_str())) {
                push_gated(
                    &mut out,
                    input,
                    header.as_ref(),
                    Span {
                        start: m.start(),
                        end: m.end(),
                        category: Category::Tckn,
                        validated: true,
                        priority: 0,
                    },
                );
            }
        }
    }

    if on(Category::Vkn) {
        for m in re_digits_10().find_iter(input) {
            if validate::vkn(&digits_of(m.as_str())) {
                push_gated(
                    &mut out,
                    input,
                    header.as_ref(),
                    Span {
                        start: m.start(),
                        end: m.end(),
                        category: Category::Vkn,
                        validated: true,
                        priority: 1,
                    },
                );
            }
        }
    }

    if on(Category::Iban) {
        for m in re_iban().find_iter(input) {
            if let Some(len) = iban_valid_prefix(m.as_str()) {
                push_gated(
                    &mut out,
                    input,
                    header.as_ref(),
                    Span {
                        start: m.start(),
                        end: m.start() + len,
                        category: Category::Iban,
                        validated: true,
                        priority: 2,
                    },
                );
            }
        }
    }

    if on(Category::Card) {
        for m in re_card().find_iter(input) {
            let d = digits_of(m.as_str());
            if !d.is_empty() && card_prefix_ok(&d) && validate::luhn(&d) {
                push_gated(
                    &mut out,
                    input,
                    header.as_ref(),
                    Span {
                        start: m.start(),
                        end: m.end(),
                        category: Category::Card,
                        validated: true,
                        priority: 3,
                    },
                );
            }
        }
    }

    if on(Category::Imei) {
        for m in re_digits_15().find_iter(input) {
            if validate::luhn(&digits_of(m.as_str())) {
                push_gated(
                    &mut out,
                    input,
                    header.as_ref(),
                    Span {
                        start: m.start(),
                        end: m.end(),
                        category: Category::Imei,
                        validated: true,
                        priority: 4,
                    },
                );
            }
        }
    }

    if on(Category::Email) {
        for m in re_email().find_iter(input) {
            push_gated(
                &mut out,
                input,
                header.as_ref(),
                Span {
                    start: m.start(),
                    end: m.end(),
                    category: Category::Email,
                    validated: false,
                    priority: 5,
                },
            );
        }
    }

    if on(Category::Phone) {
        for m in re_phone().find_iter(input) {
            let text = m.as_str();
            let d = digits_of(text);
            // E.164 caps the whole number at 15 digits; 8 is the shortest
            // plausible subscriber number.
            if !(8..=15).contains(&d.len()) {
                continue;
            }
            let has_plus = text.starts_with('+');
            // Turkish mobile: 0 5XX ... or +90 5XX ...
            let tr_mobile = (d.len() == 11 && d[0] == 0 && d[1] == 5)
                || (d.len() == 12 && d[0] == 9 && d[1] == 0 && d[2] == 5);
            if has_plus || tr_mobile {
                push_gated(
                    &mut out,
                    input,
                    header.as_ref(),
                    Span {
                        start: m.start(),
                        end: m.end(),
                        category: Category::Phone,
                        validated: false,
                        priority: 6,
                    },
                );
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
        assert!(found("card 4111111111111111")
            .iter()
            .any(|(c, _)| *c == Category::Card));
        assert!(found("card 4111 1111 1111 1111")
            .iter()
            .any(|(c, _)| *c == Category::Card));
    }

    #[test]
    fn bare_card_without_a_key_name_is_not_redacted() {
        // Deliberate recall cost of requiring key context: a Luhn-valid,
        // Visa-prefixed run in prose is indistinguishable from a record count
        // (`processed 4111111111111111 records`), so it is left alone.
        assert!(!found("4111111111111111")
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
    fn finds_emails() {
        let hits = found("contact ali@example.com now");
        assert!(
            hits.iter()
                .any(|(c, v)| *c == Category::Email && v == "ali@example.com"),
            "got {hits:?}"
        );
    }

    #[test]
    fn ignores_non_email_at_signs() {
        let hits = found("run cargo@1.85 and user@ and @handle");
        assert!(
            !hits.iter().any(|(c, _)| *c == Category::Email),
            "got {hits:?}"
        );
    }

    #[test]
    fn finds_tr_mobile_in_several_formats() {
        for s in ["+90 555 123 45 67", "05551234567", "+905551234567"] {
            let hits = found(s);
            assert!(
                hits.iter().any(|(c, _)| *c == Category::Phone),
                "no phone in {s:?}: {hits:?}"
            );
        }
    }

    #[test]
    fn phone_never_wins_over_a_valid_tckn() {
        // 11 digits that satisfy TCKN, under a key name so the TCKN candidate
        // clears the context requirement. Both detectors may fire; resolve()
        // must keep the validated one.
        let input = "tckn 12345678950";
        let spans = crate::scrubber::pii::span::resolve(candidates(input, &cats()));
        assert_eq!(spans.len(), 1, "got {spans:?}");
        assert_eq!(spans[0].category, Category::Tckn);
    }

    #[test]
    fn ignores_bare_digit_runs_without_a_phone_anchor() {
        // No +, no leading 0, no 5XX mobile block: not a phone candidate.
        let hits = found("build 17539284611 finished");
        assert!(
            !hits.iter().any(|(c, _)| *c == Category::Phone),
            "got {hits:?}"
        );
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
