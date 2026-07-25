//! Context gating, the second half of the false-positive defense.
//!
//! Checksums cut the candidate pool hard but not far enough: ~1% of random
//! 11-digit runs satisfy the TCKN equations, and a large log contains
//! thousands of numbers. The negative rules below remove digit runs that are
//! structurally *part of something else* — a git SHA, a UUID, a version
//! string, a source position. The positive rules mirror `entropy.rs`'s
//! `KEY_VOCABULARY` approach: a value sitting under a key that names an
//! identifier is worth redacting even when its shape is marginal.
//!
//! The `regex` crate has no lookaround, so all of this inspects the bytes
//! around an already-found match rather than encoding it in the pattern.

use super::alias::Category;
use super::span::Span;

/// Key names that mark a value as an identifier worth redacting.
const KEY_VOCABULARY: &[&str] = &[
    "tckn",
    "kimlik",
    "tc_no",
    "tcno",
    "vkn",
    "vergi",
    "iban",
    "card",
    "kart",
    "phone",
    "telefon",
    "tel",
    "gsm",
    "msisdn",
    "mobile",
    "cep",
    "email",
    "eposta",
    "e_mail",
    "mail",
    "imei",
    "account",
    "hesap",
    "müşteri",
    "musteri",
    "customer",
];

fn byte_before(input: &str, at: usize) -> Option<u8> {
    if at == 0 {
        None
    } else {
        input.as_bytes().get(at - 1).copied()
    }
}

fn byte_after(input: &str, at: usize) -> Option<u8> {
    input.as_bytes().get(at).copied()
}

/// True when the span is structurally part of a larger technical token and
/// must not be treated as personal data.
pub fn is_suppressed(input: &str, span: &Span) -> bool {
    let before = byte_before(input, span.start);
    let after = byte_after(input, span.end);

    // Inside a longer hex/identifier run: a hex letter, another digit or an
    // underscore directly abuts the match.
    let hexish = |b: Option<u8>| matches!(b, Some(c) if c.is_ascii_hexdigit() || c == b'_');
    if hexish(before) || hexish(after) {
        return true;
    }

    // 0x-prefixed literal. `x` is not a hex digit, so the run above does not
    // catch it; require the `0` too so a word ending in `x` does not suppress
    // a following value.
    if span.start >= 2
        && input.as_bytes()[span.start - 1] == b'x'
        && input.as_bytes()[span.start - 2] == b'0'
    {
        return true;
    }

    // Dotted or colon-delimited technical position: semver, file:line:col,
    // IPv4-ish runs. Emails and IBANs legitimately sit next to these, so the
    // rule is restricted to the numeric categories.
    let numeric = !matches!(span.category, Category::Email | Category::Iban);
    if numeric {
        let dotted = |b: Option<u8>| matches!(b, Some(b'.') | Some(b':'));
        if dotted(before) && dotted(after) {
            return true;
        }
        if dotted(before)
            && matches!(byte_before(input, span.start - 1), Some(c) if c.is_ascii_digit())
        {
            return true;
        }
        if dotted(after) && matches!(byte_after(input, span.end + 1), Some(c) if c.is_ascii_digit())
        {
            return true;
        }
    }

    // A hyphen on both sides is a UUID or a compound identifier, not a value.
    // Phones and cards are routinely hyphen-formatted, so they are exempt.
    let hyphenated = !matches!(span.category, Category::Phone | Category::Card);
    if hyphenated && (matches!(before, Some(b'-')) || matches!(after, Some(b'-'))) {
        return true;
    }

    false
}

/// True when a key name near the span names an identifier. Looks back at most
/// 40 bytes — enough for `"customer_tckn": ` without reaching the previous
/// field.
///
/// The lower bound is walked forward to the next char boundary: command
/// output is routinely UTF-8 (`müşteri kimliği 12345678950`), and slicing a
/// `&str` at a non-boundary byte panics.
pub fn has_positive_context(input: &str, span: &Span) -> bool {
    let mut lo = span.start.saturating_sub(40);
    while lo < span.start && !input.is_char_boundary(lo) {
        lo += 1;
    }
    let lower = input[lo..span.start].to_lowercase();
    KEY_VOCABULARY.iter().any(|k| lower.contains(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrubber::pii::alias::Category;
    use crate::scrubber::pii::detect::candidates;

    fn survives(input: &str) -> bool {
        !candidates(input, Category::ALL).is_empty()
    }

    #[test]
    fn suppresses_digits_inside_a_git_sha() {
        assert!(!survives("commit a1b2c3d412345678950f0e9d8c7b6a5f4e3d2c1b"));
    }

    #[test]
    fn suppresses_digits_inside_a_uuid() {
        assert!(!survives("id 12345678-9501-4a2b-8c3d-1234567890ab"));
    }

    #[test]
    fn suppresses_hex_prefixed_values() {
        assert!(!survives("addr 0x12345678950"));
    }

    #[test]
    fn suppresses_file_line_column_positions() {
        assert!(!survives("src/main.rs:12345678950:3"));
    }

    #[test]
    fn suppresses_semver_like_runs() {
        assert!(!survives("version 1.12345678950.3"));
    }

    #[test]
    fn keeps_a_tckn_in_ordinary_prose() {
        assert!(survives("kimlik no 12345678950 kayitli"));
    }

    #[test]
    fn positive_context_is_detected_from_key_names() {
        let input = "tckn=12345678950";
        let spans = candidates(input, Category::ALL);
        assert!(!spans.is_empty());
        assert!(
            has_positive_context(input, &spans[0]),
            "expected key-name context"
        );
    }

    #[test]
    fn neutral_text_yields_no_candidate_for_context_gated_categories() {
        // No key name near the value, so TCKN never becomes a candidate.
        assert!(candidates("value 12345678950 here", Category::ALL).is_empty());
    }

    #[test]
    fn context_free_categories_need_no_key_name() {
        // IBAN and email carry enough intrinsic signal to stand alone.
        assert!(survives("GB82WEST12345698765432"));
        assert!(survives("ali@example.com"));
    }

    #[test]
    fn technical_key_names_do_not_count_as_positive_context() {
        for line in [
            "Content-Length: 12345678950",
            "worker=12345678950",
            "Total: 1234567890 bytes written",
            "Retry-After: 12345678950",
        ] {
            assert!(
                candidates(line, Category::ALL).is_empty(),
                "false positive on {line:?}"
            );
        }
    }
}
