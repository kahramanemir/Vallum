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

/// A delimited first line whose field names include identifier-ish ones, and
/// which columns those are.
///
/// Byte-distance lookback alone is not enough for tabular output: in a CSV the
/// header sits one line above the first record and many lines above the rest,
/// so a fixed window redacts row 1 and silently leaks every row after it.
/// Column position is the signal that actually generalizes down the table.
pub struct HeaderContext {
    delimiter: char,
    /// Zero-based indices of columns whose header name looks like an
    /// identifier.
    columns: Vec<usize>,
}

const DELIMITERS: [char; 4] = [',', ';', '\t', '|'];

/// Parse the first non-empty line as a delimited header, if it looks like one.
///
/// The structural proof that this is a table, rather than prose that happens
/// to contain a comma, is that some following line splits into the same number
/// of fields. Without that check, `no customer records found, retrying`
/// registers as a header naming a `customer` column and poisons every line
/// under it.
pub fn detect_header(input: &str) -> Option<HeaderContext> {
    let mut lines = input.lines().filter(|l| !l.trim().is_empty());
    let first = lines.next()?;
    let delimiter = *DELIMITERS
        .iter()
        .max_by_key(|d| first.matches(**d).count())?;
    let field_count = first.matches(delimiter).count();
    if field_count == 0 {
        return None;
    }
    if !lines.any(|l| l.matches(delimiter).count() == field_count) {
        return None; // no row matches the header's shape: not a table
    }

    let columns: Vec<usize> = first
        .split(delimiter)
        .enumerate()
        .filter(|(_, name)| {
            let lower = name.trim().trim_matches('"').to_lowercase();
            // Column names are short. A long field is prose, not a name.
            lower.len() <= 24 && contains_key_word(&lower)
        })
        .map(|(i, _)| i)
        .collect();
    if columns.is_empty() {
        return None;
    }
    Some(HeaderContext { delimiter, columns })
}

/// Substring match against `KEY_VOCABULARY`, except that short entries
/// (`vkn`, `tel`, `cep`, `imei`, …) must land on a word boundary. Without
/// that, `telemetry_id=` matches `tel` and `hotel_no=` matches it too — a
/// three-letter substring is not evidence of anything on its own.
fn contains_key_word(haystack: &str) -> bool {
    KEY_VOCABULARY.iter().any(|k| {
        if k.len() > 4 {
            return haystack.contains(k);
        }
        haystack.match_indices(k).any(|(i, _)| {
            let before_ok = i == 0 || !haystack.as_bytes()[i - 1].is_ascii_alphanumeric();
            let after = i + k.len();
            let after_ok =
                after >= haystack.len() || !haystack.as_bytes()[after].is_ascii_alphanumeric();
            before_ok && after_ok
        })
    })
}

/// True when the span sits in a column the header marked as an identifier.
fn in_identifier_column(input: &str, span: &Span, hc: &HeaderContext) -> bool {
    let line_start = input[..span.start].rfind('\n').map_or(0, |i| i + 1);
    // The header line itself carries names, not values.
    if line_start == 0 {
        return false;
    }
    let column = input[line_start..span.start].matches(hc.delimiter).count();
    hc.columns.contains(&column)
}

/// True when a key name identifies the span as personal data — either a key
/// name within 40 bytes to the left (`tckn=`, `"customer_tckn": `), or a
/// delimited-table column whose header names one.
///
/// The lookback's lower bound is walked forward to the next char boundary:
/// command output is routinely UTF-8 (`müşteri kimliği 12345678950`), and
/// slicing a `&str` at a non-boundary byte panics.
pub fn has_positive_context(input: &str, span: &Span, header: Option<&HeaderContext>) -> bool {
    // Clamped to the current line: a key name on the line above is not a key
    // for this value. That relationship exists only in tabular data, and it is
    // the column check below — not distance — that expresses it.
    let line_start = input[..span.start].rfind('\n').map_or(0, |i| i + 1);
    let mut lo = span.start.saturating_sub(40).max(line_start);
    while lo < span.start && !input.is_char_boundary(lo) {
        lo += 1;
    }
    let lower = input[lo..span.start].to_lowercase();
    if contains_key_word(&lower) {
        return true;
    }
    header.is_some_and(|hc| in_identifier_column(input, span, hc))
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
            has_positive_context(input, &spans[0], None),
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
    fn csv_header_gives_context_to_every_row_not_just_the_first() {
        // Regression guard: a fixed byte-distance lookback reaches the header
        // from row 1 only, which redacts the first record and silently leaks
        // the rest. Column position has to carry down the whole table.
        let input = "musteri,tckn\nAli,12345678950\nAyse,10000000146\nAli,12345678950\n";
        let spans = candidates(input, Category::ALL);
        let tckns: Vec<&str> = spans
            .iter()
            .filter(|s| s.category == Category::Tckn)
            .map(|s| &input[s.start..s.end])
            .collect();
        assert_eq!(tckns.len(), 3, "expected every row gated in, got {tckns:?}");
    }

    #[test]
    fn csv_context_is_scoped_to_the_named_column() {
        // Only the `tckn` column gets context; a checksum-valid value in an
        // unrelated column stays visible.
        let input = "sira,tckn\n12345678950,10000000146\n";
        let spans = candidates(input, Category::ALL);
        let tckns: Vec<&str> = spans
            .iter()
            .filter(|s| s.category == Category::Tckn)
            .map(|s| &input[s.start..s.end])
            .collect();
        assert_eq!(tckns, vec!["10000000146"], "got {tckns:?}");
    }

    #[test]
    fn a_prose_line_with_a_comma_is_not_treated_as_a_header() {
        let input = "no customer records found, retrying\nContent-Length: 12345678950\n";
        assert!(candidates(input, Category::ALL).is_empty());
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
