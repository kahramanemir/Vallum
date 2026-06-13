// src/scrubber/normalize.rs — input normalization to defeat Unicode and
// concatenation-based evasion of the injection scanner.

/// Code points that are never legitimate in terminal output and are used to
/// break keyword matching: zero-width joiners/spaces, BOM, and bidi controls
/// (the "Trojan Source" set).
const INVISIBLE: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{2060}', // WORD JOINER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE / BOM
    '\u{202A}', // LRE
    '\u{202B}', // RLE
    '\u{202C}', // PDF
    '\u{202D}', // LRO
    '\u{202E}', // RLO
    '\u{2066}', // LRI
    '\u{2067}', // RLI
    '\u{2068}', // FSI
    '\u{2069}', // PDI
];

/// Remove invisible/bidi code points. This is the only normalization step that
/// changes the bytes the agent sees. Total and idempotent; everything else
/// (whitespace, combining marks, printables) is preserved.
pub fn strip_invisible(s: &str) -> String {
    if !s.chars().any(|c| INVISIBLE.contains(&c)) {
        return s.to_string();
    }
    s.chars().filter(|c| !INVISIBLE.contains(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_and_bidi() {
        // ZWSP between letters, plus a bidi override and a BOM.
        let s = "ig\u{200B}nore\u{202E}\u{FEFF}";
        assert_eq!(strip_invisible(s), "ignore");
    }

    #[test]
    fn leaves_ordinary_text_and_whitespace_untouched() {
        let s = "café ☕\n\tTürkçe — ok";
        assert_eq!(strip_invisible(s), s);
    }

    #[test]
    fn strip_invisible_is_idempotent() {
        let s = "a\u{200D}b\u{2069}c";
        let once = strip_invisible(s);
        assert_eq!(strip_invisible(&once), once);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_strip_invisible_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = strip_invisible(&s);
        }

        // Only removes the fixed INVISIBLE set: every surviving char of the
        // output was present in the input, and no INVISIBLE char survives.
        #[test]
        fn prop_strip_invisible_only_removes_target_set(s in "[\\s\\S]{0,500}") {
            let out = strip_invisible(&s);
            prop_assert!(out.chars().all(|c| !INVISIBLE.contains(&c)));
            prop_assert!(out.chars().all(|c| s.contains(c)));
        }
    }
}
