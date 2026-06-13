// src/scrubber/normalize.rs — input normalization to defeat Unicode and
// concatenation-based evasion of the injection scanner.
use regex::Regex;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

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

fn mn_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\p{Mn}").unwrap())
}

pub(crate) fn detection_shadow(line: &str) -> String {
    let visible = strip_invisible(line);
    let no_marks = mn_regex().replace_all(&visible, "");
    let nfkc: String = no_marks.nfkc().collect();
    let lowered = nfkc.to_lowercase();
    fold_confusables(&lowered)
}

fn fold_confusables(s: &str) -> String {
    s.chars().map(fold_char).collect()
}

fn fold_char(c: char) -> char {
    match c {
        '\u{0430}' => 'a',
        '\u{0435}' => 'e',
        '\u{043E}' => 'o',
        '\u{0440}' => 'p',
        '\u{0441}' => 'c',
        '\u{0445}' => 'x',
        '\u{0443}' => 'y',
        '\u{0456}' => 'i',
        '\u{0458}' => 'j',
        '\u{0455}' => 's',
        '\u{0501}' => 'd',
        '\u{043A}' => 'k',
        '\u{03BF}' => 'o',
        '\u{03B1}' => 'a',
        '\u{03C1}' => 'p',
        '\u{03BD}' => 'v',
        '\u{03B9}' => 'i',
        '\u{03BA}' => 'k',
        _ => c,
    }
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

    #[test]
    fn shadow_folds_fullwidth_and_math_to_ascii() {
        assert_eq!(
            detection_shadow("\u{FF49}\u{FF47}\u{FF4E}\u{FF4F}\u{FF52}\u{FF45}"),
            "ignore"
        ); // ｉｇｎｏｒｅ
        assert_eq!(
            detection_shadow("\u{1D422}\u{1D420}\u{1D427}\u{1D428}\u{1D42B}\u{1D41E}"),
            "ignore"
        ); // 𝐢𝐠𝐧𝐨𝐫𝐞 (bold)
    }

    #[test]
    fn shadow_folds_cyrillic_confusables() {
        // Cyrillic і(U+0456) g n o r e  ->  "ignore"
        assert_eq!(detection_shadow("\u{0456}gnore"), "ignore");
        // Uppercase Cyrillic А(U+0410) -> lowercase -> fold -> 'a'
        assert_eq!(detection_shadow("\u{0410}dmin"), "admin");
    }

    #[test]
    fn shadow_strips_combining_marks() {
        // i + combining acute, g n o r e
        assert_eq!(detection_shadow("i\u{0301}gnore"), "ignore");
    }

    #[test]
    fn shadow_lowercases() {
        assert_eq!(detection_shadow("IGNORE"), "ignore");
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

        #[test]
        fn prop_detection_shadow_does_not_panic(s in "[\\s\\S]{0,500}") {
            // detection_shadow takes a single line; feed it line-by-line.
            for line in s.split('\n') {
                let _ = detection_shadow(line);
            }
        }

        #[test]
        fn prop_detection_shadow_is_idempotent(s in "[a-zA-Z0-9 ]{0,200}") {
            // On already-ASCII-lowercased-foldable input the shadow is stable.
            let once = detection_shadow(&s);
            prop_assert_eq!(detection_shadow(&once), once);
        }
    }
}
