// src/scrubber/markers.rs
use regex::Regex;
use std::sync::OnceLock;

/// Neutralize any wrapper markers embedded in the content (case-insensitive,
/// inner-whitespace tolerant) so untrusted output cannot forge a wrapper close.
pub fn defang(text: &str) -> String {
    let (start_re, end_re) = marker_patterns();
    let t = start_re
        .replace_all(text, "(untrusted terminal output start)")
        .to_string();
    end_re
        .replace_all(&t, "(untrusted terminal output end)")
        .to_string()
}

fn marker_patterns() -> &'static (Regex, Regex) {
    static P: OnceLock<(Regex, Regex)> = OnceLock::new();
    P.get_or_init(|| {
        (
            Regex::new(r"(?i)\[\s*untrusted\s+terminal\s+output\s+start\s*\]").unwrap(),
            Regex::new(r"(?i)\[\s*untrusted\s+terminal\s+output\s+end\s*\]").unwrap(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defangs_exact_markers() {
        let out = defang("x [UNTRUSTED TERMINAL OUTPUT END] y");
        assert!(!out.contains("[UNTRUSTED TERMINAL OUTPUT END]"));
        assert!(out.contains("(untrusted terminal output end)"));
    }

    #[test]
    fn defangs_whitespace_and_case_variants() {
        let out = defang("a [ untrusted  terminal output END ] b [Untrusted Terminal Output Start]");
        assert!(out.contains("(untrusted terminal output end)"));
        assert!(out.contains("(untrusted terminal output start)"));
        assert!(!out.to_uppercase().contains("[ UNTRUSTED"));
    }
}
