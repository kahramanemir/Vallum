//! Context-preserving head/tail truncation that keeps error lines in place.

const CONTEXT: usize = 2;

/// Truncate a single line longer than `max_len` chars to
/// `<head>…[N chars elided]…<tail>`, operating on char boundaries so the
/// result is always valid UTF-8. `max_len == 0` disables capping.
pub fn cap_line_length(line: &str, max_len: usize) -> String {
    if max_len == 0 {
        return line.to_string();
    }
    let chars: Vec<char> = line.chars().collect();
    if chars.len() <= max_len {
        return line.to_string();
    }
    let head_n = max_len / 2;
    let tail_n = max_len / 2;
    let elided = chars.len() - head_n - tail_n;
    let head: String = chars[..head_n].iter().collect();
    let tail: String = chars[chars.len() - tail_n..].iter().collect();
    format!("{}…[{} chars elided]…{}", head, elided, tail)
}

fn is_important(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("error[")
        || lower.contains("error:")
        || lower.contains("panicked at")
        || lower.contains("exception")
        || lower.contains("fatal")
        || line.contains("FAILED")
}

pub fn smart_truncate(
    input: &str,
    head_limit: usize,
    tail_limit: usize,
    max_line_length: usize,
) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let total = lines.len();

    if total <= head_limit + tail_limit {
        if max_line_length == 0 {
            return input.to_string();
        }
        let mut out = String::new();
        for line in &lines {
            out.push_str(&cap_line_length(line, max_line_length));
            out.push('\n');
        }
        return out;
    }

    // Decide which indices to keep: head window, tail window, and any important
    // line plus +/-CONTEXT lines around it.
    let mut keep = vec![false; total];
    for (i, slot) in keep.iter_mut().enumerate() {
        if i < head_limit || i >= total - tail_limit {
            *slot = true;
        }
    }
    for (i, line) in lines.iter().enumerate() {
        if is_important(line) {
            let lo = i.saturating_sub(CONTEXT);
            let hi = (i + CONTEXT + 1).min(total);
            for slot in keep.iter_mut().take(hi).skip(lo) {
                *slot = true;
            }
        }
    }

    let mut result = String::new();
    let mut i = 0;
    while i < total {
        if keep[i] {
            result.push_str(&cap_line_length(lines[i], max_line_length));
            result.push('\n');
            i += 1;
        } else {
            let gap_start = i;
            while i < total && !keep[i] {
                i += 1;
            }
            let hidden = i - gap_start;
            result.push_str(&format!("[... {} lines hidden ...]\n", hidden));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_short_output() {
        let input = "Line 1\nLine 2\nLine 3\n";
        assert_eq!(smart_truncate(input, 5, 5, 0), input);
    }

    #[test]
    fn test_error_kept_in_place_with_context() {
        let mut input = String::from("head1\nhead2\n");
        for i in 0..20 {
            input.push_str(&format!("mid{}\n", i));
        }
        input.push_str("error: boom\n");
        for i in 0..20 {
            input.push_str(&format!("tail_mid{}\n", i));
        }
        input.push_str("end1\nend2\n");

        let result = smart_truncate(&input, 2, 2, 0);
        // Head and tail windows preserved.
        assert!(result.contains("head1"));
        assert!(result.contains("end2"));
        // Error preserved with adjacent context, in original order.
        assert!(result.contains("error: boom"));
        let err_pos = result.find("error: boom").unwrap();
        let ctx_pos = result.find("mid19").unwrap();
        assert!(ctx_pos < err_pos, "context line should precede the error");
        // Ordinary gaps elided.
        assert!(result.contains("lines hidden"));
        // "no errors" style lines must NOT be flagged as errors.
        assert!(!result.contains("[IMPORTANT"));
    }

    #[test]
    fn test_no_false_positive_on_no_errors_phrase() {
        let mut input = String::from("start\n");
        for _ in 0..30 {
            input.push_str("no errors here\n");
        }
        input.push_str("done\n");
        let result = smart_truncate(&input, 2, 2, 0);
        // None of the middle "no errors" lines should be force-kept as important.
        assert!(result.contains("lines hidden"));
    }

    #[test]
    fn caps_overlong_line_on_char_boundary() {
        let long = "x".repeat(5000);
        let capped = cap_line_length(&long, 100);
        assert!(capped.len() < long.len());
        assert!(capped.contains("chars elided"));
    }

    #[test]
    fn short_line_untouched_and_zero_disables() {
        assert_eq!(cap_line_length("short", 100), "short");
        let long = "y".repeat(5000);
        assert_eq!(cap_line_length(&long, 0), long); // 0 disables
    }

    #[test]
    fn cap_is_utf8_safe() {
        let s = "é".repeat(1000); // 2 bytes each
        let capped = cap_line_length(&s, 50);
        assert!(capped.chars().count() < s.chars().count());
        assert!(capped.contains("chars elided"));
    }

    #[test]
    fn smart_truncate_applies_line_cap() {
        let long = format!("prefix {} suffix", "z".repeat(5000));
        let input = format!("a\n{}\nb\n", long);
        let out = smart_truncate(&input, 5, 5, 100);
        assert!(out.contains("chars elided"));
        assert!(!out.contains(&"z".repeat(5000)));
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_cap_line_length_does_not_panic(s in "[\\s\\S]{0,2000}", max in 0usize..=2000) {
            let _ = cap_line_length(&s, max);
        }

        #[test]
        fn prop_cap_line_length_bounded(s in "[\\s\\S]{0,2000}", max in 1usize..=2000) {
            let out = cap_line_length(&s, max);
            // The output's char count never exceeds max plus a small marker budget
            // (the elision marker "…[N chars elided]…" stays within ~32 chars even
            // for very large N).
            prop_assert!(out.chars().count() <= max + 32);
        }

        #[test]
        fn prop_cap_line_length_zero_is_identity(s in "[\\s\\S]{0,2000}") {
            prop_assert_eq!(cap_line_length(&s, 0), s);
        }

        #[test]
        fn prop_smart_truncate_does_not_panic(
            s in "[\\s\\S]{0,2000}",
            head in 0usize..50,
            tail in 0usize..50,
            cap in 0usize..2000,
        ) {
            let _ = smart_truncate(&s, head, tail, cap);
        }
    }
}
