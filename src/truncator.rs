const CONTEXT: usize = 2;

fn is_important(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("error[")
        || lower.contains("error:")
        || lower.contains("panicked at")
        || lower.contains("exception")
        || lower.contains("fatal")
        || line.contains("FAILED")
}

pub fn smart_truncate(input: &str, head_limit: usize, tail_limit: usize) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let total = lines.len();

    if total <= head_limit + tail_limit {
        return input.to_string();
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
            result.push_str(lines[i]);
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
        assert_eq!(smart_truncate(input, 5, 5), input);
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

        let result = smart_truncate(&input, 2, 2);
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
        let result = smart_truncate(&input, 2, 2);
        // None of the middle "no errors" lines should be force-kept as important.
        assert!(result.contains("lines hidden"));
    }
}
