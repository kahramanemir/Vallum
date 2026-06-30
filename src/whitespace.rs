//! Collapse runs of blank lines and strip trailing whitespace.

pub fn collapse(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut blank_run: usize = 0;

    for line in input.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            blank_run += 1;
            continue;
        }

        let to_emit = if blank_run >= 3 { 1 } else { blank_run };
        for _ in 0..to_emit {
            result.push('\n');
        }
        blank_run = 0;

        result.push_str(trimmed);
        result.push('\n');
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_triple_blank_to_single() {
        let input = "a\n\n\n\nb\n";
        let expected = "a\n\nb\n";
        assert_eq!(collapse(input), expected);
    }

    #[test]
    fn preserve_double_blank() {
        let input = "a\n\n\nb\n";
        let expected = "a\n\n\nb\n";
        assert_eq!(collapse(input), expected);
    }

    #[test]
    fn strip_trailing_spaces() {
        let input = "hello   \nworld\t\n";
        let expected = "hello\nworld\n";
        assert_eq!(collapse(input), expected);
    }

    #[test]
    fn preserve_meaningful_indent() {
        let input = "    indented line\n";
        let expected = "    indented line\n";
        assert_eq!(collapse(input), expected);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_collapse_does_not_panic(s in "[\\s\\S]{0,1000}") {
            let _ = collapse(&s);
        }

        #[test]
        fn prop_collapse_no_quad_newline(s in "[\\s\\S]{0,1000}") {
            // After collapse, no run of 4+ consecutive newlines remains
            // (which would represent 3+ blank lines between text).
            let out = collapse(&s);
            prop_assert!(!out.contains("\n\n\n\n"));
        }
    }
}
