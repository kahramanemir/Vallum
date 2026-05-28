// src/ansi.rs
use regex::Regex;
use std::sync::OnceLock;

pub fn strip(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
            .unwrap()
    });
    re.replace_all(input, "").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_basic_color() {
        let input = "\x1b[31mError\x1b[0m: failed";
        assert_eq!(strip(input), "Error: failed");
    }

    #[test]
    fn strip_cursor_move() {
        let input = "line1\x1b[2Aline2";
        assert_eq!(strip(input), "line1line2");
    }

    #[test]
    fn preserve_plain_text() {
        let input = "hello world";
        assert_eq!(strip(input), "hello world");
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_strip_does_not_panic(s in "[\\s\\S]{0,1000}") {
            let _ = strip(&s);
        }

        #[test]
        fn prop_strip_never_grows(s in "[\\s\\S]{0,1000}") {
            let out = strip(&s);
            prop_assert!(out.len() <= s.len());
        }
    }
}
