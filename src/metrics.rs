// src/metrics.rs

pub fn estimate_tokens(s: &str) -> usize {
    s.chars().count() / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_empty() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn estimate_ascii() {
        assert_eq!(estimate_tokens("hello world"), 2);
    }

    #[test]
    fn estimate_unicode() {
        assert_eq!(estimate_tokens("Türkçe"), 1);
    }
}
