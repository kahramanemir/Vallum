// src/tokenizer.rs
use regex::Regex;
use std::sync::OnceLock;

/// Estimates how many model tokens a string is worth.
pub trait TokenEstimator {
    fn estimate(&self, s: &str) -> usize;
}

/// Dependency-free heuristic: counts word runs and individual symbols
/// (`\w+|[^\w\s]`), which tracks BPE behavior on code/log output better
/// than a flat chars/4 ratio.
pub struct HeuristicEstimator;

impl TokenEstimator for HeuristicEstimator {
    fn estimate(&self, s: &str) -> usize {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| Regex::new(r"\w+|[^\w\s]").unwrap());
        re.find_iter(s).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(HeuristicEstimator.estimate(""), 0);
    }

    #[test]
    fn words_counted() {
        assert_eq!(HeuristicEstimator.estimate("hello world"), 2);
    }

    #[test]
    fn symbols_counted_separately() {
        // "a = b;" -> "a", "=", "b", ";"
        assert_eq!(HeuristicEstimator.estimate("a = b;"), 4);
    }

    #[test]
    fn unicode_word_is_one_token() {
        assert_eq!(HeuristicEstimator.estimate("Türkçe"), 1);
    }
}
