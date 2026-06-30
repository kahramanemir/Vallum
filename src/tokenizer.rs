//! Pluggable `TokenEstimator` with a dependency-free heuristic default.

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

/// Exact BPE token counting via tiktoken (o200k_base, the GPT-4o-family BPE).
/// Compiled only with `--features bpe`. This is an OpenAI-family tokenizer — a
/// close approximation of, not identical to, Claude's tokenizer, and far more
/// accurate than the heuristic.
#[cfg(feature = "bpe")]
pub struct BpeEstimator {
    bpe: tiktoken_rs::CoreBPE,
}

#[cfg(feature = "bpe")]
impl BpeEstimator {
    pub fn new() -> Self {
        Self {
            bpe: tiktoken_rs::o200k_base().expect("load o200k_base tokenizer"),
        }
    }
}

#[cfg(feature = "bpe")]
impl Default for BpeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "bpe")]
impl TokenEstimator for BpeEstimator {
    fn estimate(&self, s: &str) -> usize {
        self.bpe.encode_ordinary(s).len()
    }
}

#[cfg(all(test, feature = "bpe"))]
mod bpe_tests {
    use super::*;

    #[test]
    fn bpe_counts_are_plausible() {
        let est = BpeEstimator::new();
        assert_eq!(est.estimate(""), 0);
        assert!(est.estimate("hello world") >= 2);
        let long = "the quick brown fox ".repeat(50);
        assert!(est.estimate(&long) > est.estimate("the quick brown fox "));
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
