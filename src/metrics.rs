//! Token estimation and the per-command JSONL stats writer (`~/.vallum/stats.jsonl`).

use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn estimate_tokens(s: &str) -> usize {
    #[cfg(feature = "bpe")]
    {
        use crate::tokenizer::{BpeEstimator, TokenEstimator};
        thread_local! {
            static EST: BpeEstimator = BpeEstimator::new();
        }
        EST.with(|e| e.estimate(s))
    }
    #[cfg(not(feature = "bpe"))]
    {
        use crate::tokenizer::{HeuristicEstimator, TokenEstimator};
        HeuristicEstimator.estimate(s)
    }
}

#[derive(Serialize)]
pub struct StatEntry {
    pub ts: String,
    pub cmd: String,
    pub args: Vec<String>,
    pub tokens_before: usize,
    pub tokens_after: usize,
    pub optimizer: Option<String>,
    pub exit_code: i32,
}

/// None when the home directory is unknown — stats must not silently land in
/// the working directory.
pub fn stats_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".vallum").join("stats.jsonl"))
}

pub fn append_stat_to(path: &Path, entry: &StatEntry) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = crate::fsutil::open_append_private(path)?;
    let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    writeln!(file, "{}", line)
}

pub fn append_stat(entry: &StatEntry) {
    if let Some(path) = stats_path() {
        let _ = append_stat_to(&path, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_empty() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[cfg(not(feature = "bpe"))]
    #[test]
    fn estimate_ascii() {
        assert_eq!(estimate_tokens("hello world"), 2);
    }

    #[cfg(not(feature = "bpe"))]
    #[test]
    fn estimate_unicode() {
        assert_eq!(estimate_tokens("Türkçe"), 1);
    }

    #[test]
    fn append_stat_creates_file_and_dir() {
        use std::fs;
        let tmp = std::env::temp_dir().join("vallum_test_metrics_append");
        let _ = fs::remove_dir_all(&tmp);
        let path = tmp.join("nested").join("stats.jsonl");

        let entry = StatEntry {
            ts: "2026-01-01T00:00:00Z".to_string(),
            cmd: "ls".to_string(),
            args: vec!["-la".to_string()],
            tokens_before: 100,
            tokens_after: 20,
            optimizer: None,
            exit_code: 0,
        };

        append_stat_to(&path, &entry).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"cmd\":\"ls\""));
        assert!(content.contains("\"tokens_before\":100"));
        assert!(content.contains("\"tokens_after\":20"));
        let _ = fs::remove_dir_all(&tmp);
    }
}
