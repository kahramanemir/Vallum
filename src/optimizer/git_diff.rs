// src/optimizer/git_diff.rs
use super::{collapse_noise_runs, CommandOptimizer};

pub struct GitDiffOptimizer;

impl CommandOptimizer for GitDiffOptimizer {
    fn name(&self) -> &'static str {
        "git_diff"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        cmd == "git" && args.iter().any(|a| a == "diff")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        // Noise = unchanged context lines (leading space) and blank lines.
        // Kept = headers (diff --git, @@, +++, ---, index ...) and changed
        // lines (start with '+' or '-'; +++/--- also start with +/-).
        collapse_noise_runs(
            input,
            15,
            |line| line.is_empty() || line.starts_with(' '),
            "unchanged lines",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_git_diff() {
        assert!(GitDiffOptimizer.matches("git", &args(&["diff"])));
        assert!(GitDiffOptimizer.matches("git", &args(&["diff", "--cached"])));
        assert!(!GitDiffOptimizer.matches("git", &args(&["status"])));
        assert!(!GitDiffOptimizer.matches("cargo", &args(&["diff"])));
    }

    #[test]
    fn collapses_context_keeps_changes() {
        let mut input = String::from("diff --git a/f.rs b/f.rs\n@@ -1,30 +1,30 @@\n");
        for i in 0..25 {
            input.push_str(&format!(" context line {}\n", i)); // unchanged
        }
        input.push_str("-old line\n+new line\n");
        let out = GitDiffOptimizer.optimize(&input).unwrap();
        assert!(out.contains("diff --git a/f.rs b/f.rs"));
        assert!(out.contains("@@ -1,30 +1,30 @@"));
        assert!(out.contains("-old line"));
        assert!(out.contains("+new line"));
        assert!(out.contains("unchanged lines hidden"));
        assert!(out.lines().count() < input.lines().count());
    }

    #[test]
    fn passthrough_small_diff() {
        let input = "diff --git a/f b/f\n@@ -1 +1 @@\n-a\n+b\n";
        assert!(GitDiffOptimizer.optimize(input).is_none());
    }
}
