// src/optimizer/git_status.rs
use super::CommandOptimizer;

pub struct GitStatusOptimizer;

const SECTION_HEADERS: &[&str] = &[
    "Changes to be committed:",
    "Changes not staged for commit:",
    "Untracked files:",
    "Unmerged paths:",
];

impl CommandOptimizer for GitStatusOptimizer {
    fn name(&self) -> &'static str {
        "git_status"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        if cmd != "git" {
            return false;
        }
        let has_status = args.iter().any(|a| a == "status");
        let has_porcelain = args
            .iter()
            .any(|a| a.starts_with("--porcelain") || a == "-z");
        has_status && !has_porcelain
    }

    fn optimize(&self, input: &str) -> Option<String> {
        if input.lines().count() < 15 {
            return None;
        }

        let mut header: Vec<String> = Vec::new();
        let mut sections: Vec<(String, Vec<String>)> = Vec::new();
        let mut current: Option<(String, Vec<String>)> = None;
        let mut in_header = true;

        for line in input.lines() {
            if SECTION_HEADERS.iter().any(|h| line.starts_with(h)) {
                in_header = false;
                if let Some(prev) = current.take() {
                    sections.push(prev);
                }
                current = Some((line.to_string(), Vec::new()));
                continue;
            }

            let trimmed = line.trim();

            if trimmed.starts_with('(') && trimmed.ends_with(')') {
                continue;
            }

            if in_header {
                if !trimmed.is_empty() {
                    header.push(line.to_string());
                }
            } else if let Some((_, items)) = current.as_mut() {
                if trimmed.is_empty() || line.starts_with("no changes added") {
                    continue;
                }
                items.push(line.to_string());
            }
        }

        if let Some(prev) = current.take() {
            sections.push(prev);
        }

        let mut out = String::new();
        for h in &header {
            out.push_str(h);
            out.push('\n');
        }
        out.push('\n');

        for (title, items) in &sections {
            let count = items.len();
            out.push_str(title);
            out.push_str(&format!(" ({} files)\n", count));

            if count <= 10 {
                for item in items {
                    out.push_str(item);
                    out.push('\n');
                }
            } else {
                for item in items.iter().take(5) {
                    out.push_str(item);
                    out.push('\n');
                }
                out.push_str(&format!("\t... {} more files ...\n", count - 7));
                for item in items.iter().rev().take(2).rev() {
                    out.push_str(item);
                    out.push('\n');
                }
            }
            out.push('\n');
        }

        out.push_str("[summarized by vallum]\n");
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_git_status() {
        let opt = GitStatusOptimizer;
        assert!(opt.matches("git", &args(&["status"])));
    }

    #[test]
    fn not_match_git_log() {
        let opt = GitStatusOptimizer;
        assert!(!opt.matches("git", &args(&["log"])));
    }

    #[test]
    fn not_match_porcelain() {
        let opt = GitStatusOptimizer;
        assert!(!opt.matches("git", &args(&["status", "--porcelain"])));
    }

    #[test]
    fn passthrough_short_status() {
        let opt = GitStatusOptimizer;
        let input = "On branch main\nnothing to commit\n";
        assert!(opt.optimize(input).is_none());
    }

    #[test]
    fn compress_long_status() {
        let opt = GitStatusOptimizer;
        let mut files = String::new();
        for i in 0..40 {
            files.push_str(&format!("\tmodified:   src/file_{}.rs\n", i));
        }
        let input = format!(
            "On branch main\nYour branch is up to date with 'origin/main'.\n\nChanges to be committed:\n  (use \"git restore --staged <file>...\" to unstage)\n{}\n",
            files
        );
        let result = opt.optimize(&input).unwrap();
        assert!(result.contains("On branch main"));
        assert!(result.contains("Changes to be committed"));
        assert!(result.contains("more files"));
        assert!(result.contains("[summarized by vallum]"));
        assert!(result.lines().count() < input.lines().count());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_optimize_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = GitStatusOptimizer.optimize(&s);
        }
    }
}
