// src/optimizer/git_log.rs
use super::CommandOptimizer;

pub struct GitLogOptimizer;

impl CommandOptimizer for GitLogOptimizer {
    fn name(&self) -> &'static str {
        "git_log"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        cmd == "git" && args.iter().any(|a| a == "log")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        let lines: Vec<&str> = input.lines().collect();
        if lines.len() < 15 {
            return None;
        }

        let mut out = String::new();
        let mut collapsed_any = false;
        let mut body_run = 0usize; // consecutive collapsed body lines
        let mut subject_seen_for_block = false;

        let flush_body = |out: &mut String, run: &mut usize, collapsed: &mut bool| {
            if *run > 0 {
                out.push_str(&format!("    [{} message lines hidden]\n", run));
                *collapsed = true;
                *run = 0;
            }
        };

        for line in &lines {
            if line.starts_with("commit ") {
                flush_body(&mut out, &mut body_run, &mut collapsed_any);
                subject_seen_for_block = false;
                out.push_str(line);
                out.push('\n');
            } else if line.starts_with("Author:")
                || line.starts_with("Date:")
                || line.starts_with("Merge:")
            {
                out.push_str(line);
                out.push('\n');
            } else if line.trim().is_empty() {
                // Blank line: flush any pending body run, keep one blank.
                flush_body(&mut out, &mut body_run, &mut collapsed_any);
                out.push_str(line);
                out.push('\n');
            } else {
                // Indented/plain message line. Keep the first (subject) per block,
                // collapse subsequent ones.
                if !subject_seen_for_block {
                    out.push_str(line);
                    out.push('\n');
                    subject_seen_for_block = true;
                } else {
                    body_run += 1;
                }
            }
        }
        flush_body(&mut out, &mut body_run, &mut collapsed_any);

        if !collapsed_any {
            return None;
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
    fn matches_git_log() {
        assert!(GitLogOptimizer.matches("git", &args(&["log"])));
        assert!(!GitLogOptimizer.matches("git", &args(&["status"])));
    }

    #[test]
    fn keeps_headers_and_subject_collapses_body() {
        let mut input = String::new();
        for c in 0..3 {
            input.push_str(&format!("commit {:040x}\n", c));
            input.push_str("Author: Dev <dev@example.com>\n");
            input.push_str("Date:   Wed May 28 12:00:00 2026 +0300\n\n");
            input.push_str("    subject line for commit\n\n");
            for b in 0..8 {
                input.push_str(&format!("    body paragraph line {}\n", b));
            }
            input.push('\n');
        }
        let out = GitLogOptimizer.optimize(&input).unwrap();
        assert!(out.contains("Author: Dev <dev@example.com>"));
        assert!(out.contains("subject line for commit"));
        assert!(out.contains("message lines hidden"));
        assert!(!out.contains("body paragraph line 7"));
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn passthrough_short_log() {
        let input = "commit abc\nAuthor: x\nDate: y\n\n    subj\n";
        assert!(GitLogOptimizer.optimize(input).is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_optimize_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = GitLogOptimizer.optimize(&s);
        }
    }
}
