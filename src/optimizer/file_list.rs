// src/optimizer/file_list.rs

//! File-listing output optimizer (`ls`, `find`, `fd`, `tree`).
//!
//! Three output shapes are recognised:
//!
//! - **Tree mode** — output contains `├──` / `└──` / `|--` / `` `-- `` glyphs.
//!   The trailing `N directories, M files` report line is always kept verbatim.
//!
//! - **ls-long mode** — majority of lines start with a permission string
//!   (`-rw-r--r--`, `drwxr-xr-x`, …). The `total N` header is always kept.
//!
//! - **Path-per-line mode** (default) — one path per line, as produced by
//!   `find`, `fd`, or plain `ls`. The top-`N` directory components are
//!   summarised in a `[top dirs: …]` footer.
//!
//! In all modes the first [`KEEP_ENTRIES`] lines are shown verbatim, excess
//! lines collapse into a single `[N … hidden]` marker, and error lines
//! (`Permission denied`, `find:`, `ls:`, `fd:`, `tree:` prefixes) are never
//! hidden wherever they appear.
//!
//! Pass-through (returns `None`) when the input has fewer than [`MIN_LINES`]
//! lines or when nothing actually collapses.
//!
//! **Shape detection is best-effort substring matching** (tree glyphs,
//! permission-prefix majority vote, report line). Mis-detection is safe:
//! every mode only collapses runs into count markers and never drops error
//! lines, so a false positive merely produces a slightly different summary
//! rather than silently discarding signal.

use super::CommandOptimizer;
use std::collections::HashMap;

pub struct FileListOptimizer;

/// Below this many lines the output is left alone.
const MIN_LINES: usize = 40;
/// Leading entries kept verbatim.
const KEEP_ENTRIES: usize = 30;
/// Directories shown in the path-mode frequency summary.
const TOP_DIRS: usize = 5;

/// Errors are never hidden, wherever they appear.
fn is_error_line(line: &str) -> bool {
    line.contains(": Permission denied")
        || line.starts_with("find:")
        || line.starts_with("ls:")
        || line.starts_with("fd:")
        || line.starts_with("tree:")
}

impl CommandOptimizer for FileListOptimizer {
    fn name(&self) -> &'static str {
        "file_list"
    }

    fn matches(&self, cmd: &str, _args: &[String]) -> bool {
        matches!(cmd, "ls" | "find" | "fd" | "tree")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        let lines: Vec<&str> = input.lines().collect();
        if lines.len() < MIN_LINES {
            return None;
        }
        if is_tree_shaped(&lines) {
            optimize_tree(&lines)
        } else if is_ls_long_shaped(&lines) {
            optimize_ls(&lines)
        } else {
            optimize_paths(&lines)
        }
    }
}

fn is_tree_shaped(lines: &[&str]) -> bool {
    lines
        .iter()
        .take(50)
        .any(|l| l.contains("├──") || l.contains("└──") || l.contains("|--") || l.contains("`--"))
}

fn is_ls_long_shaped(lines: &[&str]) -> bool {
    fn perm(l: &str) -> bool {
        let b = l.as_bytes();
        b.len() >= 10
            && matches!(b[0], b'-' | b'd' | b'l' | b'b' | b'c' | b'p' | b's')
            && b[1..10]
                .iter()
                .all(|c| matches!(c, b'r' | b'w' | b'x' | b's' | b'S' | b't' | b'T' | b'-'))
    }
    // Majority of lines look like `ls -l` entries.
    lines.iter().filter(|l| perm(l)).count() * 2 > lines.len()
}

/// Keep lines for which `keep` returns true; collapse each hidden run into a
/// `[N <label> hidden]` marker placed where the run was. Returns the rebuilt
/// text and the number of hidden lines.
fn collapse_entries(
    lines: &[&str],
    keep: impl Fn(usize, &str) -> bool,
    label: &str,
) -> (String, usize) {
    let mut out = String::new();
    let mut hidden_total = 0usize;
    let mut run = 0usize;
    for (i, line) in lines.iter().enumerate() {
        if keep(i, line) {
            if run > 0 {
                out.push_str(&format!("[{} {} hidden]\n", run, label));
                hidden_total += run;
                run = 0;
            }
            out.push_str(line);
            out.push('\n');
        } else {
            run += 1;
        }
    }
    if run > 0 {
        out.push_str(&format!("[{} {} hidden]\n", run, label));
        hidden_total += run;
    }
    (out, hidden_total)
}

fn optimize_tree(lines: &[&str]) -> Option<String> {
    // tree's trailing report line, e.g. "12 directories, 340 files" or
    // "1 directory, 1 file" (absent under --noreport).
    // "director" matches both "directory" and "directories".
    let report_idx = lines
        .iter()
        .rposition(|l| l.contains("director") && l.contains("file"));
    let (mut out, hidden) = collapse_entries(
        lines,
        |i, l| i < KEEP_ENTRIES || Some(i) == report_idx || is_error_line(l),
        "lines",
    );
    if hidden == 0 {
        return None;
    }
    out.push_str("[summarized by vallum]\n");
    Some(out)
}

fn optimize_ls(lines: &[&str]) -> Option<String> {
    let (mut out, hidden) = collapse_entries(
        lines,
        |i, l| i < KEEP_ENTRIES || l.starts_with("total ") || is_error_line(l),
        "entries",
    );
    if hidden == 0 {
        return None;
    }
    out.push_str("[summarized by vallum]\n");
    Some(out)
}

fn optimize_paths(lines: &[&str]) -> Option<String> {
    let (mut out, hidden) = collapse_entries(
        lines,
        |i, l| i < KEEP_ENTRIES || is_error_line(l),
        "more paths",
    );
    if hidden == 0 {
        return None;
    }
    let summary = top_dirs(lines);
    if !summary.is_empty() {
        out.push_str(&format!("[top dirs: {}]\n", summary));
    }
    out.push_str("[summarized by vallum]\n");
    Some(out)
}

/// First path component frequency over all (non-error) lines, e.g.
/// "src (60), tests (40)". Empty when every component is unique (plain `ls`
/// name-per-line output), where the summary would be noise.
///
/// Paths are assumed POSIX (`/`-separated). Windows backslash paths fall into
/// the all-unique suppression case and produce no footer.
fn top_dirs(lines: &[&str]) -> String {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for l in lines {
        if is_error_line(l) || l.trim().is_empty() {
            continue;
        }
        let trimmed = l.trim_start_matches("./").trim_start_matches('/');
        let top = trimmed.split('/').next().unwrap_or(trimmed);
        if top.is_empty() {
            continue;
        }
        *counts.entry(top).or_insert(0) += 1;
    }
    let mut pairs: Vec<(&str, usize)> = counts.into_iter().collect();
    if pairs.iter().all(|(_, n)| *n == 1) {
        return String::new();
    }
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    pairs
        .iter()
        .take(TOP_DIRS)
        .map(|(d, n)| format!("{} ({})", d, n))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_file_list_commands() {
        assert!(FileListOptimizer.matches("ls", &args(&["-la"])));
        assert!(FileListOptimizer.matches("find", &args(&[".", "-type", "f"])));
        assert!(FileListOptimizer.matches("fd", &args(&["rs"])));
        assert!(FileListOptimizer.matches("tree", &args(&[])));
        assert!(!FileListOptimizer.matches("cat", &args(&["x"])));
        assert!(!FileListOptimizer.matches("grep", &args(&["x"])));
    }

    #[test]
    fn path_mode_keeps_head_and_summarizes_dirs() {
        let mut input = String::new();
        for i in 0..60 {
            input.push_str(&format!("./src/module_{:02}.rs\n", i));
        }
        for i in 0..40 {
            input.push_str(&format!("./tests/case_{:02}.rs\n", i));
        }
        let out = FileListOptimizer.optimize(&input).unwrap();
        assert!(out.contains("./src/module_00.rs"));
        assert!(out.contains("./src/module_29.rs"));
        assert!(
            !out.contains("./src/module_30.rs"),
            "31st path must be hidden"
        );
        assert!(out.contains("[70 more paths hidden]"));
        assert!(out.contains("[top dirs: src (60), tests (40)]"));
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn path_mode_never_hides_error_lines() {
        let mut input = String::new();
        for i in 0..50 {
            input.push_str(&format!("./src/file_{:02}.rs\n", i));
        }
        input.push_str("find: ./locked: Permission denied\n");
        for i in 0..20 {
            input.push_str(&format!("./tests/t_{:02}.rs\n", i));
        }
        let out = FileListOptimizer.optimize(&input).unwrap();
        assert!(out.contains("find: ./locked: Permission denied"));
    }

    #[test]
    fn ls_long_mode_keeps_head_and_total() {
        let mut input = String::from("total 480\n");
        for i in 0..60 {
            input.push_str(&format!(
                "-rw-r--r--  1 user staff  123 Jan  1 00:00 file_{:02}.txt\n",
                i
            ));
        }
        let out = FileListOptimizer.optimize(&input).unwrap();
        assert!(out.contains("total 480"));
        assert!(out.contains("file_00.txt"));
        assert!(out.contains("[31 entries hidden]"));
        assert!(out.contains("[summarized by vallum]"));
        // No misleading dir summary in ls mode.
        assert!(!out.contains("[top dirs:"));
    }

    #[test]
    fn tree_mode_keeps_head_and_report_line() {
        let mut input = String::from(".\n");
        for i in 0..48 {
            input.push_str(&format!("├── file_{:02}.rs\n", i));
        }
        input.push_str("└── last.rs\n");
        input.push('\n');
        input.push_str("5 directories, 50 files\n");
        let out = FileListOptimizer.optimize(&input).unwrap();
        assert!(out.contains("├── file_00.rs"));
        assert!(
            out.contains("5 directories, 50 files"),
            "tree report must survive"
        );
        assert!(out.contains("lines hidden]"));
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn passthrough_small_input() {
        let input = "./src/a.rs\n./src/b.rs\n";
        assert!(FileListOptimizer.optimize(input).is_none());
    }

    #[test]
    fn path_mode_absolute_paths_get_real_top_dirs() {
        let mut input = String::new();
        for i in 0..50 {
            input.push_str(&format!("/srv/www/file_{:02}.txt\n", i));
        }
        let out = FileListOptimizer.optimize(&input).unwrap();
        assert!(out.contains("[top dirs: srv (50)]"));
        assert!(
            !out.contains("[top dirs:  ("),
            "empty component must be skipped"
        );
    }

    #[test]
    fn tree_mode_keeps_singular_report_line() {
        let mut input = String::from(".\n");
        for i in 0..45 {
            input.push_str(&format!("├── file_{:02}.rs\n", i));
        }
        input.push_str("1 directory, 1 file\n");
        let out = FileListOptimizer.optimize(&input).unwrap();
        assert!(
            out.contains("1 directory, 1 file"),
            "singular tree report must survive"
        );
    }

    #[test]
    fn path_mode_passthrough_when_only_errors_beyond_head() {
        // >= MIN_LINES total, but everything past the kept head is an error
        // line -> nothing hidden -> pass through.
        let mut input = String::new();
        for i in 0..30 {
            input.push_str(&format!("./src/file_{:02}.rs\n", i));
        }
        for i in 0..12 {
            input.push_str(&format!("find: ./locked_{:02}: Permission denied\n", i));
        }
        assert!(FileListOptimizer.optimize(&input).is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_optimize_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = FileListOptimizer.optimize(&s);
        }
    }
}
