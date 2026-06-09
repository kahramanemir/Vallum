// src/optimizer/grep.rs
use super::CommandOptimizer;

pub struct GrepOptimizer;

/// Below this many lines the output is left alone (consistent with other optimizers).
const MIN_LINES: usize = 30;
/// Match lines kept per file before collapsing the rest.
const PER_FILE_KEEP: usize = 3;
/// Files shown in detail before the remainder collapses into one summary line.
const MAX_FILES_DETAILED: usize = 20;

/// Flags that change the output shape (compact lists, JSON, context blocks
/// with `--` separators). Matching with these present would mangle structure,
/// so we pass through. Prefix checks over-exclude (e.g. `-A3`), which is the
/// safe direction.
fn has_excluded_flag(args: &[String]) -> bool {
    args.iter().any(|a| {
        matches!(
            a.as_str(),
            "-l" | "--files-with-matches"
                | "-L"
                | "--files-without-match"
                | "-c"
                | "--count"
                | "--json"
        ) || a.starts_with("-A")
            || a.starts_with("-B")
            || a.starts_with("-C")
            || a.starts_with("--context")
            || a.starts_with("--after-context")
            || a.starts_with("--before-context")
    })
}

impl CommandOptimizer for GrepOptimizer {
    fn name(&self) -> &'static str {
        "grep"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        matches!(cmd, "rg" | "grep" | "egrep" | "fgrep") && !has_excluded_flag(args)
    }

    fn optimize(&self, input: &str) -> Option<String> {
        let lines: Vec<&str> = input.lines().collect();
        if lines.len() < MIN_LINES {
            return None;
        }

        struct FileGroup<'a> {
            path: &'a str,
            matches: Vec<&'a str>,
        }
        enum Item<'a> {
            Group(FileGroup<'a>),
            Verbatim(&'a str),
        }

        // Tool diagnostics look like match lines ("grep: x: Permission denied")
        // but must stay verbatim.
        fn is_tool_diagnostic(path: &str) -> bool {
            matches!(path, "grep" | "rg" | "egrep" | "fgrep")
        }

        let mut items: Vec<Item> = Vec::new();
        for &line in &lines {
            match line.split_once(':') {
                Some((path, _)) if !path.is_empty() && !is_tool_diagnostic(path) => {
                    if let Some(Item::Group(g)) = items.last_mut() {
                        if g.path == path {
                            g.matches.push(line);
                            continue;
                        }
                    }
                    items.push(Item::Group(FileGroup {
                        path,
                        matches: vec![line],
                    }));
                }
                _ => items.push(Item::Verbatim(line)),
            }
        }

        let total_matches: usize = items
            .iter()
            .map(|i| match i {
                Item::Group(g) => g.matches.len(),
                Item::Verbatim(_) => 0,
            })
            .sum();
        let total_files = items.iter().filter(|i| matches!(i, Item::Group(_))).count();

        let mut out = String::new();
        let mut hidden_any = false;
        let mut files_seen = 0usize;
        let mut overflow_files = 0usize;
        let mut overflow_matches = 0usize;

        for item in &items {
            match item {
                Item::Verbatim(l) => {
                    out.push_str(l);
                    out.push('\n');
                }
                Item::Group(g) => {
                    files_seen += 1;
                    if files_seen > MAX_FILES_DETAILED {
                        overflow_files += 1;
                        overflow_matches += g.matches.len();
                        hidden_any = true;
                        continue;
                    }
                    for m in g.matches.iter().take(PER_FILE_KEEP) {
                        out.push_str(m);
                        out.push('\n');
                    }
                    if g.matches.len() > PER_FILE_KEEP {
                        out.push_str(&format!(
                            "[{} more matches in {} hidden]\n",
                            g.matches.len() - PER_FILE_KEEP,
                            g.path
                        ));
                        hidden_any = true;
                    }
                }
            }
        }

        if !hidden_any {
            return None;
        }
        if overflow_files > 0 {
            out.push_str(&format!(
                "[{} more files with {} matches hidden]\n",
                overflow_files, overflow_matches
            ));
        }
        out.push_str(&format!(
            "Total: {} matches in {} files\n",
            total_matches, total_files
        ));
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
    fn matches_grep_family_without_shape_changing_flags() {
        assert!(GrepOptimizer.matches("rg", &args(&["fn", "src/"])));
        assert!(GrepOptimizer.matches("grep", &args(&["-rn", "fn", "."])));
        assert!(GrepOptimizer.matches("egrep", &args(&["a|b"])));
        assert!(GrepOptimizer.matches("fgrep", &args(&["literal"])));
        assert!(!GrepOptimizer.matches("cat", &args(&["file"])));
        // Shape-changing flags must not match.
        assert!(!GrepOptimizer.matches("rg", &args(&["-l", "fn"])));
        assert!(!GrepOptimizer.matches("rg", &args(&["--json", "fn"])));
        assert!(!GrepOptimizer.matches("grep", &args(&["-c", "fn", "."])));
        assert!(!GrepOptimizer.matches("rg", &args(&["-A", "3", "fn"])));
        assert!(!GrepOptimizer.matches("rg", &args(&["-A3", "fn"])));
        assert!(!GrepOptimizer.matches("grep", &args(&["--context=2", "fn"])));
    }

    #[test]
    fn groups_by_file_and_caps_matches_per_file() {
        let mut input = String::new();
        for i in 0..25 {
            input.push_str(&format!("src/alpha.rs:{}:let x = {};\n", i + 1, i));
        }
        for i in 0..10 {
            input.push_str(&format!("src/beta.rs:{}:fn beta_{}() {{}}\n", i + 1, i));
        }
        let out = GrepOptimizer.optimize(&input).unwrap();
        assert!(out.contains("src/alpha.rs:1:"));
        assert!(out.contains("src/alpha.rs:3:"));
        assert!(!out.contains("src/alpha.rs:4:"), "4th match must be hidden");
        assert!(out.contains("[22 more matches in src/alpha.rs hidden]"));
        assert!(out.contains("[7 more matches in src/beta.rs hidden]"));
        assert!(out.contains("Total: 35 matches in 2 files"));
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn caps_number_of_detailed_files() {
        // 25 files x 2 matches: per-file cap (3) never trips, file cap (20) does.
        let mut input = String::new();
        for f in 0..25 {
            for l in 0..2 {
                input.push_str(&format!("src/file_{:02}.rs:{}:match here\n", f, l + 1));
            }
        }
        let out = GrepOptimizer.optimize(&input).unwrap();
        assert!(out.contains("src/file_00.rs:1:"));
        assert!(out.contains("src/file_19.rs:2:"));
        assert!(
            !out.contains("src/file_20.rs"),
            "21st file must be collapsed"
        );
        assert!(out.contains("[5 more files with 10 matches hidden]"));
        assert!(out.contains("Total: 50 matches in 25 files"));
    }

    #[test]
    fn keeps_non_match_lines_verbatim() {
        let mut input = String::from("Binary file target/debug/vallum matches\n");
        for i in 0..35 {
            input.push_str(&format!("src/alpha.rs:{}:line\n", i + 1));
        }
        input.push_str("grep: ./locked: Permission denied\n");
        let out = GrepOptimizer.optimize(&input).unwrap();
        assert!(out.contains("Binary file target/debug/vallum matches"));
        assert!(out.contains("grep: ./locked: Permission denied"));
    }

    #[test]
    fn passthrough_small_input() {
        let input = "src/a.rs:1:x\nsrc/a.rs:2:y\n";
        assert!(GrepOptimizer.optimize(input).is_none());
    }

    #[test]
    fn passthrough_when_nothing_hidden() {
        // 30 lines, 15 files x 2 matches: under both caps -> no collapse -> None.
        let mut input = String::new();
        for f in 0..15 {
            for l in 0..2 {
                input.push_str(&format!("src/f{:02}.rs:{}:m\n", f, l + 1));
            }
        }
        assert!(GrepOptimizer.optimize(&input).is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_optimize_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = GrepOptimizer.optimize(&s);
        }

        #[test]
        fn prop_output_never_longer_in_lines(s in "([a-z/.]{1,20}:[0-9]{1,3}:[a-z ]{0,30}\n){0,80}") {
            if let Some(out) = GrepOptimizer.optimize(&s) {
                // Grouping adds at most: per-file markers (bounded by kept files),
                // one overflow line, one total line, one trailer.
                prop_assert!(out.lines().count() <= s.lines().count() + 23);
            }
        }
    }
}
