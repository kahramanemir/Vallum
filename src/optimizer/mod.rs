//! Per-command output optimizers: the `CommandOptimizer` trait and dispatch registry.

pub mod cargo;
pub mod docker;
pub mod file_list;
pub mod git_diff;
pub mod git_log;
pub mod git_status;
pub mod go_test;
pub mod grep;
pub mod kubectl;
pub mod make;
pub mod npm;
pub mod pip;
pub mod pytest;
pub mod terraform;

use std::sync::OnceLock;

pub trait CommandOptimizer {
    fn name(&self) -> &'static str;
    fn matches(&self, cmd: &str, args: &[String]) -> bool;
    fn optimize(&self, input: &str) -> Option<String>;
}

fn registry() -> &'static [Box<dyn CommandOptimizer + Send + Sync>] {
    static REG: OnceLock<Vec<Box<dyn CommandOptimizer + Send + Sync>>> = OnceLock::new();
    REG.get_or_init(|| {
        vec![
            Box::new(pytest::PytestOptimizer),
            Box::new(pip::PipOptimizer),
            Box::new(npm::NpmOptimizer),
            Box::new(cargo::CargoOptimizer),
            Box::new(git_status::GitStatusOptimizer),
            Box::new(git_diff::GitDiffOptimizer),
            Box::new(git_log::GitLogOptimizer),
            Box::new(docker::DockerOptimizer),
            Box::new(go_test::GoTestOptimizer),
            Box::new(make::MakeOptimizer),
            Box::new(kubectl::KubectlOptimizer),
            Box::new(terraform::TerraformOptimizer),
            Box::new(grep::GrepOptimizer),
            Box::new(file_list::FileListOptimizer),
        ]
    })
}

/// Names of all registered optimizers. Used by `vallum doctor` to validate
/// `[optimizer] disabled` entries against real optimizer names.
pub fn names() -> Vec<&'static str> {
    registry().iter().map(|o| o.name()).collect()
}

/// Shell metacharacters that make a `bash -c` script unsafe to word-split.
/// Any hit means we bail and match the invocation as-is (today's behavior).
const SHELL_METACHARACTERS: &[char] = &[
    '|', '&', ';', '<', '>', '(', ')', '$', '`', '\\', '"', '\'', '*', '?', '[', ']', '{', '}',
    '~', '#',
];

/// The Claude Code hook rewrites every Bash call to `bash -c '<original>'`,
/// which would otherwise hide the real command from optimizer matching.
/// Unwraps only the trivial case: exactly `["-c", script]` with no shell
/// metacharacters in the script.
fn unwrap_shell_invocation(cmd: &str, args: &[String]) -> Option<(String, Vec<String>)> {
    if !matches!(cmd, "bash" | "sh" | "zsh") {
        return None;
    }
    if args.len() != 2 || args[0] != "-c" {
        return None;
    }
    let script = &args[1];
    if script.chars().any(|c| SHELL_METACHARACTERS.contains(&c)) {
        return None;
    }
    let mut words = script.split_whitespace();
    let inner_cmd = words.next()?.to_string();
    let inner_args: Vec<String> = words.map(str::to_string).collect();
    Some((inner_cmd, inner_args))
}

pub fn dispatch(
    cmd: &str,
    args: &[String],
    input: &str,
    disabled: &[String],
) -> Option<(String, &'static str)> {
    let unwrapped = unwrap_shell_invocation(cmd, args);
    let (cmd, args) = match &unwrapped {
        Some((c, a)) => (c.as_str(), a.as_slice()),
        None => (cmd, args),
    };
    for opt in registry() {
        if disabled.iter().any(|d| d == opt.name()) {
            continue;
        }
        if opt.matches(cmd, args) {
            if let Some(out) = opt.optimize(input) {
                return Some((out, opt.name()));
            }
        }
    }
    None
}

/// Collapse maximal runs of "noise" lines (3 or more consecutive lines for which
/// `is_noise` returns true) into a single `[N <label> hidden]` marker, keeping
/// all other lines verbatim. Returns `None` if the input has fewer than
/// `min_lines` lines or nothing was collapsed (so callers pass through).
pub(crate) fn collapse_noise_runs(
    input: &str,
    min_lines: usize,
    is_noise: impl Fn(&str) -> bool,
    label: &str,
) -> Option<String> {
    let lines: Vec<&str> = input.lines().collect();
    if lines.len() < min_lines {
        return None;
    }

    let mut out = String::new();
    let mut collapsed_any = false;
    let mut i = 0;
    while i < lines.len() {
        if is_noise(lines[i]) {
            let start = i;
            while i < lines.len() && is_noise(lines[i]) {
                i += 1;
            }
            let run = i - start;
            if run >= 3 {
                out.push_str(&format!("[{} {} hidden]\n", run, label));
                collapsed_any = true;
            } else {
                for l in &lines[start..i] {
                    out.push_str(l);
                    out.push('\n');
                }
            }
        } else {
            out.push_str(lines[i]);
            out.push('\n');
            i += 1;
        }
    }

    if !collapsed_any {
        return None;
    }
    out.push_str("[summarized by vallum]\n");
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysMatch;
    impl CommandOptimizer for AlwaysMatch {
        fn name(&self) -> &'static str {
            "always_match"
        }
        fn matches(&self, _cmd: &str, _args: &[String]) -> bool {
            true
        }
        fn optimize(&self, input: &str) -> Option<String> {
            Some(format!("OPT:{}", input))
        }
    }

    #[test]
    fn dispatch_matches_git_status_when_input_is_long() {
        let mut files = String::new();
        for i in 0..40 {
            files.push_str(&format!("\tmodified:   src/file_{}.rs\n", i));
        }
        let input = format!(
            "On branch main\nYour branch is up to date with 'origin/main'.\n\nChanges to be committed:\n{}\n",
            files
        );
        let result = dispatch("git", &["status".to_string()], &input, &[]);
        assert!(result.is_some());
        let (out, name) = result.unwrap();
        assert_eq!(name, "git_status");
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn dispatch_matches_cargo_test_when_output_is_long() {
        let input = concat!(
            "   Compiling dep_a v0.1.0\n",
            "   Compiling dep_b v0.1.0\n",
            "   Compiling dep_c v0.1.0\n",
            "   Compiling vallum v0.2.0 (/tmp/vallum)\n",
            "    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.23s\n",
            "     Running unittests src/main.rs (target/debug/deps/vallum-abc)\n",
            "\n",
            "running 30 tests\n",
            "test alpha ... ok\n",
            "test beta ... ok\n",
            "test gamma ... ok\n",
            "test delta ... ok\n",
            "test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        );

        let result = dispatch("cargo", &["test".to_string()], input, &[]);
        assert!(result.is_some());
        let (out, name) = result.unwrap();
        assert_eq!(name, "cargo");
        assert!(out.contains("Compiling: 4 crates hidden"));
        assert!(out.contains("test result: ok."));
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn dispatch_matches_pytest_when_output_is_long() {
        let input = concat!(
            "============================= test session starts =============================\n",
            "platform darwin -- Python 3.11.0, pytest-8.0.0, pluggy-1.0.0\n",
            "rootdir: /tmp/app\n",
            "plugins: anyio-4.0.0\n",
            "collected 12 items\n",
            "\n",
            "tests/test_alpha.py ........\n",
            "tests/test_beta.py ...F.\n",
            "\n",
            "=================================== FAILURES ===================================\n",
            "______________________________ test_example ___________________________________\n",
            "E   assert 1 == 2\n",
            "\n",
            "=========================== short test summary info ============================\n",
            "FAILED tests/test_beta.py::test_example - assert 1 == 2\n",
            "========================= 1 failed, 11 passed in 0.50s =========================\n"
        );

        let result = dispatch("pytest", &[], input, &[]);
        assert!(result.is_some());
        let (out, name) = result.unwrap();
        assert_eq!(name, "pytest");
        assert!(out.contains("collected 12 items"));
        assert!(out.contains("Progress: 2 lines hidden"));
        assert!(out.contains("1 failed, 11 passed"));
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn dispatch_matches_npm_test_when_output_is_long() {
        let input = concat!(
            "> app@1.0.0 test\n",
            "> jest\n",
            "\n",
            "PASS src/a.test.js\n",
            "PASS src/b.test.js\n",
            "PASS src/c.test.js\n",
            "PASS src/d.test.js\n",
            "PASS src/e.test.js\n",
            "\n",
            "Test Suites: 5 passed, 5 total\n",
            "Tests:       42 passed, 42 total\n",
            "Snapshots:   0 total\n",
            "Time:        1.234 s\n",
            "Ran all test suites.\n"
        );

        let result = dispatch("npm", &["test".to_string()], input, &[]);
        assert!(result.is_some());
        let (out, name) = result.unwrap();
        assert_eq!(name, "npm");
        assert!(out.contains("PASS: 5 lines hidden"));
        assert!(out.contains("Test Suites: 5 passed, 5 total"));
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn dispatch_matches_rg_output() {
        let mut input = String::new();
        for i in 0..35 {
            input.push_str(&format!("src/alpha.rs:{}:line\n", i + 1));
        }
        let result = dispatch("rg", &["line".to_string()], &input, &[]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "grep");
    }

    #[test]
    fn dispatch_returns_none_for_unknown_command() {
        let result = dispatch("ls", &[], "foo", &[]);
        assert!(result.is_none());
    }

    #[test]
    fn dispatch_skips_disabled_optimizer() {
        let mut files = String::new();
        for i in 0..40 {
            files.push_str(&format!("\tmodified:   src/file_{}.rs\n", i));
        }
        let input = format!(
            "On branch main\nYour branch is up to date with 'origin/main'.\n\nChanges to be committed:\n{}\n",
            files
        );
        let disabled = vec!["git_status".to_string()];
        let result = dispatch("git", &["status".to_string()], &input, &disabled);
        assert!(result.is_none(), "disabled optimizer must be skipped");
    }

    #[test]
    fn trait_dispatch_returns_name_and_output() {
        let opt = AlwaysMatch;
        assert!(opt.matches("anything", &[]));
        assert_eq!(opt.optimize("x").unwrap(), "OPT:x");
        assert_eq!(opt.name(), "always_match");
    }

    #[test]
    fn collapse_noise_runs_collapses_and_keeps_signal() {
        let input = "keep A\nnoise\nnoise\nnoise\nnoise\nkeep B\nnoise\nkeep C\n";
        let out = collapse_noise_runs(input, 4, |l| l == "noise", "noise lines").unwrap();
        assert!(out.contains("keep A"));
        assert!(out.contains("keep B"));
        assert!(out.contains("keep C"));
        assert!(out.contains("[4 noise lines hidden]"));
        // A run shorter than 3 is NOT collapsed.
        assert!(out.matches("noise").count() >= 1); // the single "noise" before "keep C" stays
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn collapse_noise_runs_passthrough_when_nothing_collapsed() {
        // No run of >=3 noise lines -> None (pass-through).
        let input = "a\nnoise\nb\nnoise\nc\n";
        assert!(collapse_noise_runs(input, 1, |l| l == "noise", "x").is_none());
    }

    #[test]
    fn collapse_noise_runs_passthrough_when_too_small() {
        let input = "noise\nnoise\nnoise\n";
        assert!(collapse_noise_runs(input, 10, |l| l == "noise", "x").is_none());
    }

    #[test]
    fn unwrap_shell_invocation_shapes() {
        let ok = unwrap_shell_invocation("bash", &["-c".into(), "git status".into()]);
        assert_eq!(ok, Some(("git".to_string(), vec!["status".to_string()])));
        assert!(unwrap_shell_invocation("sh", &["-c".into(), "cargo test".into()]).is_some());
        assert!(unwrap_shell_invocation("zsh", &["-c".into(), "ls -la".into()]).is_some());
        // Wrong shapes must not unwrap.
        assert!(unwrap_shell_invocation("bash", &["-c".into()]).is_none());
        assert!(unwrap_shell_invocation("bash", &["-lc".into(), "git status".into()]).is_none());
        assert!(unwrap_shell_invocation(
            "bash",
            &["-c".into(), "git status".into(), "extra".into()]
        )
        .is_none());
        assert!(unwrap_shell_invocation("python", &["-c".into(), "print(1)".into()]).is_none());
        assert!(unwrap_shell_invocation("bash", &["-c".into(), "".into()]).is_none());
    }

    #[test]
    fn dispatch_unwraps_bash_c_simple_command() {
        let mut files = String::new();
        for i in 0..40 {
            files.push_str(&format!("\tmodified:   src/file_{}.rs\n", i));
        }
        let input = format!(
            "On branch main\nYour branch is up to date with 'origin/main'.\n\nChanges to be committed:\n{}\n",
            files
        );
        let args = vec!["-c".to_string(), "git status".to_string()];
        let result = dispatch("bash", &args, &input, &[]);
        assert!(
            result.is_some(),
            "bash -c 'git status' must reach git_status"
        );
        assert_eq!(result.unwrap().1, "git_status");
    }

    #[test]
    fn dispatch_unwraps_bash_c_find_to_file_list() {
        let mut input = String::new();
        for i in 0..60 {
            input.push_str(&format!("./src/file_{:02}.rs\n", i));
        }
        let args = vec!["-c".to_string(), "find . -type f".to_string()];
        let result = dispatch("bash", &args, &input, &[]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, "file_list");
    }

    #[test]
    fn dispatch_does_not_unwrap_metacharacter_scripts() {
        for script in [
            "git status | head",
            "echo 'hi'",
            "ls *.rs",
            "a; b",
            "x > y",
            "echo $HOME",
            "cd ~/src",
        ] {
            let args = vec!["-c".to_string(), script.to_string()];
            assert!(
                dispatch("bash", &args, "irrelevant", &[]).is_none(),
                "{script} must not unwrap"
            );
        }
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_collapse_noise_runs_does_not_panic(
            s in "[\\s\\S]{0,500}",
            min_lines in 0usize..50,
        ) {
            let _ = collapse_noise_runs(&s, min_lines, |line| line.is_empty(), "noise");
        }

        #[test]
        fn prop_collapse_noise_runs_line_count_bounded(
            s in "[\\s\\S]{0,500}",
            min_lines in 0usize..50,
        ) {
            if let Some(out) = collapse_noise_runs(&s, min_lines, |line| line.is_empty(), "noise") {
                let in_lines = s.lines().count();
                let out_lines = out.lines().count();
                // A collapse can only equal or reduce the line count, plus one
                // trailing "[summarized by vallum]" marker.
                prop_assert!(out_lines <= in_lines + 2);
            }
        }
    }
}
