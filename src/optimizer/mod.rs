// src/optimizer/mod.rs
pub mod cargo;
pub mod git_status;
pub mod npm;
pub mod pytest;

pub trait CommandOptimizer {
    fn name(&self) -> &'static str;
    fn matches(&self, cmd: &str, args: &[String]) -> bool;
    fn optimize(&self, input: &str) -> Option<String>;
}

pub fn dispatch(cmd: &str, args: &[String], input: &str) -> Option<(String, &'static str)> {
    let optimizers: Vec<Box<dyn CommandOptimizer>> = vec![
        Box::new(pytest::PytestOptimizer),
        Box::new(npm::NpmOptimizer),
        Box::new(cargo::CargoOptimizer),
        Box::new(git_status::GitStatusOptimizer),
    ];

    for opt in &optimizers {
        if opt.matches(cmd, args) {
            if let Some(out) = opt.optimize(input) {
                return Some((out, opt.name()));
            }
        }
    }
    None
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
        let result = dispatch("git", &["status".to_string()], &input);
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

        let result = dispatch("cargo", &["test".to_string()], input);
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

        let result = dispatch("pytest", &[], input);
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

        let result = dispatch("npm", &["test".to_string()], input);
        assert!(result.is_some());
        let (out, name) = result.unwrap();
        assert_eq!(name, "npm");
        assert!(out.contains("PASS: 5 lines hidden"));
        assert!(out.contains("Test Suites: 5 passed, 5 total"));
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn dispatch_returns_none_for_unknown_command() {
        let result = dispatch("ls", &[], "foo");
        assert!(result.is_none());
    }

    #[test]
    fn trait_dispatch_returns_name_and_output() {
        let opt = AlwaysMatch;
        assert!(opt.matches("anything", &[]));
        assert_eq!(opt.optimize("x").unwrap(), "OPT:x");
        assert_eq!(opt.name(), "always_match");
    }
}
