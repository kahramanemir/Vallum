// src/optimizer/go_test.rs
use super::{collapse_noise_runs, CommandOptimizer};

pub struct GoTestOptimizer;

fn is_run_or_pass(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("=== RUN")
        || t.starts_with("=== CONT")
        || t.starts_with("=== PAUSE")
        || t.starts_with("=== NAME")
        || t.starts_with("--- PASS")
}

impl CommandOptimizer for GoTestOptimizer {
    fn name(&self) -> &'static str {
        "go_test"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        cmd == "go" && args.iter().any(|a| a == "test")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        collapse_noise_runs(input, 15, is_run_or_pass, "passing test lines")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_go_test() {
        assert!(GoTestOptimizer.matches("go", &args(&["test", "./..."])));
        assert!(!GoTestOptimizer.matches("go", &args(&["build"])));
    }

    #[test]
    fn collapses_pass_keeps_fail_and_summary() {
        let mut input = String::new();
        for i in 0..20 {
            input.push_str(&format!("=== RUN   TestThing{}\n", i));
            input.push_str(&format!("--- PASS: TestThing{} (0.00s)\n", i));
        }
        input.push_str("--- FAIL: TestBroken (0.01s)\n");
        input.push_str("    main_test.go:42: expected 1 got 2\n");
        input.push_str("FAIL\n");
        input.push_str("FAIL\texample/pkg\t0.123s\n");
        let out = GoTestOptimizer.optimize(&input).unwrap();
        assert!(out.contains("--- FAIL: TestBroken (0.01s)"));
        assert!(out.contains("expected 1 got 2"));
        assert!(out.contains("FAIL\texample/pkg"));
        assert!(out.contains("passing test lines hidden"));
        assert!(out.lines().count() < input.lines().count());
    }

    #[test]
    fn passthrough_small() {
        let input = "=== RUN TestX\n--- PASS: TestX\nok\texample\t0.01s\n";
        assert!(GoTestOptimizer.optimize(input).is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_optimize_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = GoTestOptimizer.optimize(&s);
        }
    }
}
