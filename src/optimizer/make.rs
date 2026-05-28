// src/optimizer/make.rs
use super::{collapse_noise_runs, CommandOptimizer};

pub struct MakeOptimizer;

/// A line worth keeping: diagnostics and recipe failures.
fn is_important(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("error")
        || lower.contains("warning")
        || lower.contains("undefined reference")
        || line.contains("***")
        || line.starts_with("make:")
        || line.starts_with("make[")
}

impl CommandOptimizer for MakeOptimizer {
    fn name(&self) -> &'static str {
        "make"
    }

    fn matches(&self, cmd: &str, _args: &[String]) -> bool {
        cmd == "make"
    }

    fn optimize(&self, input: &str) -> Option<String> {
        // Noise = everything that is NOT a diagnostic.
        collapse_noise_runs(input, 15, |line| !is_important(line), "build lines")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_make() {
        assert!(MakeOptimizer.matches("make", &[]));
        assert!(!MakeOptimizer.matches("cargo", &[]));
    }

    #[test]
    fn surfaces_diagnostics_collapses_noise() {
        let mut input = String::new();
        for i in 0..20 {
            input.push_str(&format!("cc -c module_{}.c -o module_{}.o\n", i, i));
        }
        input.push_str("src/foo.c:10:5: warning: unused variable 'x'\n");
        input.push_str("src/bar.c:22:1: error: expected ';'\n");
        let out = MakeOptimizer.optimize(&input).unwrap();
        assert!(out.contains("warning: unused variable 'x'"));
        assert!(out.contains("error: expected ';'"));
        assert!(out.contains("build lines hidden"));
        assert!(out.lines().count() < input.lines().count());
    }

    #[test]
    fn passthrough_small() {
        let input = "cc -c a.c\ncc -c b.c\n";
        assert!(MakeOptimizer.optimize(input).is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_optimize_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = MakeOptimizer.optimize(&s);
        }
    }
}
