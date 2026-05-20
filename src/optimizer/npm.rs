use super::CommandOptimizer;

pub struct NpmOptimizer;

impl CommandOptimizer for NpmOptimizer {
    fn name(&self) -> &'static str {
        "npm"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        if cmd != "npm" {
            return false;
        }

        if args.iter().any(|arg| arg == "--json") {
            return false;
        }

        matches!(
            args.first().map(|value| value.as_str()),
            Some("test" | "install" | "ci" | "run")
        )
    }

    fn optimize(&self, input: &str) -> Option<String> {
        if input.lines().count() < 8 {
            return None;
        }

        let mut pass_hidden = 0usize;
        let mut warning_hidden = 0usize;
        let mut preserved = Vec::new();

        for line in input.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("PASS ") {
                pass_hidden += 1;
                continue;
            }

            if trimmed.starts_with("npm WARN ") {
                warning_hidden += 1;
                continue;
            }

            if should_preserve(trimmed) {
                preserved.push(line.to_string());
            }
        }

        if pass_hidden == 0 && warning_hidden == 0 {
            return None;
        }

        let mut out = String::new();
        if pass_hidden > 0 {
            out.push_str(&format!("PASS: {} lines hidden\n", pass_hidden));
        }
        if warning_hidden > 0 {
            out.push_str(&format!("Warnings: {} lines hidden\n", warning_hidden));
        }

        if !preserved.is_empty() {
            out.push('\n');
            out.push_str(&preserved.join("\n"));
            out.push('\n');
        }

        out.push_str("[summarized by vallum]\n");
        Some(out)
    }
}

fn should_preserve(trimmed: &str) -> bool {
    trimmed.is_empty()
        || trimmed.starts_with('>')
        || trimmed.starts_with("added ")
        || trimmed.starts_with("removed ")
        || trimmed.starts_with("changed ")
        || trimmed.starts_with("up to date")
        || trimmed.starts_with("audited ")
        || trimmed.starts_with("found ")
        || trimmed.starts_with("Test Suites:")
        || trimmed.starts_with("Tests:")
        || trimmed.starts_with("Snapshots:")
        || trimmed.starts_with("Time:")
        || trimmed.starts_with("Ran all test suites.")
        || trimmed.starts_with("npm ERR!")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_npm_test() {
        let opt = NpmOptimizer;
        assert!(opt.matches("npm", &args(&["test"])));
    }

    #[test]
    fn does_not_match_npm_json_mode() {
        let opt = NpmOptimizer;
        assert!(!opt.matches("npm", &args(&["test", "--json"])));
    }

    #[test]
    fn summarizes_pass_lines() {
        let opt = NpmOptimizer;
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

        let result = opt.optimize(input).unwrap();
        assert!(result.contains("PASS: 5 lines hidden"));
        assert!(result.contains("Test Suites: 5 passed, 5 total"));
        assert!(result.contains("[summarized by vallum]"));
    }
}
