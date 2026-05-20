use super::CommandOptimizer;

pub struct CargoOptimizer;

impl CommandOptimizer for CargoOptimizer {
    fn name(&self) -> &'static str {
        "cargo"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        if cmd != "cargo" {
            return false;
        }

        let supported = ["build", "test", "check", "clippy", "run"];
        let has_supported_subcommand = args.iter().any(|arg| supported.contains(&arg.as_str()));
        let has_json_output = args.iter().any(|arg| {
            arg == "--message-format=json"
                || arg == "--message-format=json-diagnostic-rendered-ansi"
        });

        has_supported_subcommand && !has_json_output
    }

    fn optimize(&self, input: &str) -> Option<String> {
        if input.lines().count() < 12 {
            return None;
        }

        let mut compiling_count = 0usize;
        let mut checking_count = 0usize;
        let mut download_count = 0usize;
        let mut preserved = Vec::new();

        for line in input.lines() {
            let trimmed = line.trim_start();

            if trimmed.starts_with("Compiling ") {
                compiling_count += 1;
                continue;
            }
            if trimmed.starts_with("Checking ") {
                checking_count += 1;
                continue;
            }
            if trimmed.starts_with("Downloading ") || trimmed.starts_with("Downloaded ") {
                download_count += 1;
                continue;
            }

            if should_preserve(trimmed) {
                preserved.push(line.to_string());
            }
        }

        if compiling_count == 0 && checking_count == 0 && download_count == 0 {
            return None;
        }

        let mut out = String::new();
        if compiling_count > 0 {
            out.push_str(&format!("Compiling: {} crates hidden\n", compiling_count));
        }
        if checking_count > 0 {
            out.push_str(&format!("Checking: {} crates hidden\n", checking_count));
        }
        if download_count > 0 {
            out.push_str(&format!("Downloads: {} lines hidden\n", download_count));
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
        || trimmed.starts_with("Finished ")
        || trimmed.starts_with("Running ")
        || trimmed.starts_with("running ")
        || trimmed.starts_with("test ")
        || trimmed.starts_with("test result:")
        || trimmed.starts_with("Doc-tests ")
        || trimmed.starts_with("error")
        || trimmed.starts_with("warning")
        || trimmed.starts_with("help:")
        || trimmed.starts_with("note:")
        || trimmed.starts_with("Caused by:")
        || trimmed.starts_with("failures:")
        || trimmed.starts_with("----")
        || trimmed.starts_with("thread '")
        || trimmed.starts_with("For more information")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_cargo_test() {
        let opt = CargoOptimizer;
        assert!(opt.matches("cargo", &args(&["test"])));
    }

    #[test]
    fn does_not_match_cargo_metadata() {
        let opt = CargoOptimizer;
        assert!(!opt.matches("cargo", &args(&["metadata"])));
    }

    #[test]
    fn does_not_match_json_message_format() {
        let opt = CargoOptimizer;
        assert!(!opt.matches("cargo", &args(&["check", "--message-format=json"])));
    }

    #[test]
    fn summarizes_long_cargo_output() {
        let opt = CargoOptimizer;
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

        let result = opt.optimize(input).unwrap();
        assert!(result.contains("Compiling: 4 crates hidden"));
        assert!(result.contains("Finished `test` profile"));
        assert!(result.contains("test result: ok."));
        assert!(result.contains("[summarized by vallum]"));
    }
}
