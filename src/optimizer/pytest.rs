use super::CommandOptimizer;

pub struct PytestOptimizer;

impl CommandOptimizer for PytestOptimizer {
    fn name(&self) -> &'static str {
        "pytest"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        if cmd == "pytest" {
            return true;
        }

        matches!(cmd, "python" | "python3")
            && args.len() >= 2
            && args[0] == "-m"
            && args[1] == "pytest"
    }

    fn optimize(&self, input: &str) -> Option<String> {
        if input.lines().count() < 10 {
            return None;
        }

        let mut progress_hidden = 0usize;
        let mut preserved = Vec::new();

        for line in input.lines() {
            let trimmed = line.trim();

            if is_progress_line(trimmed) {
                progress_hidden += 1;
                continue;
            }

            if should_preserve(trimmed) {
                preserved.push(line.to_string());
            }
        }

        if progress_hidden == 0 {
            return None;
        }

        let mut out = String::new();
        out.push_str(&format!("Progress: {} lines hidden\n", progress_hidden));

        if !preserved.is_empty() {
            out.push('\n');
            out.push_str(&preserved.join("\n"));
            out.push('\n');
        }

        out.push_str("[summarized by vallum]\n");
        Some(out)
    }
}

fn is_progress_line(trimmed: &str) -> bool {
    if !(trimmed.contains(".py") || trimmed.contains("::")) {
        return false;
    }

    let Some(last) = trimmed.split_whitespace().last() else {
        return false;
    };

    !last.is_empty()
        && last
            .chars()
            .all(|ch| matches!(ch, '.' | 'F' | 'E' | 's' | 'x' | 'X'))
}

fn should_preserve(trimmed: &str) -> bool {
    trimmed.is_empty()
        || trimmed.starts_with("================")
        || trimmed.starts_with("platform ")
        || trimmed.starts_with("rootdir:")
        || trimmed.starts_with("configfile:")
        || trimmed.starts_with("plugins:")
        || trimmed.starts_with("collected ")
        || trimmed.starts_with("FAILED ")
        || trimmed.starts_with("ERROR ")
        || trimmed.starts_with("E   ")
        || trimmed.starts_with(">")
        || trimmed.starts_with("________________")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_pytest_binary() {
        let opt = PytestOptimizer;
        assert!(opt.matches("pytest", &[]));
    }

    #[test]
    fn matches_python_module_pytest() {
        let opt = PytestOptimizer;
        assert!(opt.matches("python3", &args(&["-m", "pytest"])));
    }

    #[test]
    fn summarizes_progress_lines() {
        let opt = PytestOptimizer;
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

        let result = opt.optimize(input).unwrap();
        assert!(result.contains("Progress: 2 lines hidden"));
        assert!(result.contains("collected 12 items"));
        assert!(result.contains("1 failed, 11 passed"));
        assert!(result.contains("[summarized by vallum]"));
    }
}
