use super::CommandOptimizer;

/// Collapses Poetry's per-package operation chatter (`• Installing …`,
/// `• Updating …`, `• Removing …`) while keeping the `Package operations`
/// summary, warnings, and errors verbatim.
pub struct PoetryOptimizer;

impl CommandOptimizer for PoetryOptimizer {
    fn name(&self) -> &'static str {
        "poetry"
    }

    fn matches(&self, cmd: &str, _args: &[String]) -> bool {
        cmd == "poetry"
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_operation_line, "package operations")
    }
}

fn is_operation_line(line: &str) -> bool {
    let t = line.trim_start();
    let Some(rest) = t.strip_prefix("• ").or_else(|| t.strip_prefix("- ")) else {
        return false;
    };
    rest.starts_with("Installing")
        || rest.starts_with("Updating")
        || rest.starts_with("Removing")
        || rest.starts_with("Downgrading")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_poetry_only() {
        let opt = PoetryOptimizer;
        assert!(opt.matches("poetry", &args(&["install"])));
        assert!(!opt.matches("pip", &args(&["install"])));
    }

    #[test]
    fn collapses_operations_keeps_summary() {
        let opt = PoetryOptimizer;
        let mut input = String::from(
            "Installing dependencies from lock file\n\nPackage operations: 12 installs, 0 updates, 0 removals\n\n",
        );
        for pkg in [
            "charset-normalizer (3.1.0)",
            "idna (3.4)",
            "certifi (2023.5.7)",
            "urllib3 (2.0.2)",
            "requests (2.31.0)",
            "click (8.1.3)",
            "rich (13.4.1)",
            "typer (0.9.0)",
            "pyyaml (6.0)",
            "packaging (23.1)",
            "attrs (23.1.0)",
            "sniffio (1.3.0)",
        ] {
            input.push_str(&format!("  • Installing {pkg}\n"));
        }

        let out = opt.optimize(&input).unwrap();
        assert!(out.contains("package operations hidden"), "got: {out}");
        assert!(out.contains("Package operations: 12 installs, 0 updates, 0 removals"));
        assert!(out.contains("[summarized by vallum]"));
        assert!(!out.contains("charset-normalizer"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = PoetryOptimizer;
        assert!(opt.optimize("  • Installing requests (2.31.0)\n").is_none());
    }
}
