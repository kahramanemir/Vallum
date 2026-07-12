use super::CommandOptimizer;

/// Collapses the repetitive dependency-resolution chatter of `pip install`
/// (`Requirement already satisfied`, `Collecting`, `Downloading`, `Using
/// cached`) while keeping the outcome lines (`Installing collected packages`,
/// `Successfully installed`, errors, and warnings) verbatim.
pub struct PipOptimizer;

impl CommandOptimizer for PipOptimizer {
    fn name(&self) -> &'static str {
        "pip"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        let is_pip = matches!(cmd, "pip" | "pip3")
            || (matches!(cmd, "python" | "python3")
                && args.first().is_some_and(|a| a == "-m")
                && args.get(1).is_some_and(|a| a == "pip"));
        // Only `install` output carries the collapsible dependency chatter.
        is_pip && args.iter().any(|a| a == "install")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_dependency_line, "dependency lines")
    }
}

fn is_dependency_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("Requirement already satisfied")
        || t.starts_with("Collecting ")
        || t.starts_with("Downloading ")
        || t.starts_with("Using cached ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_pip_install() {
        let opt = PipOptimizer;
        assert!(opt.matches("pip", &args(&["install", "requests"])));
        assert!(opt.matches("pip3", &args(&["install", "-r", "requirements.txt"])));
        assert!(opt.matches("python3", &args(&["-m", "pip", "install", "flask"])));
    }

    #[test]
    fn does_not_match_non_install_or_other_commands() {
        let opt = PipOptimizer;
        assert!(!opt.matches("pip", &args(&["list"])));
        assert!(!opt.matches("pip", &args(&["freeze"])));
        assert!(!opt.matches("npm", &args(&["install"])));
    }

    #[test]
    fn collapses_dependency_chatter_keeps_outcome() {
        let opt = PipOptimizer;
        let input = concat!(
            "Collecting requests\n",
            "  Downloading requests-2.31.0-py3-none-any.whl (62 kB)\n",
            "Collecting urllib3\n",
            "  Downloading urllib3-2.0.7-py3-none-any.whl (124 kB)\n",
            "Requirement already satisfied: idna in ./venv/lib/python3.11/site-packages (3.4)\n",
            "Requirement already satisfied: certifi in ./venv/lib/python3.11/site-packages (2023.7.22)\n",
            "Requirement already satisfied: charset-normalizer in ./venv/lib/python3.11/site-packages (3.3.0)\n",
            "Using cached charset_normalizer-3.3.0-py3-none-any.whl (123 kB)\n",
            "Installing collected packages: urllib3, idna, requests\n",
            "Successfully installed requests-2.31.0 urllib3-2.0.7 idna-3.4\n"
        );

        let out = opt.optimize(input).unwrap();
        assert!(out.contains("dependency lines hidden"), "got: {out}");
        assert!(out.contains("Installing collected packages: urllib3, idna, requests"));
        assert!(out.contains("Successfully installed requests-2.31.0"));
        assert!(out.contains("[summarized by vallum]"));
        // The collapsed chatter is gone.
        assert!(!out.contains("Requirement already satisfied"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = PipOptimizer;
        let input = "Requirement already satisfied: pip\nSuccessfully installed x\n";
        assert!(opt.optimize(input).is_none());
    }
}
