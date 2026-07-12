use super::CommandOptimizer;

/// Collapses the repetitive progress chatter of `apt`/`apt-get install`
/// (package-list reads, `Get:` downloads, `Unpacking`, `Setting up`,
/// `Processing triggers`) while keeping the plan and outcome lines (the
/// NEW-packages list, the `N upgraded, N newly installed …` summary, and any
/// `E:`/`W:` diagnostics) verbatim. Handles an optional `sudo` prefix.
pub struct AptOptimizer;

impl CommandOptimizer for AptOptimizer {
    fn name(&self) -> &'static str {
        "apt"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        // Peel an optional leading `sudo` so `sudo apt-get install …` matches.
        let (base, rest): (&str, &[String]) = if cmd == "sudo" && !args.is_empty() {
            (args[0].as_str(), &args[1..])
        } else {
            (cmd, args)
        };
        matches!(base, "apt" | "apt-get") && rest.iter().any(|a| a == "install")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_apt_noise, "apt progress lines")
    }
}

fn is_apt_noise(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("Reading package lists")
        || t.starts_with("Building dependency tree")
        || t.starts_with("Reading state information")
        || t.starts_with("Get:")
        || t.starts_with("Fetched ")
        || t.starts_with("Selecting previously unselected")
        || t.starts_with("Preparing to unpack")
        || t.starts_with("Unpacking ")
        || t.starts_with("Setting up ")
        || t.starts_with("Processing triggers")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_apt_install_with_and_without_sudo() {
        let opt = AptOptimizer;
        assert!(opt.matches("apt", &args(&["install", "ripgrep"])));
        assert!(opt.matches("apt-get", &args(&["install", "-y", "curl"])));
        assert!(opt.matches("sudo", &args(&["apt-get", "install", "-y", "jq"])));
    }

    #[test]
    fn does_not_match_non_install_or_other_commands() {
        let opt = AptOptimizer;
        assert!(!opt.matches("apt", &args(&["update"])));
        assert!(!opt.matches("sudo", &args(&["apt", "remove", "x"])));
        assert!(!opt.matches("brew", &args(&["install", "x"])));
        assert!(!opt.matches("sudo", &[])); // no panic on empty args
    }

    #[test]
    fn collapses_progress_keeps_plan_and_summary() {
        let opt = AptOptimizer;
        let input = concat!(
            "Reading package lists... Done\n",
            "Building dependency tree... Done\n",
            "Reading state information... Done\n",
            "The following NEW packages will be installed:\n",
            "  ripgrep\n",
            "0 upgraded, 1 newly installed, 0 to remove and 3 not upgraded.\n",
            "Need to get 1,234 kB of archives.\n",
            "Get:1 http://deb.debian.org/debian bookworm/main amd64 ripgrep amd64 13.0.0 [1,234 kB]\n",
            "Fetched 1,234 kB in 1s (1,234 kB/s)\n",
            "Selecting previously unselected package ripgrep.\n",
            "Preparing to unpack .../ripgrep_13.0.0_amd64.deb ...\n",
            "Unpacking ripgrep (13.0.0) ...\n",
            "Setting up ripgrep (13.0.0) ...\n",
            "Processing triggers for man-db (2.11.2-2) ...\n"
        );

        let out = opt.optimize(input).unwrap();
        assert!(out.contains("apt progress lines hidden"), "got: {out}");
        assert!(out.contains("The following NEW packages will be installed:"));
        assert!(out.contains("0 upgraded, 1 newly installed"));
        assert!(out.contains("[summarized by vallum]"));
        assert!(!out.contains("Processing triggers"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = AptOptimizer;
        let input = "Reading package lists... Done\nSetting up x ...\n";
        assert!(opt.optimize(input).is_none());
    }
}
