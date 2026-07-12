use super::CommandOptimizer;

/// Collapses Homebrew's download chatter (`==> Downloading …` and the
/// `####…%` progress bars) while keeping `==> Pouring`, `==> Caveats`,
/// `==> Summary`, warnings, and errors verbatim.
pub struct BrewOptimizer;

impl CommandOptimizer for BrewOptimizer {
    fn name(&self) -> &'static str {
        "brew"
    }

    fn matches(&self, cmd: &str, _args: &[String]) -> bool {
        cmd == "brew"
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_download_line, "download lines")
    }
}

fn is_download_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("==> Downloading")
        || t.starts_with("==> Fetching")
        || (t.starts_with('#') && t.ends_with('%'))
        || t == "Already downloaded"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_brew_only() {
        let opt = BrewOptimizer;
        assert!(opt.matches("brew", &args(&["install", "jq"])));
        assert!(!opt.matches("apt", &args(&["install"])));
    }

    #[test]
    fn collapses_downloads_keeps_pour_and_caveats() {
        let opt = BrewOptimizer;
        let input = concat!(
            "==> Downloading https://ghcr.io/v2/homebrew/core/jq/manifests/1.7\n",
            "######################################################################## 100.0%\n",
            "==> Fetching jq\n",
            "==> Downloading https://ghcr.io/v2/homebrew/core/jq/blobs/sha256:abc\n",
            "######################################################################## 100.0%\n",
            "==> Downloading https://ghcr.io/v2/homebrew/core/oniguruma/manifests/6.9\n",
            "######################################################################## 100.0%\n",
            "==> Pouring jq--1.7.arm64_sonoma.bottle.tar.gz\n",
            "==> Caveats\n",
            "jq is keg-only\n",
            "==> Summary\n",
            "🍺  /opt/homebrew/Cellar/jq/1.7: 20 files, 1.2MB\n"
        );

        let out = opt.optimize(input).unwrap();
        assert!(out.contains("download lines hidden"), "got: {out}");
        assert!(out.contains("==> Pouring jq--1.7.arm64_sonoma.bottle.tar.gz"));
        assert!(out.contains("==> Caveats"));
        assert!(out.contains("==> Summary"));
        assert!(out.contains("[summarized by vallum]"));
        assert!(!out.contains("blobs/sha256:abc"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = BrewOptimizer;
        assert!(opt.optimize("==> Pouring jq.bottle.tar.gz\n").is_none());
    }
}
