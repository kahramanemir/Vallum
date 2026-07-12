use super::CommandOptimizer;

/// Collapses Maven's high-volume artifact-download chatter (`Downloading from`
/// / `Downloaded from` / `Progress` lines) while keeping build phases,
/// `[WARNING]`/`[ERROR]` diagnostics, and the `BUILD SUCCESS`/`BUILD FAILURE`
/// reactor summary verbatim. Matches `mvn` and the `mvnw` wrapper.
pub struct MavenOptimizer;

impl CommandOptimizer for MavenOptimizer {
    fn name(&self) -> &'static str {
        "maven"
    }

    fn matches(&self, cmd: &str, _args: &[String]) -> bool {
        cmd == "mvn" || cmd.ends_with("mvnw")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_download_line, "download lines")
    }
}

fn is_download_line(line: &str) -> bool {
    let t = line.trim_start();
    // Tolerate the leading `[INFO] ` prefix Maven puts on most lines.
    let t = t.strip_prefix("[INFO] ").unwrap_or(t);
    t.starts_with("Downloading from")
        || t.starts_with("Downloaded from")
        || t.starts_with("Progress (")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_mvn_and_wrapper() {
        let opt = MavenOptimizer;
        assert!(opt.matches("mvn", &args(&["install"])));
        assert!(opt.matches("mvnw", &args(&["package"])));
        assert!(opt.matches("./mvnw", &args(&["test"])));
        assert!(!opt.matches("gradle", &args(&["build"])));
    }

    #[test]
    fn collapses_downloads_keeps_phases_and_summary() {
        let opt = MavenOptimizer;
        let input = concat!(
            "[INFO] Scanning for projects...\n",
            "[INFO] Downloading from central: https://repo1.maven.org/org/x/a/1.0/a-1.0.pom\n",
            "[INFO] Downloaded from central: https://repo1.maven.org/org/x/a/1.0/a-1.0.pom (2.1 kB at 5.0 kB/s)\n",
            "[INFO] Downloading from central: https://repo1.maven.org/org/x/b/1.0/b-1.0.pom\n",
            "[INFO] Downloaded from central: https://repo1.maven.org/org/x/b/1.0/b-1.0.pom (2.1 kB at 5.0 kB/s)\n",
            "[INFO] Downloading from central: https://repo1.maven.org/org/x/c/1.0/c-1.0.jar\n",
            "[INFO] Downloaded from central: https://repo1.maven.org/org/x/c/1.0/c-1.0.jar (2.1 kB at 5.0 kB/s)\n",
            "[INFO] \n",
            "[INFO] --- compiler:3.11.0:compile (default-compile) @ app ---\n",
            "[WARNING] some deprecation\n",
            "[INFO] BUILD SUCCESS\n",
            "[INFO] Total time:  3.456 s\n"
        );

        let out = opt.optimize(input).unwrap();
        assert!(out.contains("download lines hidden"), "got: {out}");
        assert!(out.contains("[INFO] Scanning for projects..."));
        assert!(out.contains("[WARNING] some deprecation"));
        assert!(out.contains("BUILD SUCCESS"));
        assert!(out.contains("[summarized by vallum]"));
        assert!(!out.contains("Downloaded from central"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = MavenOptimizer;
        let input = "[INFO] BUILD SUCCESS\n[INFO] Total time: 1.0 s\n";
        assert!(opt.optimize(input).is_none());
    }
}
