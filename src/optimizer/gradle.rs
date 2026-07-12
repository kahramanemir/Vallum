use super::CommandOptimizer;

/// Collapses Gradle's dependency-download chatter (`Download https://…` lines)
/// while keeping task output, warnings, and the `BUILD SUCCESSFUL`/`BUILD
/// FAILED` result verbatim. Matches `gradle` and the `gradlew` wrapper.
pub struct GradleOptimizer;

impl CommandOptimizer for GradleOptimizer {
    fn name(&self) -> &'static str {
        "gradle"
    }

    fn matches(&self, cmd: &str, _args: &[String]) -> bool {
        cmd == "gradle" || cmd.ends_with("gradlew")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_download_line, "download lines")
    }
}

fn is_download_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("Download http") || t.starts_with("> Download http")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_gradle_and_wrapper() {
        let opt = GradleOptimizer;
        assert!(opt.matches("gradle", &args(&["build"])));
        assert!(opt.matches("gradlew", &args(&["test"])));
        assert!(opt.matches("./gradlew", &args(&["assemble"])));
        assert!(!opt.matches("mvn", &args(&["install"])));
    }

    #[test]
    fn collapses_downloads_keeps_result() {
        let opt = GradleOptimizer;
        let input = concat!(
            "Starting a Gradle Daemon\n",
            "Download https://repo1.maven.org/org/x/a/1.0/a-1.0.jar\n",
            "Download https://repo1.maven.org/org/x/b/1.0/b-1.0.jar\n",
            "Download https://repo1.maven.org/org/x/c/1.0/c-1.0.jar\n",
            "Download https://repo1.maven.org/org/x/d/1.0/d-1.0.jar\n",
            "Download https://repo1.maven.org/org/x/e/1.0/e-1.0.jar\n",
            "> Task :compileJava\n",
            "> Task :test\n",
            "BUILD SUCCESSFUL in 12s\n",
            "5 actionable tasks: 5 executed\n"
        );

        let out = opt.optimize(input).unwrap();
        assert!(out.contains("download lines hidden"), "got: {out}");
        assert!(out.contains("> Task :compileJava"));
        assert!(out.contains("BUILD SUCCESSFUL in 12s"));
        assert!(out.contains("[summarized by vallum]"));
        assert!(!out.contains("a-1.0.jar"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = GradleOptimizer;
        assert!(opt.optimize("BUILD SUCCESSFUL in 1s\n").is_none());
    }
}
