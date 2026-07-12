use super::CommandOptimizer;

/// Collapses Go's module-download chatter (`go: downloading <mod> <ver>`) for
/// `go build`/`mod`/`get`/`install`, keeping errors and other output verbatim.
/// (`go test` output is handled by the separate `go_test` optimizer.)
pub struct GoBuildOptimizer;

impl CommandOptimizer for GoBuildOptimizer {
    fn name(&self) -> &'static str {
        "go_build"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        cmd == "go"
            && args
                .first()
                .is_some_and(|a| matches!(a.as_str(), "build" | "mod" | "get" | "install"))
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_download_line, "module downloads")
    }
}

fn is_download_line(line: &str) -> bool {
    line.trim_start().starts_with("go: downloading ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_go_build_family_not_test() {
        let opt = GoBuildOptimizer;
        assert!(opt.matches("go", &args(&["build", "./..."])));
        assert!(opt.matches("go", &args(&["mod", "download"])));
        assert!(opt.matches("go", &args(&["get", "example.com/x"])));
        // `go test` is the go_test optimizer's job, not ours.
        assert!(!opt.matches("go", &args(&["test", "./..."])));
        assert!(!opt.matches("gofmt", &args(&["-l", "."])));
    }

    #[test]
    fn collapses_module_downloads() {
        let opt = GoBuildOptimizer;
        let input = concat!(
            "go: downloading github.com/a/a v1.2.3\n",
            "go: downloading github.com/b/b v0.4.0\n",
            "go: downloading github.com/c/c v2.0.1\n",
            "go: downloading github.com/d/d v1.0.0\n",
            "go: downloading github.com/e/e v1.5.0\n",
            "go: downloading github.com/f/f v3.1.0\n",
            "# example.com/app\n",
            "./main.go:10:2: undefined: Foo\n",
            "./main.go:11:2: undefined: Bar\n",
            "note: module requires Go 1.21\n"
        );

        let out = opt.optimize(input).unwrap();
        assert!(out.contains("module downloads hidden"), "got: {out}");
        assert!(out.contains("./main.go:10:2: undefined: Foo"));
        assert!(out.contains("[summarized by vallum]"));
        assert!(!out.contains("github.com/a/a"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = GoBuildOptimizer;
        assert!(opt.optimize("go: downloading x v1\nok\n").is_none());
    }
}
