use super::CommandOptimizer;

/// Collapses .NET's NuGet-restore chatter (`Determining projects to restore`,
/// `Restored …`, `Restoring packages …`) while keeping build results,
/// `CS####`/`NU####` diagnostics, and the warning/error summary verbatim.
pub struct DotnetOptimizer;

impl CommandOptimizer for DotnetOptimizer {
    fn name(&self) -> &'static str {
        "dotnet"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        cmd == "dotnet"
            && args.first().is_some_and(|a| {
                matches!(a.as_str(), "build" | "restore" | "test" | "publish" | "run")
            })
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_restore_line, "restore lines")
    }
}

fn is_restore_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("Determining projects to restore")
        || t.starts_with("Restored ")
        || t.starts_with("Restoring packages")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_dotnet_build_family() {
        let opt = DotnetOptimizer;
        assert!(opt.matches("dotnet", &args(&["build"])));
        assert!(opt.matches("dotnet", &args(&["restore"])));
        assert!(opt.matches("dotnet", &args(&["test", "-c", "Release"])));
        assert!(!opt.matches("dotnet", &args(&["--version"])));
        assert!(!opt.matches("go", &args(&["build"])));
    }

    #[test]
    fn collapses_restore_keeps_build_result() {
        let opt = DotnetOptimizer;
        let input = concat!(
            "Determining projects to restore...\n",
            "Restored /src/A/A.csproj (in 120 ms).\n",
            "Restored /src/B/B.csproj (in 130 ms).\n",
            "Restored /src/C/C.csproj (in 140 ms).\n",
            "Restored /src/D/D.csproj (in 150 ms).\n",
            "Restoring packages for /src/E/E.csproj...\n",
            "  E.csproj -> /src/E/bin/Debug/net8.0/E.dll\n",
            "Build succeeded.\n",
            "    0 Warning(s)\n",
            "    0 Error(s)\n"
        );

        let out = opt.optimize(input).unwrap();
        assert!(out.contains("restore lines hidden"), "got: {out}");
        assert!(out.contains("Build succeeded."));
        assert!(out.contains("0 Error(s)"));
        assert!(out.contains("[summarized by vallum]"));
        assert!(!out.contains("A.csproj (in"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = DotnetOptimizer;
        assert!(opt.optimize("Build succeeded.\n0 Error(s)\n").is_none());
    }
}
