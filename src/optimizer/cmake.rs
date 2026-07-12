use super::CommandOptimizer;

/// Collapses CMake's compiler/feature-probe chatter (`-- Detecting …`,
/// `-- Looking for …`, `-- Check for working …`, `-- Performing Test …`,
/// `-- Found …`) while keeping errors, warnings, and the meaningful
/// `-- Configuring done` / `-- Generating done` / `-- Build files …` lines
/// verbatim.
pub struct CmakeOptimizer;

impl CommandOptimizer for CmakeOptimizer {
    fn name(&self) -> &'static str {
        "cmake"
    }

    fn matches(&self, cmd: &str, _args: &[String]) -> bool {
        cmd == "cmake"
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_probe_line, "probe lines")
    }
}

fn is_probe_line(line: &str) -> bool {
    let t = line.trim_start();
    let Some(rest) = t.strip_prefix("-- ") else {
        return false;
    };
    rest.starts_with("Detecting")
        || rest.starts_with("Looking for")
        || rest.starts_with("Check for working")
        || rest.starts_with("Performing Test")
        || rest.starts_with("Found ")
        || rest.starts_with("Checking for")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_cmake_only() {
        let opt = CmakeOptimizer;
        assert!(opt.matches("cmake", &args(&["--build", "."])));
        assert!(!opt.matches("make", &args(&[])));
        assert!(!opt.matches("ninja", &args(&[])));
    }

    #[test]
    fn collapses_probes_keeps_result_and_errors() {
        let opt = CmakeOptimizer;
        let input = concat!(
            "-- The C compiler identification is GNU 11.2.0\n",
            "-- Detecting C compiler ABI info\n",
            "-- Detecting C compiler ABI info - done\n",
            "-- Check for working C compiler: /usr/bin/cc - skipped\n",
            "-- Looking for pthread.h\n",
            "-- Looking for pthread.h - found\n",
            "-- Performing Test HAVE_FLAG\n",
            "-- Found Threads: TRUE\n",
            "CMake Warning at CMakeLists.txt:5 (message):\n",
            "  deprecated option\n",
            "-- Configuring done\n",
            "-- Generating done\n",
            "-- Build files have been written to: /tmp/build\n"
        );

        let out = opt.optimize(input).unwrap();
        assert!(out.contains("probe lines hidden"), "got: {out}");
        assert!(out.contains("CMake Warning at CMakeLists.txt:5"));
        assert!(out.contains("-- Configuring done"));
        assert!(out.contains("-- Build files have been written to: /tmp/build"));
        assert!(out.contains("[summarized by vallum]"));
        assert!(!out.contains("Detecting C compiler ABI info"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = CmakeOptimizer;
        assert!(opt.optimize("-- Configuring done\n").is_none());
    }
}
