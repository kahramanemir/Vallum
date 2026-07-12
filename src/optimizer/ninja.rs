use super::CommandOptimizer;

/// Collapses Ninja's `[N/M] …` build-progress lines while keeping compiler
/// warnings, errors, and any other non-progress output verbatim.
pub struct NinjaOptimizer;

impl CommandOptimizer for NinjaOptimizer {
    fn name(&self) -> &'static str {
        "ninja"
    }

    fn matches(&self, cmd: &str, _args: &[String]) -> bool {
        cmd == "ninja"
    }

    fn optimize(&self, input: &str) -> Option<String> {
        super::collapse_noise_runs(input, 10, is_progress_line, "build steps")
    }
}

/// True for a `[<digits>/<digits>] …` Ninja progress line.
fn is_progress_line(line: &str) -> bool {
    let t = line.trim_start();
    let Some(rest) = t.strip_prefix('[') else {
        return false;
    };
    let Some((counter, _)) = rest.split_once(']') else {
        return false;
    };
    let Some((num, den)) = counter.split_once('/') else {
        return false;
    };
    !num.is_empty()
        && !den.is_empty()
        && num.bytes().all(|b| b.is_ascii_digit())
        && den.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_ninja_only() {
        let opt = NinjaOptimizer;
        assert!(opt.matches("ninja", &args(&[])));
        assert!(!opt.matches("make", &args(&[])));
    }

    #[test]
    fn collapses_progress_keeps_warnings() {
        let opt = NinjaOptimizer;
        let mut input = String::new();
        for i in 1..=12 {
            input.push_str(&format!(
                "[{i}/12] Building CXX object src/CMakeFiles/foo.dir/f{i}.cpp.o\n"
            ));
        }
        input.push_str("../src/f3.cpp:10:5: warning: unused variable 'x'\n");
        input.push_str("[12/12] Linking CXX executable foo\n");

        let out = opt.optimize(&input).unwrap();
        assert!(out.contains("build steps hidden"), "got: {out}");
        assert!(out.contains("warning: unused variable 'x'"));
        assert!(out.contains("[summarized by vallum]"));
        assert!(!out.contains("f1.cpp.o"));
    }

    #[test]
    fn passes_through_short_output() {
        let opt = NinjaOptimizer;
        assert!(opt.optimize("[1/1] Linking foo\n").is_none());
    }

    #[test]
    fn non_progress_bracket_line_is_not_noise() {
        assert!(!is_progress_line("[info] building"));
        assert!(!is_progress_line("[1/] partial"));
        assert!(is_progress_line("[7/512] Building"));
    }
}
