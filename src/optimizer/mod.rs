// src/optimizer/mod.rs
pub mod git_status;

pub trait CommandOptimizer {
    fn name(&self) -> &'static str;
    fn matches(&self, cmd: &str, args: &[String]) -> bool;
    fn optimize(&self, input: &str) -> Option<String>;
}

pub fn dispatch(
    cmd: &str,
    args: &[String],
    input: &str,
) -> Option<(String, &'static str)> {
    let optimizers: Vec<Box<dyn CommandOptimizer>> = vec![
        Box::new(git_status::GitStatusOptimizer),
    ];

    for opt in &optimizers {
        if opt.matches(cmd, args) {
            if let Some(out) = opt.optimize(input) {
                return Some((out, opt.name()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysMatch;
    impl CommandOptimizer for AlwaysMatch {
        fn name(&self) -> &'static str { "always_match" }
        fn matches(&self, _cmd: &str, _args: &[String]) -> bool { true }
        fn optimize(&self, input: &str) -> Option<String> { Some(format!("OPT:{}", input)) }
    }

    #[test]
    fn dispatch_matches_git_status_when_input_is_long() {
        let mut files = String::new();
        for i in 0..40 {
            files.push_str(&format!("\tmodified:   src/file_{}.rs\n", i));
        }
        let input = format!(
            "On branch main\nYour branch is up to date with 'origin/main'.\n\nChanges to be committed:\n{}\n",
            files
        );
        let result = dispatch("git", &["status".to_string()], &input);
        assert!(result.is_some());
        let (out, name) = result.unwrap();
        assert_eq!(name, "git_status");
        assert!(out.contains("[summarized by vallum]"));
    }

    #[test]
    fn dispatch_returns_none_for_unknown_command() {
        let result = dispatch("ls", &[], "foo");
        assert!(result.is_none());
    }

    #[test]
    fn trait_dispatch_returns_name_and_output() {
        let opt = AlwaysMatch;
        assert!(opt.matches("anything", &[]));
        assert_eq!(opt.optimize("x").unwrap(), "OPT:x");
        assert_eq!(opt.name(), "always_match");
    }
}
