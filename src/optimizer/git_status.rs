// src/optimizer/git_status.rs
use super::CommandOptimizer;

pub struct GitStatusOptimizer;

impl CommandOptimizer for GitStatusOptimizer {
    fn name(&self) -> &'static str {
        "git_status"
    }

    fn matches(&self, _cmd: &str, _args: &[String]) -> bool {
        false
    }

    fn optimize(&self, _input: &str) -> Option<String> {
        None
    }
}
