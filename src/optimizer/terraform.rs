// src/optimizer/terraform.rs
use super::{collapse_noise_runs, CommandOptimizer};

pub struct TerraformOptimizer;

/// A line worth keeping during a `terraform plan`/`apply`: the per-resource
/// action headers, the final plan/apply summary, and any error or warning.
/// Everything else (state-refresh chatter and the long attribute diff bodies)
/// is collapsible noise.
fn is_important(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.starts_with("error")
        || lower.starts_with("warning")
        || lower.starts_with("│ error")
        || lower.starts_with("│ warning")
        || line.starts_with("Plan:")
        || line.starts_with("Apply complete!")
        || line.starts_with("Destroy complete!")
        || line.starts_with("No changes.")
        || line.contains("will be created")
        || line.contains("will be destroyed")
        || line.contains("will be updated")
        || line.contains("will be replaced")
        || line.contains("must be replaced")
        || line.contains("forces replacement")
}

impl CommandOptimizer for TerraformOptimizer {
    fn name(&self) -> &'static str {
        "terraform"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        cmd == "terraform" && args.iter().any(|a| a == "plan" || a == "apply")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        // Noise = everything that is NOT a header/summary/diagnostic.
        collapse_noise_runs(input, 15, |line| !is_important(line), "plan lines")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_terraform_plan_and_apply() {
        assert!(TerraformOptimizer.matches("terraform", &args(&["plan"])));
        assert!(TerraformOptimizer.matches("terraform", &args(&["apply", "-auto-approve"])));
        assert!(!TerraformOptimizer.matches("terraform", &args(&["init"])));
        assert!(!TerraformOptimizer.matches("tofu", &args(&["plan"])));
    }

    #[test]
    fn keeps_headers_summary_and_collapses_refresh_and_diff() {
        let mut input = String::new();
        for i in 0..10 {
            input.push_str(&format!(
                "aws_instance.node[{}]: Refreshing state... [id=i-0abc{}]\n",
                i, i
            ));
        }
        input.push_str("  # aws_instance.web will be updated in-place\n");
        input.push_str("  ~ resource \"aws_instance\" \"web\" {\n");
        for i in 0..8 {
            input.push_str(&format!("      ~ attribute_{} = \"old\" -> \"new\"\n", i));
        }
        input.push_str("    }\n");
        input.push_str("Plan: 0 to add, 1 to change, 0 to destroy.\n");

        let out = TerraformOptimizer.optimize(&input).unwrap();
        assert!(out.contains("# aws_instance.web will be updated in-place"));
        assert!(out.contains("Plan: 0 to add, 1 to change, 0 to destroy."));
        assert!(out.contains("plan lines hidden"));
        assert!(!out.contains("Refreshing state"));
        assert!(out.lines().count() < input.lines().count());
    }

    #[test]
    fn passthrough_small() {
        let input = "Plan: 1 to add, 0 to change, 0 to destroy.\n";
        assert!(TerraformOptimizer.optimize(input).is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_optimize_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = TerraformOptimizer.optimize(&s);
        }
    }
}
