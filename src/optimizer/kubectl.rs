// src/optimizer/kubectl.rs
use super::{collapse_noise_runs, CommandOptimizer};

pub struct KubectlOptimizer;

/// Status tokens that signal a resource needs attention. A row carrying any of
/// these is always kept verbatim so problems are never hidden.
const PROBLEM_STATES: &[&str] = &[
    "Error",
    "CrashLoopBackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "Pending",
    "Evicted",
    "OOMKilled",
    "Terminating",
    "Failed",
    "Unknown",
    "NotReady",
    "ContainerCreating",
    "Init:",
    "RunContainerError",
    "CreateContainerConfigError",
];

/// A "healthy" `kubectl get` row: a Running/Completed resource with nothing that
/// looks like a problem. These are the rows worth collapsing in a long listing.
/// The header row (`NAME ... STATUS`) carries neither token, so it is kept.
fn is_healthy_row(line: &str) -> bool {
    let healthy = line.contains("Running") || line.contains("Completed");
    if !healthy {
        return false;
    }
    !PROBLEM_STATES.iter().any(|s| line.contains(s))
}

impl CommandOptimizer for KubectlOptimizer {
    fn name(&self) -> &'static str {
        "kubectl"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        cmd == "kubectl" && args.iter().any(|a| a == "get")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        collapse_noise_runs(input, 15, is_healthy_row, "healthy resources")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_kubectl_get() {
        assert!(KubectlOptimizer.matches("kubectl", &args(&["get", "pods"])));
        assert!(KubectlOptimizer.matches("kubectl", &args(&["get", "all", "-A"])));
        assert!(!KubectlOptimizer.matches("kubectl", &args(&["describe", "pod", "x"])));
        assert!(!KubectlOptimizer.matches("helm", &args(&["get", "pods"])));
    }

    #[test]
    fn collapses_healthy_keeps_header_and_problems() {
        let mut input = String::from("NAME                     READY   STATUS    RESTARTS   AGE\n");
        for i in 0..20 {
            input.push_str(&format!(
                "web-deploy-{:02}            1/1     Running   0          5d\n",
                i
            ));
        }
        input.push_str("api-broken-7c9            0/1     CrashLoopBackOff   8          2m\n");
        input.push_str("batch-job-xyz            0/1     Completed   0          1h\n");

        let out = KubectlOptimizer.optimize(&input).unwrap();
        // Header and the failing pod survive.
        assert!(out.contains("NAME                     READY"));
        assert!(out.contains("api-broken-7c9"));
        assert!(out.contains("CrashLoopBackOff"));
        assert!(out.contains("healthy resources hidden"));
        assert!(out.lines().count() < input.lines().count());
    }

    #[test]
    fn passthrough_small() {
        let input =
            "NAME   READY   STATUS    RESTARTS   AGE\nweb    1/1     Running   0          5d\n";
        assert!(KubectlOptimizer.optimize(input).is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_optimize_does_not_panic(s in "[\\s\\S]{0,500}") {
            let _ = KubectlOptimizer.optimize(&s);
        }
    }
}
