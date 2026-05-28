// src/optimizer/docker.rs
use super::{collapse_noise_runs, CommandOptimizer};

pub struct DockerOptimizer;

fn is_progress(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("---> ")
        || t.starts_with("Step ")
        || t.starts_with("#")
        || t.contains("Pulling fs layer")
        || t.contains("Waiting")
        || t.contains("Downloading")
        || t.contains("Download complete")
        || t.contains("Extracting")
        || t.contains("Pull complete")
        || t.contains("Already exists")
        || t.contains("Verifying Checksum")
        || line.is_empty()
}

impl CommandOptimizer for DockerOptimizer {
    fn name(&self) -> &'static str {
        "docker"
    }

    fn matches(&self, cmd: &str, args: &[String]) -> bool {
        if cmd == "docker-compose" {
            return true;
        }
        cmd == "docker" && args.iter().any(|a| a == "build" || a == "compose")
    }

    fn optimize(&self, input: &str) -> Option<String> {
        collapse_noise_runs(input, 15, is_progress, "build/progress lines")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn matches_docker_build_and_compose() {
        assert!(DockerOptimizer.matches("docker", &args(&["build", "."])));
        assert!(DockerOptimizer.matches("docker", &args(&["compose", "up"])));
        assert!(DockerOptimizer.matches("docker-compose", &args(&["up"])));
        assert!(!DockerOptimizer.matches("docker", &args(&["ps"])));
    }

    #[test]
    fn collapses_progress_keeps_result() {
        let mut input = String::from("Step 1/3 : FROM rust:1.77\n");
        for i in 0..20 {
            input.push_str(&format!("#{} extracting layer\n", i)); // progress (starts with #)
        }
        input.push_str("ERROR: failed to solve: missing file\n");
        input.push_str("Successfully built abc123\n");
        let out = DockerOptimizer.optimize(&input).unwrap();
        assert!(out.contains("ERROR: failed to solve: missing file"));
        assert!(out.contains("Successfully built abc123"));
        assert!(out.contains("build/progress lines hidden"));
        assert!(out.lines().count() < input.lines().count());
    }

    #[test]
    fn passthrough_small() {
        let input = "Step 1/1 : FROM scratch\nSuccessfully built x\n";
        assert!(DockerOptimizer.optimize(input).is_none());
    }
}
