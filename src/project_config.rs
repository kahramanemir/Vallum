//! Project-level `.vallum.toml`: a repo-committed, tighten-only policy file.
//!
//! Threat model: this file is ATTACKER-ADJACENT — cloning an untrusted repo
//! brings it along, and the hook picks it up from the agent's cwd. It may
//! therefore contain ONLY additional ask/deny rules; every other key is
//! rejected by name (`deny_unknown_fields` at every level). A broken or
//! forbidden file is loudly ignored: gating continues on the global config
//! alone. That can never fail open (the file can only tighten, so ignoring
//! it never weakens) and it denies a malicious repo the ability to DoS
//! `vallum run` with a crafted config. Only the git-root file is read — a
//! subdirectory `.vallum.toml` can never shadow the reviewed root one.

use crate::config::PolicyRuleConfig;
use regex::Regex;
use serde::Deserialize;
use std::path::{Path, PathBuf};

const MAX_RULES: usize = 64;
const MAX_PATTERN_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 200;

pub const PROJECT_FILE_NAME: &str = ".vallum.toml";
const KILL_SWITCH_ENV: &str = "VALLUM_NO_PROJECT_CONFIG";

#[derive(Debug)]
pub enum LoadOutcome {
    /// No project file found (or the kill switch is set).
    None,
    Loaded {
        path: PathBuf,
        rules: Vec<PolicyRuleConfig>,
    },
    Rejected {
        path: PathBuf,
        reason: String,
    },
}

// Narrow schema: anything not listed here is a hard rejection that names the
// offending key. Do NOT reuse AppConfig here — the whole point is that the
// project file cannot express the rest of the config surface.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectFile {
    #[serde(default)]
    policy: ProjectPolicy,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ProjectPolicy {
    #[serde(default)]
    rules: Vec<ProjectRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRule {
    pattern: String,
    action: String,
    reason: String,
}

/// Nearest ancestor of `start` (inclusive) containing `.git` (dir or file —
/// worktrees use a `.git` file). Lexical walk, no filesystem canonicalization.
pub fn git_root_from(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start.to_path_buf());
    while let Some(dir) = cur {
        let dotgit = dir.join(".git");
        if dotgit.is_dir() || dotgit.is_file() {
            return Some(dir);
        }
        cur = dir.parent().map(|p| p.to_path_buf());
    }
    None
}

/// The single project-config path considered: `<git-root>/.vallum.toml`, or
/// `./.vallum.toml` when cwd is not inside a git repo. None when absent or
/// when `VALLUM_NO_PROJECT_CONFIG=1`.
fn project_file_path() -> Option<PathBuf> {
    if std::env::var(KILL_SWITCH_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return None;
    }
    let cwd = std::env::current_dir().ok()?;
    let root = git_root_from(&cwd).unwrap_or(cwd);
    let p = root.join(PROJECT_FILE_NAME);
    p.is_file().then_some(p)
}

/// Parse and validate one project file into plain rule configs.
pub(crate) fn parse_file(path: &Path) -> Result<Vec<PolicyRuleConfig>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read failed: {e}"))?;
    let file: ProjectFile = toml::from_str(&raw).map_err(|e| e.to_string())?;
    if file.policy.rules.len() > MAX_RULES {
        return Err(format!(
            "{} rules exceed the {MAX_RULES}-rule cap",
            file.policy.rules.len()
        ));
    }
    let mut out = Vec::new();
    for rule in &file.policy.rules {
        if rule.pattern.len() > MAX_PATTERN_BYTES {
            // Char-safe truncation for the error message — a byte slice could
            // split a multi-byte character and panic.
            let head: String = rule.pattern.chars().take(40).collect();
            return Err(format!(
                "pattern exceeds {MAX_PATTERN_BYTES} bytes: '{head}…'"
            ));
        }
        if rule.reason.len() > MAX_REASON_BYTES {
            return Err(format!("reason exceeds {MAX_REASON_BYTES} bytes"));
        }
        if rule.reason.trim().is_empty() {
            return Err(format!("rule '{}' needs a non-empty reason", rule.pattern));
        }
        match rule.action.as_str() {
            "ask" | "deny" => {}
            "allow" => {
                return Err(format!(
                    "action \"allow\" is not allowed in a project config (pattern '{}'); \
                     scoped allows live in the global config only ([[policy.allow]])",
                    rule.pattern
                ))
            }
            other => {
                return Err(format!(
                    "invalid action \"{other}\" (pattern '{}'); expected \"ask\" or \"deny\"",
                    rule.pattern
                ))
            }
        }
        Regex::new(&rule.pattern).map_err(|e| format!("invalid regex '{}': {e}", rule.pattern))?;
        out.push(PolicyRuleConfig {
            pattern: rule.pattern.clone(),
            action: rule.action.clone(),
            reason: rule.reason.clone(),
        });
    }
    Ok(out)
}

/// Discover and load the project config. Rejection warns on stderr HERE (the
/// single choke point both the hook and direct commands pass through) and the
/// caller continues with the global config alone.
pub fn load() -> LoadOutcome {
    let Some(path) = project_file_path() else {
        return LoadOutcome::None;
    };
    match parse_file(&path) {
        Ok(rules) => LoadOutcome::Loaded { path, rules },
        Err(reason) => {
            eprintln!(
                "vallum: ignoring project config {}: {reason} — gating continues on the \
                 global config (a project file can only tighten, so ignoring it never weakens)",
                path.display()
            );
            LoadOutcome::Rejected { path, reason }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "vallum_projcfg_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_project(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join(PROJECT_FILE_NAME);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn valid_file_parses_rules() {
        let d = temp_dir("ok");
        let p = write_project(
            &d,
            "[[policy.rules]]\npattern = 'terraform\\s+destroy'\naction = \"deny\"\nreason = \"prod guard\"\n",
        );
        let rules = parse_file(&p).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, "deny");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn every_forbidden_table_is_rejected_by_name() {
        let d = temp_dir("forbidden");
        for (body, needle) in [
            ("[policy]\ndisabled = [\"rm_rf_root\"]\n", "disabled"),
            (
                "[[policy.allow]]\npattern = 'x'\nsuppresses = \"git_push_force\"\nreason = \"r\"\n",
                "allow",
            ),
            ("[security]\nguardrail = false\n", "security"),
            ("[audit]\nlog_dir = \"/tmp/x\"\n", "audit"),
            ("[scrubber]\nextra_secret_patterns = []\n", "scrubber"),
            ("[optimizer]\ndisabled = [\"npm\"]\n", "optimizer"),
            ("[pipeline]\nhead_lines = 1\n", "pipeline"),
        ] {
            let p = write_project(&d, body);
            let err = parse_file(&p).unwrap_err();
            assert!(
                err.contains(needle),
                "body {body:?} must be rejected naming {needle:?}, got: {err}"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn allow_action_and_bad_action_and_bad_regex_are_rejected() {
        let d = temp_dir("actions");
        let p = write_project(
            &d,
            "[[policy.rules]]\npattern = 'x'\naction = \"allow\"\nreason = \"r\"\n",
        );
        let err = parse_file(&p).unwrap_err();
        assert!(err.contains("global config"), "{err}");
        let p = write_project(
            &d,
            "[[policy.rules]]\npattern = 'x'\naction = \"warn\"\nreason = \"r\"\n",
        );
        assert!(parse_file(&p).is_err());
        let p = write_project(
            &d,
            "[[policy.rules]]\npattern = '('\naction = \"ask\"\nreason = \"r\"\n",
        );
        assert!(parse_file(&p).unwrap_err().contains("regex"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn caps_are_enforced() {
        let d = temp_dir("caps");
        let mut body = String::new();
        for i in 0..65 {
            body.push_str(&format!(
                "[[policy.rules]]\npattern = 'cmd{i}'\naction = \"ask\"\nreason = \"r\"\n"
            ));
        }
        let p = write_project(&d, &body);
        assert!(parse_file(&p).unwrap_err().contains("cap"));
        let long = "a".repeat(513);
        let p = write_project(
            &d,
            &format!("[[policy.rules]]\npattern = '{long}'\naction = \"ask\"\nreason = \"r\"\n"),
        );
        assert!(parse_file(&p).unwrap_err().contains("512"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn git_root_walk_finds_dotgit_dir_and_file() {
        let d = temp_dir("walk");
        std::fs::create_dir_all(d.join("repo/.git")).unwrap();
        std::fs::create_dir_all(d.join("repo/a/b")).unwrap();
        assert_eq!(git_root_from(&d.join("repo/a/b")), Some(d.join("repo")));
        // Worktree-style `.git` FILE.
        std::fs::create_dir_all(d.join("wt/sub")).unwrap();
        std::fs::write(d.join("wt/.git"), "gitdir: /elsewhere\n").unwrap();
        assert_eq!(git_root_from(&d.join("wt/sub")), Some(d.join("wt")));
        // No .git anywhere under the temp root ⇒ walk escapes upward; we only
        // assert it does NOT stop at these dirs.
        assert_ne!(git_root_from(&d), Some(d.clone()));
        let _ = std::fs::remove_dir_all(&d);
    }
}
