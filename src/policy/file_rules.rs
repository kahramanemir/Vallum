//! Lexical path rules for agent file tools (Write/Edit/Read …). The Claude
//! hook gates file-tool calls through here: no regex, no filesystem access —
//! `~`/`$HOME` expansion plus textual `.`/`..` resolution only (symlinks are
//! NOT resolved; disclosed in SECURITY.md). All rules are Ask-severity.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    Write,
    Read,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRuleMatch {
    pub rule_name: &'static str,
    pub reason: &'static str,
}

struct FileRule {
    name: &'static str,
    op: FileOp,
    reason: &'static str,
    matches: fn(path: &str, home: &str, file_name: &str) -> bool,
}

const PROFILE_NAMES: &[&str] = &[
    ".zshenv",
    ".zshrc",
    ".zprofile",
    ".bashrc",
    ".bash_profile",
    ".profile",
];

fn under(path: &str, dir: &str) -> bool {
    !dir.is_empty() && path.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
}

fn rules() -> &'static [FileRule] {
    &[
        FileRule {
            name: "file_write_shell_profile",
            op: FileOp::Write,
            reason: "Writing to a shell startup file (persistence, CVE-2026-55607 class)",
            matches: |path, home, file_name| {
                !home.is_empty()
                    && PROFILE_NAMES.contains(&file_name)
                    && path == format!("{home}/{file_name}")
            },
        },
        FileRule {
            name: "file_write_ssh_config",
            op: FileOp::Write,
            reason: "Writing under ~/.ssh (persistent access)",
            matches: |path, home, _| under(path, &format!("{home}/.ssh")),
        },
        FileRule {
            name: "file_write_git_hooks",
            op: FileOp::Write,
            reason: "Writing a git hook (persistence)",
            matches: |path, _, _| path.contains("/.git/hooks/"),
        },
        FileRule {
            name: "file_write_crontab_dir",
            op: FileOp::Write,
            reason: "Writing a cron file (persistence)",
            matches: |path, _, _| {
                path == "/etc/crontab"
                    || path
                        .strip_prefix("/etc/cron.")
                        .is_some_and(|r| r.contains('/'))
                    || under(path, "/var/spool/cron")
            },
        },
        FileRule {
            name: "file_write_launch_agents",
            op: FileOp::Write,
            reason: "Writing a LaunchAgent/LaunchDaemon (persistence)",
            matches: |path, home, _| {
                under(path, &format!("{home}/Library/LaunchAgents"))
                    || under(path, "/Library/LaunchAgents")
                    || under(path, "/Library/LaunchDaemons")
            },
        },
        FileRule {
            name: "file_write_systemd_user",
            op: FileOp::Write,
            reason: "Writing a systemd user unit (persistence)",
            matches: |path, home, _| under(path, &format!("{home}/.config/systemd/user")),
        },
        FileRule {
            name: "file_write_agent_config",
            op: FileOp::Write,
            reason: "Writing to an AI agent config/hook file (possible hook injection)",
            matches: |path, _, file_name| {
                path.ends_with("/.claude/settings.json")
                    || path.ends_with("/.claude/settings.local.json")
                    || path.ends_with("/.cursor/hooks.json")
                    || path.ends_with("/.codex/hooks.json")
                    || path.ends_with("/.codex/config.toml")
                    || path.ends_with("/.gemini/settings.json")
                    || file_name == ".mcp.json"
            },
        },
        FileRule {
            name: "file_write_vallum",
            op: FileOp::Write,
            reason: "Writing to Vallum's own config/state directory (guardrail self-disable)",
            matches: |path, home, _| under(path, &format!("{home}/.vallum")),
        },
        FileRule {
            name: "file_read_sensitive",
            op: FileOp::Read,
            reason: "Reading a private key, credential file, or shadow password file",
            matches: |path, home, file_name| {
                (under(path, &format!("{home}/.ssh"))
                    && file_name.starts_with("id_")
                    && !file_name.ends_with(".pub"))
                    || (!home.is_empty() && path == format!("{home}/.aws/credentials"))
                    || path == "/etc/shadow"
                    || file_name == "approval.secret"
            },
        },
    ]
}

/// Expand `~`/`$HOME`, absolutize against the cwd, and resolve `.`/`..`
/// textually. Never touches the filesystem and never fails: an odd input is
/// normalized as far as possible and matched as-is.
fn normalize(raw: &str, home: &str) -> String {
    let trimmed = raw.trim();
    let mut p = if trimmed == "~" || trimmed == "$HOME" {
        home.to_string()
    } else if let Some(rest) = trimmed.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("$HOME/") {
        format!("{home}/{rest}")
    } else {
        trimmed.to_string()
    };
    if !p.starts_with('/') {
        if let Ok(cwd) = std::env::current_dir() {
            p = format!("{}/{}", cwd.to_string_lossy(), p);
        }
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// Evaluate one file-tool access. Returns the first matching enabled rule
/// (rules are disjoint in practice), or None for Allow-equivalent.
pub fn evaluate(op: FileOp, raw_path: &str, disabled: &[String]) -> Option<FileRuleMatch> {
    let home = dirs::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default();
    let path = normalize(raw_path, &home);
    let file_name = path.rsplit('/').next().unwrap_or("");
    rules()
        .iter()
        .filter(|r| r.op == op)
        .filter(|r| !disabled.iter().any(|d| d == r.name))
        .find(|r| (r.matches)(&path, &home, file_name))
        .map(|r| FileRuleMatch {
            rule_name: r.name,
            reason: r.reason,
        })
}

/// File-rule names, for `[policy] disabled` validation in doctor.
pub fn rule_names() -> Vec<&'static str> {
    rules().iter().map(|r| r.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> String {
        dirs::home_dir().unwrap().to_string_lossy().into_owned()
    }

    fn write_hit(path: &str) -> Option<&'static str> {
        evaluate(FileOp::Write, path, &[]).map(|m| m.rule_name)
    }

    fn read_hit(path: &str) -> Option<&'static str> {
        evaluate(FileOp::Read, path, &[]).map(|m| m.rule_name)
    }

    #[test]
    fn tilde_and_home_var_expand() {
        assert_eq!(write_hit("~/.zshenv"), Some("file_write_shell_profile"));
        assert_eq!(write_hit("$HOME/.zshrc"), Some("file_write_shell_profile"));
        assert_eq!(
            write_hit(&format!("{}/.bashrc", home())),
            Some("file_write_shell_profile")
        );
    }

    #[test]
    fn dotdot_traversal_is_resolved() {
        assert_eq!(
            write_hit(&format!("{}/project/../.zshenv", home())),
            Some("file_write_shell_profile")
        );
    }

    #[test]
    fn profile_names_are_home_anchored() {
        // .zshrc inside a project dir is NOT the login shell's rc file.
        assert_eq!(write_hit(&format!("{}/proj/.zshrc", home())), None);
        // Suffix near-miss must not match.
        assert_eq!(write_hit("~/.zshrc.bak"), None);
    }

    #[test]
    fn ssh_dir_writes_ask() {
        assert_eq!(
            write_hit("~/.ssh/authorized_keys"),
            Some("file_write_ssh_config")
        );
        assert_eq!(write_hit("~/.ssh/config"), Some("file_write_ssh_config"));
        // Component anchoring: "notssh" and a project file named .ssh-something.
        assert_eq!(write_hit(&format!("{}/notssh/config", home())), None);
    }

    #[test]
    fn git_hooks_anywhere() {
        assert_eq!(
            write_hit("/Users/x/proj/.git/hooks/pre-commit"),
            Some("file_write_git_hooks")
        );
        assert_eq!(write_hit("/Users/x/proj/.github/workflows/ci.yml"), None);
    }

    #[test]
    fn cron_paths() {
        assert_eq!(write_hit("/etc/crontab"), Some("file_write_crontab_dir"));
        assert_eq!(
            write_hit("/etc/cron.d/backdoor"),
            Some("file_write_crontab_dir")
        );
        assert_eq!(
            write_hit("/var/spool/cron/crontabs/root"),
            Some("file_write_crontab_dir")
        );
        // Component anchoring: /etc/cronicle is not cron.
        assert_eq!(write_hit("/etc/cronicle/conf.json"), None);
    }

    #[test]
    fn launch_agents_and_daemons() {
        assert_eq!(
            write_hit("~/Library/LaunchAgents/com.evil.plist"),
            Some("file_write_launch_agents")
        );
        assert_eq!(
            write_hit("/Library/LaunchDaemons/com.evil.plist"),
            Some("file_write_launch_agents")
        );
        assert_eq!(write_hit("~/Library/Application Support/x.plist"), None);
    }

    #[test]
    fn systemd_user_units() {
        assert_eq!(
            write_hit("~/.config/systemd/user/evil.service"),
            Some("file_write_systemd_user")
        );
        assert_eq!(write_hit("~/.config/systemd/other.conf"), None);
    }

    #[test]
    fn agent_configs() {
        assert_eq!(
            write_hit("/Users/x/proj/.claude/settings.json"),
            Some("file_write_agent_config")
        );
        assert_eq!(
            write_hit("~/.claude/settings.local.json"),
            Some("file_write_agent_config")
        );
        assert_eq!(
            write_hit("~/.codex/config.toml"),
            Some("file_write_agent_config")
        );
        assert_eq!(
            write_hit("/Users/x/proj/.mcp.json"),
            Some("file_write_agent_config")
        );
        // Other files under .claude/ are fine (e.g. CLAUDE.md lives elsewhere anyway).
        assert_eq!(write_hit("~/.claude/projects/foo.md"), None);
    }

    #[test]
    fn vallum_dir_is_self_protected() {
        assert_eq!(
            write_hit("~/.vallum/config.toml"),
            Some("file_write_vallum")
        );
        assert_eq!(
            write_hit("~/.vallum/logs/policy.log"),
            Some("file_write_vallum")
        );
        assert_eq!(
            write_hit(&format!("{}/proj/.vallum-notes.md", home())),
            None
        );
    }

    #[test]
    fn sensitive_reads() {
        assert_eq!(read_hit("~/.ssh/id_rsa"), Some("file_read_sensitive"));
        assert_eq!(read_hit("~/.ssh/id_ed25519"), Some("file_read_sensitive"));
        // Public halves are fine.
        assert_eq!(read_hit("~/.ssh/id_rsa.pub"), None);
        assert_eq!(read_hit("~/.aws/credentials"), Some("file_read_sensitive"));
        assert_eq!(read_hit("/etc/shadow"), Some("file_read_sensitive"));
        assert_eq!(
            read_hit("~/.vallum/logs/approval.secret"),
            Some("file_read_sensitive")
        );
        // Reads are not gated by write rules and vice versa.
        assert_eq!(read_hit("~/.zshenv"), None);
        assert_eq!(write_hit("/etc/shadow"), None);
    }

    #[test]
    fn benign_everyday_paths_pass() {
        for p in [
            "/Users/x/proj/README.md",
            "/Users/x/proj/src/main.rs",
            "~/.config/git/ignore",
            "~/Downloads/notes.txt",
            "/tmp/scratch.json",
        ] {
            assert_eq!(write_hit(p), None, "write {p}");
            assert_eq!(read_hit(p), None, "read {p}");
        }
    }

    #[test]
    fn disabled_list_suppresses_a_rule() {
        let disabled = vec!["file_write_shell_profile".to_string()];
        assert!(evaluate(FileOp::Write, "~/.zshenv", &disabled).is_none());
        // Other rules unaffected.
        assert!(evaluate(FileOp::Write, "~/.ssh/config", &disabled).is_some());
    }

    #[test]
    fn rule_names_lists_all_nine() {
        let names = rule_names();
        assert_eq!(names.len(), 9);
        assert!(names.contains(&"file_write_vallum"));
        assert!(names.contains(&"file_read_sensitive"));
    }
}
