// tests/project_config_cli.rs — project-level .vallum.toml end-to-end.
use std::process::Command;

fn vallum_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vallum")
}

fn temp_repo(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("vallum_projcli_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    let cfg = dir.join("global-config.toml");
    std::fs::write(&cfg, format!("[audit]\nlog_dir = \"{}\"\n", dir.display())).unwrap();
    (dir, cfg)
}

#[test]
fn config_init_project_scaffolds_and_refuses_overwrite() {
    let (dir, cfg) = temp_repo("init");
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["config", "init", "--project"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let body = std::fs::read_to_string(dir.join(".vallum.toml")).unwrap();
    assert!(body.contains("[[policy.rules]]"), "{body}");
    assert!(body.contains("tighten-only"), "{body}");
    // Second run without --force refuses (still exit 0, message says exists).
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["config", "init", "--project"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("already exists"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn write_project_rule(dir: &std::path::Path) {
    std::fs::write(
        dir.join(".vallum.toml"),
        "[[policy.rules]]\npattern = 'echo BLOCKME'\naction = \"deny\"\nreason = \"project deny\"\n",
    )
    .unwrap();
}

#[test]
fn project_deny_rule_fires_in_direct_run_with_attribution() {
    let (dir, cfg) = temp_repo("deny");
    write_project_rule(&dir);
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["run", "echo", "BLOCKME"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&out.stderr).contains("project deny"));
    // policy test attributes the source.
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["policy", "test", "echo BLOCKME"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(20));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("project:"), "{stdout}");
    assert!(stdout.contains("project rule"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn project_rule_fires_from_subdirectory_via_git_root() {
    let (dir, cfg) = temp_repo("subdir");
    write_project_rule(&dir);
    let sub = dir.join("deep").join("er");
    std::fs::create_dir_all(&sub).unwrap();
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&sub)
        .args(["policy", "test", "echo BLOCKME"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(20),
        "git-root file applies from subdirs"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn subdirectory_vallum_toml_cannot_shadow_git_root() {
    let (dir, cfg) = temp_repo("shadow");
    // NO file at the git root; a crafted one sits in a subdirectory.
    let sub = dir.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    write_project_rule(&sub);
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&sub)
        .args(["policy", "test", "echo BLOCKME"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "subdir file must be ignored");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn kill_switch_disables_project_config() {
    let (dir, cfg) = temp_repo("kill");
    write_project_rule(&dir);
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .env("VALLUM_NO_PROJECT_CONFIG", "1")
        .current_dir(&dir)
        .args(["policy", "test", "echo BLOCKME"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rejected_project_file_never_blocks_and_never_weakens() {
    let (dir, cfg) = temp_repo("rejected");
    // Forbidden key: tries to disable a built-in — the whole file is ignored.
    std::fs::write(
        dir.join(".vallum.toml"),
        "[policy]\ndisabled = [\"rm_rf_root\"]\n",
    )
    .unwrap();
    // 1. Never blocks: an ordinary command still runs (no DoS).
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["run", "echo", "hi"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("ignoring project config"),
        "the rejection must be loud"
    );
    // 2. Never weakens: the built-in the file tried to disable still fires.
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["policy", "test", "rm -rf /"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10), "rm_rf_root must still Ask");
    // 3. Doctor surfaces the rejection.
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["doctor"])
        .output()
        .unwrap();
    // Assert on the project-config LINE itself: a bare `contains("rejected")`
    // over the whole report can pass on unrelated output (foreign hook
    // commands in the hook-audit line, for one).
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("project-config"))
        .unwrap_or_else(|| panic!("no project-config check line in:\n{stdout}"));
    assert!(line.contains("rejected"), "{line}");
    assert!(line.contains(".vallum.toml"), "{line}");
    // The guardrail line must also see zero project rules (nothing accepted).
    assert!(
        stdout.contains("0 project rule(s)"),
        "rejected file contributes no rules: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn doctor_reports_an_accepted_project_file() {
    let (dir, cfg) = temp_repo("doctorok");
    write_project_rule(&dir);
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["doctor"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("project-config"))
        .unwrap_or_else(|| panic!("no project-config check line in:\n{stdout}"));
    assert!(line.contains("on —"), "{line}");
    assert!(line.contains("1 rule(s)"), "{line}");
    assert!(
        stdout.contains("1 project rule(s)"),
        "guardrail line must count it: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn project_rule_ask_is_never_approval_cached() {
    // Project rules are not in CACHE_ELIGIBLE_RULES (their names are
    // project:<pattern>), so an approved Ask must not mint a cache entry.
    let (dir, _cfg) = temp_repo("nocache");
    let mut cfg = vallum::config::AppConfig::default();
    cfg.audit.log_dir = Some(dir.clone());
    vallum::approvals::record(&cfg, "echo BLOCKME", "/repo", "project:echo BLOCKME");
    assert!(
        vallum::approvals::approvals_path(&cfg)
            .map(|p| !p.exists())
            .unwrap_or(true),
        "project-rule approvals must never be cached"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
