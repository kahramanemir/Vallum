// tests/policy_run.rs — direct `vallum run` is gated by the guardrail.
use std::process::Command;

fn vallum_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vallum")
}

#[test]
fn deny_rule_blocks_direct_run_with_exit_125() {
    // A user deny rule via a temp config; VALLUM_CONFIG points at it.
    let dir = std::env::temp_dir().join(format!("vallum_polrun_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "[audit]\nlog_dir = \"{}\"\n[[policy.rules]]\npattern = 'echo BLOCKME'\naction = \"deny\"\nreason = \"blocked in test\"\n",
            dir.display()
        ),
    )
    .unwrap();

    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .env("VALLUM_ASSUME_YES", "0")
        .args(["run", "echo", "BLOCKME"])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(125),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("blocked in test"));
}

#[test]
fn assume_yes_lets_ask_proceed() {
    let dir = std::env::temp_dir().join(format!("vallum_polrun2_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "[audit]\nlog_dir = \"{}\"\n[[policy.rules]]\npattern = 'echo ASKME'\naction = \"ask\"\nreason = \"ask in test\"\n",
            dir.display()
        ),
    )
    .unwrap();

    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .env("VALLUM_ASSUME_YES", "1")
        .args(["run", "echo", "ASKME"])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("ASKME"));
}

// The hook enforces policy once, then re-wraps the approved command through
// `vallum run --approval-token <hmac> -- bash -c '<original>'`. That inner run
// must NOT re-gate the approved command — otherwise it would fail closed
// (no tty) and never run. A VALID token for the exact command line proves
// approval and lets it through even against a matching Deny rule.
#[test]
fn valid_token_bypasses_regate_on_wrapped_command() {
    let dir = std::env::temp_dir().join(format!("vallum_polrun3_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "[audit]\nlog_dir = \"{}\"\n[[policy.rules]]\npattern = 'echo BLOCKME'\naction = \"deny\"\nreason = \"blocked in test\"\n",
            dir.display()
        ),
    )
    .unwrap();
    // Same secret the hook would have created, in the same resolved location.
    let secret = b"polrun-secret-key-exactly-32-byt".to_vec();
    std::fs::write(dir.join("approval.secret"), &secret).unwrap();
    let token = vallum::approval::token_for("bash -c echo BLOCKME", &secret);

    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .env("VALLUM_ASSUME_YES", "0")
        .args([
            "run",
            "--approval-token",
            &token,
            "--",
            "bash",
            "-c",
            "echo BLOCKME",
        ])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "approved command must run, not block; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("BLOCKME"));
    let _ = std::fs::remove_dir_all(&dir);
}

// A forged token (agent self-asserting a bypass) does NOT match the machine
// secret, so the command is re-gated and the Deny rule blocks it (exit 125).
#[test]
fn forged_token_is_regated_and_denied() {
    let dir = std::env::temp_dir().join(format!("vallum_polrun4_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "[audit]\nlog_dir = \"{}\"\n[[policy.rules]]\npattern = 'echo BLOCKME'\naction = \"deny\"\nreason = \"blocked in test\"\n",
            dir.display()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("approval.secret"),
        b"real-secret-key-exactly-32-bytes",
    )
    .unwrap();

    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .env("VALLUM_ASSUME_YES", "0")
        .args([
            "run",
            "--approval-token",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "--",
            "bash",
            "-c",
            "echo BLOCKME",
        ])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(125),
        "forged token must be re-gated and denied; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("blocked in test"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn policy_test_reports_ask_with_exit_10() {
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", "/nonexistent/vallum/config.toml")
        .args(["policy", "test", "rm -rf /"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("ASK [rm_rf_root] (built-in)"),
        "{stdout}"
    );
}

#[test]
fn policy_test_reports_allow_with_exit_0() {
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", "/nonexistent/vallum/config.toml")
        .args(["policy", "test", "git status"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ALLOW"));
}

#[test]
fn policy_test_user_deny_rule_exit_20_and_broken_config_125() {
    let dir = std::env::temp_dir().join(format!("vallum_poltest_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        "[[policy.rules]]\npattern = 'echo BLOCKME'\naction = \"deny\"\nreason = \"blocked in test\"\n",
    )
    .unwrap();

    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .args(["policy", "test", "echo BLOCKME"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(20));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DENY ["), "{stdout}");
    assert!(stdout.contains("(user rule)"), "{stdout}");
    assert!(stdout.contains("blocked in test"), "{stdout}");

    let broken = dir.join("broken.toml");
    std::fs::write(&broken, "[[policy.rules]\n").unwrap();
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &broken)
        .args(["policy", "test", "ls"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn policy_test_tui_command_matching_rule_asks() {
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", "/nonexistent/vallum/config.toml")
        .args(["policy", "test", "less /etc/shadow"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&out.stdout).contains("read_sensitive_creds"));
}

#[test]
fn tty_less_run_records_nothing_but_assume_yes_does_not_cache() {
    // assume-yes proceeds must NOT create cache entries: a blanket flag is
    // not a per-command human decision.
    let dir = std::env::temp_dir().join(format!("vallum_polrun_nocache_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, format!("[audit]\nlog_dir = \"{}\"\n", dir.display())).unwrap();
    let out = std::process::Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .env("VALLUM_ASSUME_YES", "1")
        .args(["run", "--", "git", "clean", "-fdn"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "assume-yes proceeds; dry-run is harmless"
    );
    assert!(
        !dir.join("approvals.jsonl").exists(),
        "assume-yes proceed must not mint a cache entry"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cached_approval_lets_direct_run_proceed_without_tty() {
    // Seed a valid entry via the library, then a non-TTY `vallum run` of the
    // identical command in the same cwd proceeds instead of failing closed.
    let dir = std::env::temp_dir().join(format!("vallum_polrun_cache_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        format!("[audit]\nlog_dir = \"{}\"\n", dir.display()),
    )
    .unwrap();
    let mut cfg = vallum::config::AppConfig::default();
    cfg.audit.log_dir = Some(dir.clone());
    let cwd = std::env::current_dir().unwrap().display().to_string();
    // `git clean -fdn` fires git_clean_force (eligible) but is a dry-run.
    vallum::approvals::record(&cfg, "git clean -fdn", &cwd, "git_clean_force");
    let out = std::process::Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg_path)
        .env("VALLUM_ASSUME_YES", "0")
        .args(["run", "--", "git", "clean", "-fdn"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "cache hit must proceed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Without the entry the same invocation fails closed (no TTY);
    // blocked commands exit 125 (see `emit_block` in src/main.rs).
    vallum::approvals::clear(&cfg).unwrap();
    let out = std::process::Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg_path)
        .env("VALLUM_ASSUME_YES", "0")
        .args(["run", "--", "git", "clean", "-fdn"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125), "no cache, no TTY → blocked");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn token_approved_run_records_eligible_command() {
    // A hook-shaped `vallum run --approval-token … -- bash -c '<cmd>'` with a
    // valid token writes a cache entry for the inner command.
    let dir = std::env::temp_dir().join(format!("vallum_polrun_mint_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        format!("[audit]\nlog_dir = \"{}\"\n", dir.display()),
    )
    .unwrap();
    let mut cfg = vallum::config::AppConfig::default();
    cfg.audit.log_dir = Some(dir.clone());
    let secret = vallum::approval::load_or_create_secret(&cfg).unwrap();
    let inner = "git clean -fdn";
    let token = vallum::approval::token_for(&format!("bash -c {inner}"), &secret);
    let out = std::process::Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg_path)
        .args(["run", "--approval-token", &token, "--", "bash", "-c", inner])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cwd = std::env::current_dir().unwrap().display().to_string();
    assert!(
        vallum::approvals::lookup(&cfg, inner, &cwd, "git_clean_force"),
        "token-approved eligible command must be cached"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn approvals_list_and_clear_cli() {
    let dir = std::env::temp_dir().join(format!("vallum_approvals_cli_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        format!("[audit]\nlog_dir = \"{}\"\n", dir.display()),
    )
    .unwrap();
    let mut cfg = vallum::config::AppConfig::default();
    cfg.audit.log_dir = Some(dir.clone());
    vallum::approvals::record(&cfg, "git push --force", "/repo", "git_push_force");

    let out = std::process::Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg_path)
        .args(["approvals", "list"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("git_push_force"), "{stdout}");
    assert!(stdout.contains("git push --force"), "{stdout}");

    let out = std::process::Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg_path)
        .args(["approvals", "clear"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("removed 1"),
        "clear reports count"
    );

    let out = std::process::Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg_path)
        .args(["approvals", "list"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("no cached approvals"));
    let _ = std::fs::remove_dir_all(&dir);
}
