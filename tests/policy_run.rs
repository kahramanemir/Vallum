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
        "[[policy.rules]]\npattern = 'echo BLOCKME'\naction = \"deny\"\nreason = \"blocked in test\"\n",
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
        "[[policy.rules]]\npattern = 'echo ASKME'\naction = \"ask\"\nreason = \"ask in test\"\n",
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
