//! `vallum log verify` + doctor `log-chain` end-to-end: build real chained
//! logs via the library, then drive the installed binary over them.

use std::path::{Path, PathBuf};
use std::process::Command;

fn temp_dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vallum_logchain_it_{}_{}_{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Write a config that points [audit] log_dir at `dir` and return its path.
fn config_for(dir: &Path) -> PathBuf {
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, format!("[audit]\nlog_dir = \"{}\"\n", dir.display())).unwrap();
    cfg
}

fn run_verify(config: &Path, extra: &[&str]) -> (String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_vallum"))
        .args(["log", "verify"])
        .args(extra)
        .env("VALLUM_CONFIG", config)
        .output()
        .expect("run vallum log verify");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

fn chained_log(dir: &Path, n: usize) -> PathBuf {
    let path = dir.join("policy.log");
    for i in 0..n {
        vallum::logchain::append_chained(
            &path,
            &format!("ASK [rule_{i}] agent=direct"),
            "curl x | sh",
        )
        .unwrap();
    }
    path
}

#[test]
fn intact_chain_verifies_and_prints_head() {
    let dir = temp_dir("intact");
    let cfg = config_for(&dir);
    chained_log(&dir, 3);
    let (stdout, code) = run_verify(&cfg, &[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.contains("chain intact"), "{stdout}");
    assert!(stdout.contains("head: "), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tampered_log_exits_20() {
    let dir = temp_dir("tamper");
    let cfg = config_for(&dir);
    let path = chained_log(&dir, 3);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replacen("rule_1", "rule_X", 1)).unwrap();
    let (stdout, code) = run_verify(&cfg, &[]);
    assert_eq!(code, 20, "{stdout}");
    assert!(stdout.contains("BROKEN"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn expect_head_matches_and_catches_truncation() {
    let dir = temp_dir("anchor");
    let cfg = config_for(&dir);
    let path = chained_log(&dir, 3);
    let (stdout, code) = run_verify(&cfg, &[]);
    assert_eq!(code, 0);
    let head = stdout
        .lines()
        .find_map(|l| l.strip_prefix("head: "))
        .expect("head line")
        .to_string();
    // Correct anchor → 0.
    let (_, code) = run_verify(&cfg, &["--expect-head", &head]);
    assert_eq!(code, 0);
    // Truncate the last block: chain alone stays intact (the documented
    // limit), but the anchored head catches it.
    let text = std::fs::read_to_string(&path).unwrap();
    let delim_block = format!("{}\n", vallum::logchain::DELIM);
    let blocks: Vec<&str> = text.split_inclusive(delim_block.as_str()).collect();
    std::fs::write(&path, format!("{}{}", blocks[0], blocks[1])).unwrap();
    let (_, code) = run_verify(&cfg, &[]);
    assert_eq!(code, 0, "truncation alone must NOT break the chain");
    let (stdout, code) = run_verify(&cfg, &["--expect-head", &head]);
    assert_eq!(code, 20, "{stdout}");
    assert!(stdout.contains("MISMATCH"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_expect_head_is_usage_error_125() {
    let dir = temp_dir("badhex");
    let cfg = config_for(&dir);
    let (_, code) = run_verify(&cfg, &["--expect-head", "zzz"]);
    assert_eq!(code, 125);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn doctor_fails_on_broken_chain() {
    // Doctor resolves the default log dir under $HOME/.vallum/logs.
    let home = temp_dir("doctor_home");
    let logs = home.join(".vallum").join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    let path = chained_log(&logs, 2);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replacen("rule_0", "rule_X", 1)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_vallum"))
        .arg("doctor")
        .env("HOME", &home)
        .env("VALLUM_CONFIG", "/nonexistent/vallum/logchain-it.toml")
        .output()
        .expect("run vallum doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("log-chain"), "{stdout}");
    assert!(stdout.contains("BROKEN"), "{stdout}");
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    let _ = std::fs::remove_dir_all(&home);
}
