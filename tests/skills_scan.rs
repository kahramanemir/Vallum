//! Integration tests for `vallum skills scan` driving the built binary.

use std::fs;
use std::process::Command;

/// Pin the config to a path that does not exist so the scan runs against
/// AppConfig::default() (guardrail on, no extra patterns) regardless of any
/// ~/.vallum/config.toml on the host. Matches the isolation used in
/// tests/mcp_scan.rs. Returns (stdout, stderr, exit_code).
fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_vallum"))
        .env(
            "VALLUM_CONFIG",
            "/nonexistent/vallum/skills-scan-test-config.toml",
        )
        .args(args)
        .output()
        .expect("run vallum");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn malicious_skill_exits_20_with_combined_signature() {
    let (stdout, _e, code) = run(&[
        "skills",
        "scan",
        "--json",
        "tests/fixtures/skills/malicious/SKILL.md",
    ]);
    assert_eq!(code, 20, "malicious fixture must exit 20; stdout: {stdout}");
    assert!(stdout.contains("combined_signature"));
}

#[test]
fn clean_skill_exits_0() {
    let (_o, _e, code) = run(&["skills", "scan", "tests/fixtures/skills/clean/SKILL.md"]);
    assert_eq!(code, 0);
}

#[test]
fn invisible_unicode_is_detected() {
    let dir = std::env::temp_dir().join(format!(
        "vallum_skills_it_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(dir.join("s")).unwrap();
    let f = dir.join("s").join("SKILL.md");
    fs::write(&f, "Read the file\u{200b} then continue.\n").unwrap();
    let (stdout, _e, code) = run(&["skills", "scan", "--json", f.to_str().unwrap()]);
    assert_eq!(
        code, 10,
        "invisible-unicode fixture must exit 10; stdout: {stdout}"
    );
    assert!(stdout.contains("invisible_unicode"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn missing_explicit_path_exits_125() {
    let (_o, _e, code) = run(&["skills", "scan", "/no/such/path-xyz.md"]);
    assert_eq!(code, 125);
}

#[test]
fn clean_repo_docs_scan_clean() {
    // Precision guard: genuinely-clean repo docs must not trip the scanner.
    // NOTE: README.md is deliberately NOT used here — it documents the
    // `curl … | installer.sh | sh` install command, which the guardrail
    // *correctly* flags (Ask). CONTRIBUTING.md and LICENSE-MIT contain no
    // risky commands, secrets, or injection phrasing.
    let (stdout, _e, code) = run(&["skills", "scan", "CONTRIBUTING.md", "LICENSE-MIT"]);
    assert_eq!(code, 0, "clean repo docs must scan clean; stdout: {stdout}");
}

#[test]
fn readme_attack_examples_are_flagged() {
    // Documents correct behavior on a hard input: Vallum's own README quotes
    // the attacks it defends against — injection example phrases in prose AND
    // dangerous commands (curl|sh, rm -rf /, fork bomb, …) in fenced code.
    // That is byte-for-byte the ToxicSkills signature (injection + risky
    // command in one document), so the scanner reports the composite High
    // finding and exits 20. Security *documentation* is indistinguishable from
    // a malicious skill to a static scanner; SECURITY.md discloses this.
    let (stdout, _e, code) = run(&["skills", "scan", "--json", "README.md"]);
    assert_eq!(
        code, 20,
        "README quotes injection + risky commands → composite High; stdout: {stdout}"
    );
    assert!(stdout.contains("combined_signature"));
}
