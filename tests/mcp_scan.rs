//! Integration tests for `vallum mcp scan` driving the built binary.

use std::process::Command;

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(env!("CARGO_BIN_EXE_vallum"))
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
fn clean_config_exits_zero_no_findings() {
    let (stdout, _stderr, code) = run(&["mcp", "scan", "tests/fixtures/mcp/clean.json"]);
    assert_eq!(code, 0, "clean fixture must exit 0; stdout: {stdout}");
    assert!(stdout.contains("No issues found"));
}

#[test]
fn risky_command_config_exits_ten() {
    // Built-in guardrail rules are all `Ask`, so a `curl | sh` launch command
    // is a Warning finding → exit 10 (verified: `policy test` returns ASK).
    let (_stdout, _stderr, code) = run(&["mcp", "scan", "tests/fixtures/mcp/risky_command.json"]);
    assert_eq!(
        code, 10,
        "curl|sh launch command is an Ask → warning finding"
    );
}

#[test]
fn injection_config_exits_ten() {
    let (_stdout, _stderr, code) = run(&["mcp", "scan", "tests/fixtures/mcp/injection.json"]);
    assert_eq!(
        code, 10,
        "description injection should be a warning finding"
    );
}

#[test]
fn missing_explicit_path_exits_125() {
    let (_stdout, stderr, code) = run(&["mcp", "scan", "/nonexistent/mcp.json"]);
    assert_eq!(code, 125);
    assert!(stderr.contains("no such file"));
}

#[test]
fn json_output_has_expected_shape() {
    let (stdout, _stderr, _code) =
        run(&["mcp", "scan", "--json", "tests/fixtures/mcp/injection.json"]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(v.get("files_scanned").is_some());
    assert!(v.get("findings").is_some());
    assert!(v.get("summary").is_some());
    assert_eq!(v["findings"][0]["check"], "description_injection");
}
