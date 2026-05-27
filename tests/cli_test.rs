// tests/cli_test.rs
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_cli_help() {
    let output = Command::new(vallum_bin())
        .arg("--help")
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vallum"));
    assert!(stdout.contains("run"));
}

#[test]
fn test_cli_help_lists_stats() {
    let output = std::process::Command::new(vallum_bin())
        .arg("--help")
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stats"));
}

#[test]
fn test_cli_version_matches_cargo() {
    let output = Command::new(vallum_bin())
        .arg("--version")
        .output()
        .expect("Failed to execute command");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_pipeline_strips_ansi_and_wraps_output() {
    // `\033` is the octal escape for ESC, accepted by both BSD and GNU printf.
    let output = std::process::Command::new(vallum_bin())
        .args(["run", "printf", "\\033[31mError\\033[0m: bad\\n"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[UNTRUSTED TERMINAL OUTPUT START]"));
    assert!(stdout.contains("Error: bad"));
    assert!(!stdout.contains("\x1b["));
}

#[test]
fn test_run_propagates_child_exit_code() {
    let output = Command::new(vallum_bin())
        .args(["run", "sh", "--", "-c", "exit 7"])
        .output()
        .expect("Failed to execute command");

    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn test_run_json_outputs_structured_response() {
    let output = Command::new(vallum_bin())
        .args(["run", "--json", "printf", "hello\\n"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: Value = serde_json::from_str(&stdout).expect("stdout should be valid json");

    assert_eq!(payload["command"], "printf");
    assert_eq!(payload["exit_code"], 0);
    assert_eq!(payload["optimizer"], Value::Null);
    assert!(payload["tokens_before"].as_u64().unwrap() > 0);
    assert!(payload["tokens_after"].as_u64().unwrap() > 0);
    assert!(payload["sanitized_output"]
        .as_str()
        .unwrap()
        .contains("hello"));
    assert!(payload["sanitized_output"]
        .as_str()
        .unwrap()
        .contains("[UNTRUSTED TERMINAL OUTPUT START]"));
}

#[test]
fn test_run_honors_configured_truncation() {
    let fixture_dir = make_temp_fixture_dir("truncate");
    let config_path = fixture_dir.join("config.toml");
    fs::write(
        &config_path,
        r#"
[pipeline]
head_lines = 1
tail_lines = 1
min_optimize_tokens = 0

[audit]
raw_enabled = false
sanitized_enabled = false
"#,
    )
    .unwrap();

    let output = Command::new(vallum_bin())
        .args(["run", "printf", "line1\\nline2\\nline3\\nline4\\nline5\\n"])
        .env("VALLUM_CONFIG", &config_path)
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("line1"));
    assert!(stdout.contains("line5"));
    assert!(stdout.contains("lines hidden"));
    assert!(!stdout.contains("line3"));
    let _ = fs::remove_dir_all(&fixture_dir);
}

#[test]
fn test_run_honors_custom_log_dir_and_extra_secret_patterns() {
    let fixture_dir = make_temp_fixture_dir("logs");
    let log_dir = fixture_dir.join("logs");
    let config_path = fixture_dir.join("config.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[audit]
log_dir = "{}"
raw_enabled = false
sanitized_enabled = true

[scrubber]
extra_secret_patterns = [{{ pattern = "token-[0-9]+", replacement = "token-***" }}]
"#,
            log_dir.display()
        ),
    )
    .unwrap();

    let output = Command::new(vallum_bin())
        .args(["run", "printf", "token-12345\\n"])
        .env("VALLUM_CONFIG", &config_path)
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("token-***"));
    assert!(!stdout.contains("token-12345"));
    assert!(log_dir.join("sanitized.ai.log").exists());
    assert!(!log_dir.join("raw.local.log").exists());
    let _ = fs::remove_dir_all(&fixture_dir);
}

fn make_temp_fixture_dir(name: &str) -> std::path::PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("vallum_cli_test_{}_{}", name, suffix));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn vallum_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vallum"))
}
