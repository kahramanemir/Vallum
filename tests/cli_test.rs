// tests/cli_test.rs
use std::process::Command;

#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("Failed to execute command");
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("vallum"));
    assert!(stdout.contains("run"));
}

#[test]
fn test_cli_help_lists_stats() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stats"));
}

#[test]
fn test_pipeline_strips_ansi_and_wraps_output() {
    // `\033` is the octal escape for ESC, accepted by both BSD and GNU printf.
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "printf",
            "\\033[31mError\\033[0m: bad\\n",
        ])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[UNTRUSTED TERMINAL OUTPUT START]"));
    assert!(stdout.contains("Error: bad"));
    assert!(!stdout.contains("\x1b["));
}
