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
