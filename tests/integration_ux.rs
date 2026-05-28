// tests/integration_ux.rs — end-to-end tests for sub-project C.

#[test]
fn proxy_failure_exits_125() {
    let bin = env!("CARGO_BIN_EXE_vallum");
    let output = std::process::Command::new(bin)
        .args(["run", "/nonexistent-vallum-test-binary-zzz"])
        .env("VALLUM_CONFIG", "/nonexistent/vallum/config.toml")
        .output()
        .expect("run vallum");
    assert_eq!(output.status.code(), Some(125), "expected exit 125, got {:?}", output.status.code());
}

#[test]
fn hook_rewrites_bash_command() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let bin = env!("CARGO_BIN_EXE_vallum");
    let mut child = Command::new(bin)
        .arg("hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn vallum hook");

    let stdin_input = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    child.stdin.as_mut().unwrap().write_all(stdin_input.as_bytes()).unwrap();
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success(), "hook exited non-zero");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"hookEventName\":\"PreToolUse\""), "got: {stdout}");
    assert!(stdout.contains("\"permissionDecision\":\"allow\""), "got: {stdout}");
    assert!(stdout.contains("vallum run -- bash -c 'git status'"), "got: {stdout}");
}

#[test]
fn hook_silently_allows_non_bash_tool() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let bin = env!("CARGO_BIN_EXE_vallum");
    let mut child = Command::new(bin)
        .arg("hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn vallum hook");

    let stdin_input = r#"{"tool_name":"Edit","tool_input":{}}"#;
    child.stdin.as_mut().unwrap().write_all(stdin_input.as_bytes()).unwrap();
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.is_empty(), "expected empty stdout, got: {stdout}");
}
