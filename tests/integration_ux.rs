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

#[test]
fn config_show_prints_valid_toml_roundtrip() {
    let bin = env!("CARGO_BIN_EXE_vallum");
    let output = std::process::Command::new(bin)
        .args(["config", "show"])
        .env("VALLUM_CONFIG", "/nonexistent/vallum/config.toml")
        .output()
        .expect("run vallum config show");
    assert!(output.status.success(), "exited {:?}", output.status.code());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[audit]"), "got: {stdout}");
    assert!(stdout.contains("[pipeline]"), "got: {stdout}");
    assert!(stdout.contains("[scrubber]"), "got: {stdout}");
    assert!(stdout.contains("[security]"), "got: {stdout}");
    assert!(stdout.contains("[optimizer]"), "got: {stdout}");
    let parsed: toml::Value = toml::from_str(&stdout).expect("output must be valid TOML");
    assert!(parsed.get("pipeline").is_some());
}

#[test]
fn config_init_creates_default_file() {
    let dir = std::env::temp_dir().join(format!(
        "vallum_config_init_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    let bin = env!("CARGO_BIN_EXE_vallum");
    let output = std::process::Command::new(bin)
        .args(["config", "init"])
        .env("VALLUM_CONFIG", &cfg)
        .output()
        .expect("run vallum config init");
    assert!(output.status.success());
    let written = std::fs::read_to_string(&cfg).unwrap();
    assert!(written.contains("[pipeline]"));
    assert!(written.contains("max_line_length"));
    // Second invocation without --force should NOT overwrite.
    let again = std::process::Command::new(bin)
        .args(["config", "init"])
        .env("VALLUM_CONFIG", &cfg)
        .output()
        .unwrap();
    assert!(again.status.success());
    let stdout = String::from_utf8_lossy(&again.stdout);
    assert!(stdout.contains("already exists"), "got: {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn completions_emits_a_zsh_script() {
    let bin = env!("CARGO_BIN_EXE_vallum");
    let output = std::process::Command::new(bin)
        .args(["completions", "zsh"])
        .output()
        .expect("run vallum completions zsh");
    assert!(output.status.success(), "exited {:?}", output.status.code());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "completion script should be non-empty");
    assert!(stdout.contains("vallum"), "completion script should reference the binary name");
}

#[test]
fn completions_emits_a_bash_script() {
    let bin = env!("CARGO_BIN_EXE_vallum");
    let output = std::process::Command::new(bin)
        .args(["completions", "bash"])
        .output()
        .expect("run vallum completions bash");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty());
    assert!(stdout.contains("vallum"));
}
