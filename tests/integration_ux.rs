// tests/integration_ux.rs — end-to-end tests for sub-project C.

#[test]
fn proxy_failure_exits_125() {
    let bin = env!("CARGO_BIN_EXE_vallum");
    let output = std::process::Command::new(bin)
        .args(["run", "/nonexistent-vallum-test-binary-zzz"])
        .env("VALLUM_CONFIG", "/nonexistent/vallum/config.toml")
        .output()
        .expect("run vallum");
    assert_eq!(
        output.status.code(),
        Some(125),
        "expected exit 125, got {:?}",
        output.status.code()
    );
}

#[test]
fn hook_rewrites_bash_command() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Isolate: the hook now mints a machine approval secret; keep it (and any
    // logs) out of the developer's real ~/.vallum via a temp HOME + log_dir.
    let dir = std::env::temp_dir().join(format!(
        "vallum_hook_rewrite_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, format!("[audit]\nlog_dir = \"{}\"\n", dir.display())).unwrap();

    let bin = env!("CARGO_BIN_EXE_vallum");
    let mut child = Command::new(bin)
        .arg("hook")
        .env("VALLUM_CONFIG", &cfg)
        .env("HOME", &dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn vallum hook");

    let stdin_input = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_input.as_bytes())
        .unwrap();
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success(), "hook exited non-zero");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"hookEventName\":\"PreToolUse\""),
        "got: {stdout}"
    );
    assert!(
        stdout.contains("\"permissionDecision\":\"allow\""),
        "got: {stdout}"
    );
    // The approved command is re-wrapped through `vallum run` carrying a
    // per-command HMAC approval token (not the old forgeable --policy-approved).
    assert!(
        stdout.contains("vallum run --approval-token "),
        "got: {stdout}"
    );
    assert!(stdout.contains(" -- bash -c 'git status'"), "got: {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hook_broken_config_warns_and_keeps_builtin_guardrail() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let dir = std::env::temp_dir().join(format!(
        "vallum_hook_brokencfg_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    // Missing closing quote: parse error. The user's deny rules are lost, but
    // the hook must not fail open — built-ins still gate, and stderr says why.
    std::fs::write(
        &cfg,
        "[[policy.rules]]\npattern = 'kubectl delete\naction = \"deny\"\nreason = \"no\"\n",
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_vallum");
    let mut child = Command::new(bin)
        .arg("hook")
        .env("VALLUM_CONFIG", &cfg)
        // Isolate ~/.vallum (breaker.state) to the temp dir: the built-in
        // fallback records the Ask verdict and must not touch the real home.
        .env("HOME", &dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vallum hook");

    let stdin_input = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_input.as_bytes())
        .unwrap();
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success(), "hook exited non-zero");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "broken config must fall back to built-ins (ask), not allow; got: {stdout}"
    );
    assert!(
        stderr.contains("config"),
        "stderr must explain the config fallback; got: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hook_silently_allows_non_bash_tool() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Isolate: `vallum hook` mints the approval secret on startup regardless of
    // tool; redirect HOME + log_dir so it never lands in the real ~/.vallum.
    let dir = std::env::temp_dir().join(format!(
        "vallum_hook_nonbash_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, format!("[audit]\nlog_dir = \"{}\"\n", dir.display())).unwrap();

    let bin = env!("CARGO_BIN_EXE_vallum");
    let mut child = Command::new(bin)
        .arg("hook")
        .env("VALLUM_CONFIG", &cfg)
        .env("HOME", &dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn vallum hook");

    let stdin_input = r#"{"tool_name":"Edit","tool_input":{}}"#;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_input.as_bytes())
        .unwrap();
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.is_empty(), "expected empty stdout, got: {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
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
    assert!(
        stdout.contains("vallum"),
        "completion script should reference the binary name"
    );
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

#[test]
fn hook_cursor_ask_emits_native_ask_json() {
    use std::io::Write as _;
    let home = std::env::temp_dir().join(format!(
        "vallum_cursor_hook_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_vallum"))
        .arg("hook")
        .arg("--agent")
        .arg("cursor")
        .env("VALLUM_CONFIG", "/nonexistent/vallum/config.toml")
        .env("HOME", &home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn vallum hook");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"command":"rm -rf /","hook_event_name":"beforeShellExecution"}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "hook exited non-zero");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"permission\":\"ask\""), "got: {stdout}");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn hook_tui_ask_emits_no_updated_input() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Temp config: default policy, but sanitized audit log off so the test
    // does not append to the developer's real ~/.vallum/logs. HOME is also
    // redirected here so the breaker's Ask recording stays isolated too.
    let dir = std::env::temp_dir().join(format!("vallum_tui_ask_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, "[audit]\nsanitized_enabled = false\n").unwrap();

    let bin = env!("CARGO_BIN_EXE_vallum");
    let mut child = Command::new(bin)
        .arg("hook")
        .env("VALLUM_CONFIG", &cfg)
        .env("HOME", &dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn vallum hook");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"less /etc/shadow"}}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));

    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("hook must emit JSON for an Ask");
    let hso = &v["hookSpecificOutput"];
    assert_eq!(hso["permissionDecision"], "ask");
    assert!(
        hso.get("updatedInput").is_none(),
        "TUI ask must not carry a rewrite: {v}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
