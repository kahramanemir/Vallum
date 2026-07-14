//! End-to-end: the Claude hook mints a real approval token; running its
//! rewritten command through `vallum run` verifies and executes it, while a
//! hand-forged token on a dangerous command is re-gated and denied.

use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn temp_dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vallum_approval_e2e_{}_{}_{}",
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

fn config_for(dir: &Path) -> PathBuf {
    let cfg = dir.join("config.toml");
    std::fs::write(&cfg, format!("[audit]\nlog_dir = \"{}\"\n", dir.display())).unwrap();
    cfg
}

/// Run the Claude hook for `command`; return the rewritten command string
/// (updatedInput.command) from the hook's JSON output.
fn hook_rewrite(cfg: &Path, home: &Path, command: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vallum"))
        .arg("hook")
        .env("VALLUM_CONFIG", cfg)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn hook");
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command }
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("hook run");
    let v: Value = serde_json::from_slice(&out.stdout).expect("hook JSON");
    v["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .expect("rewritten command")
        .to_string()
}

#[test]
fn hook_minted_token_runs_forged_token_denied() {
    let dir = temp_dir("roundtrip");
    let cfg = config_for(&dir);

    // 1. Hook rewrites a benign command; the rewrite carries a valid token.
    let rewritten = hook_rewrite(&cfg, &dir, "echo approved-ok");
    assert!(
        rewritten.starts_with("vallum run --approval-token "),
        "rewrite: {rewritten}"
    );
    // The hook created the machine secret in the isolated dir.
    assert!(dir.join("approval.secret").exists());

    // 2. Executing the rewrite verifies the token and runs the command.
    //    Prepend the binary dir to PATH so the bare `vallum` in the rewrite
    //    resolves to the test binary.
    let bin = env!("CARGO_BIN_EXE_vallum");
    let bin_dir = Path::new(bin).parent().unwrap().to_str().unwrap();
    let path_env = format!("{bin_dir}:{}", std::env::var("PATH").unwrap_or_default());
    let out = Command::new("bash")
        .arg("-c")
        .arg(&rewritten)
        .env("VALLUM_CONFIG", &cfg)
        .env("HOME", &dir)
        .env("PATH", &path_env)
        .output()
        .expect("run rewrite");
    assert_eq!(
        out.status.code(),
        Some(0),
        "approved command must run; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("approved-ok"));

    // 3. A forged token on a dangerous command is re-gated (rm -rf / asks;
    //    non-interactive Ask fails closed → exit 125).
    let out = Command::new(bin)
        .args([
            "run",
            "--approval-token",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--",
            "bash",
            "-c",
            "rm -rf /",
        ])
        .env("VALLUM_CONFIG", &cfg)
        .env("VALLUM_ASSUME_YES", "0")
        .env("HOME", &dir)
        .output()
        .expect("forged run");
    assert_eq!(
        out.status.code(),
        Some(125),
        "forged token must be denied; stdout: {} stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
