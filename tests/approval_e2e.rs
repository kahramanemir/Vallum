//! End-to-end: the Claude hook mints a real approval token; running its
//! rewritten command through `vallum run` verifies and executes it (bypassing
//! a rule that would otherwise fail closed), while a hand-forged token on a
//! Deny-matched command is re-gated and denied with the rule's reason.

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

/// Isolated config with two user rules: an Ask on the positive-leg command
/// (so that WITHOUT a honored token the re-gated run fails closed) and a Deny
/// on the negative-leg command (so a forged token surfaces the deny reason).
fn config_for(dir: &Path) -> PathBuf {
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "[audit]\nlog_dir = \"{}\"\n\
             [[policy.rules]]\npattern = 'echo need-approval'\naction = \"ask\"\nreason = \"ask in e2e\"\n\
             [[policy.rules]]\npattern = 'echo FORBIDDEN'\naction = \"deny\"\nreason = \"denied in e2e\"\n",
            dir.display()
        ),
    )
    .unwrap();
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

    // 1. The hook evaluates `echo need-approval` (an Ask rule), and on the
    //    approval path re-wraps it carrying a real token minted with the
    //    machine secret it just created.
    let rewritten = hook_rewrite(&cfg, &dir, "echo need-approval");
    assert!(
        rewritten.starts_with("vallum run --approval-token "),
        "rewrite: {rewritten}"
    );
    assert!(
        dir.join("approval.secret").exists(),
        "hook minted the secret"
    );

    // 2. Executing that rewrite must RUN (exit 0): the token is honored so the
    //    inner `vallum run` skips re-gating. This is non-vacuous — without a
    //    honored token the Ask rule would re-fire non-interactively and fail
    //    closed (125), so exit 0 proves the hook-minted token was accepted.
    //    Prepend the binary dir to PATH so the bare `vallum` resolves to the
    //    test binary.
    let bin = env!("CARGO_BIN_EXE_vallum");
    let bin_dir = Path::new(bin).parent().unwrap().to_str().unwrap();
    let path_env = format!("{bin_dir}:{}", std::env::var("PATH").unwrap_or_default());
    let out = Command::new("bash")
        .arg("-c")
        .arg(&rewritten)
        .env("VALLUM_CONFIG", &cfg)
        .env("VALLUM_ASSUME_YES", "0")
        .env("HOME", &dir)
        .env("PATH", &path_env)
        .output()
        .expect("run rewrite");
    assert_eq!(
        out.status.code(),
        Some(0),
        "honored token must run past the Ask rule; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("need-approval"));

    // 3. A forged token on a Deny-matched command is re-gated and blocked with
    //    the rule's reason (exit 125). Using a harmless `echo FORBIDDEN` rather
    //    than a real destructive command keeps the negative leg safe even if the
    //    security property regresses and the token is wrongly accepted.
    let out = Command::new(bin)
        .args([
            "run",
            "--approval-token",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--",
            "bash",
            "-c",
            "echo FORBIDDEN",
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
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("denied in e2e"),
        "125 must come from the deny rule, not an incidental error; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn honored_token_is_still_blocked_while_breaker_is_tripped() {
    let dir = temp_dir("breaker_trip");
    let cfg = config_for(&dir);

    // A real hook-minted token for the Ask-matched command.
    let rewritten = hook_rewrite(&cfg, &dir, "echo need-approval");
    assert!(
        rewritten.starts_with("vallum run --approval-token "),
        "rewrite: {rewritten}"
    );

    // Trip the breaker AFTER the token was minted — the emergency lockdown
    // must beat a token issued moments earlier.
    std::fs::write(
        dir.join("breaker.state"),
        "locked 2999-01-01T00:00:00+00:00\n",
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_vallum");
    let bin_dir = Path::new(bin).parent().unwrap().to_str().unwrap();
    let path_env = format!("{bin_dir}:{}", std::env::var("PATH").unwrap_or_default());
    let out = Command::new("bash")
        .arg("-c")
        .arg(&rewritten)
        .env("VALLUM_CONFIG", &cfg)
        .env("VALLUM_ASSUME_YES", "0")
        .env("HOME", &dir)
        .env("PATH", &path_env)
        .output()
        .expect("run rewrite while tripped");
    assert_eq!(
        out.status.code(),
        Some(125),
        "tripped breaker must block even a valid token; stdout: {} stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("circuit breaker"),
        "block must come from the breaker; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
