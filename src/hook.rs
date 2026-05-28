// src/hook.rs — Claude Code PreToolUse hook implementation.
use serde::Deserialize;
use serde::Serialize;
use std::io::Read;

#[derive(Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: HookToolInput,
}

#[derive(Deserialize, Default)]
struct HookToolInput {
    #[serde(default)]
    command: String,
}

#[derive(Serialize)]
struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: HookSpecificOutput,
}

#[derive(Serialize)]
struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'static str,
    #[serde(rename = "updatedInput")]
    updated_input: UpdatedInput,
}

#[derive(Serialize)]
struct UpdatedInput {
    command: String,
}

/// First-word skip list. Commands whose head matches one of these are passed
/// through unchanged because Vallum's executor captures stdout and would break
/// the interactive TTY they need.
const TUI_SKIP: &[&str] = &[
    "vim", "vi", "nano", "less", "more", "top", "htop", "tmux", "screen",
];

/// Decide whether to rewrite. Returns the new command, or `None` to allow the
/// normal Claude Code permission flow.
pub fn rewrite_decision(tool_name: &str, command: &str) -> Option<String> {
    if tool_name != "Bash" {
        return None;
    }
    let trimmed = command.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let head = trimmed.split_whitespace().next().unwrap_or("");
    if TUI_SKIP.iter().any(|t| *t == head) {
        return None;
    }
    if head == "vallum" {
        return None;
    }
    Some(format!("vallum run -- bash -c {}", shell_escape(command)))
}

/// POSIX-safe single-quote shell escaping.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Entry point invoked from main: read stdin JSON, decide, write stdout JSON,
/// return the exit code (always 0 — even malformed input is silently allowed).
pub fn run() -> i32 {
    let mut buf = String::new();
    if std::io::stdin().lock().read_to_string(&mut buf).is_err() {
        return 0;
    }
    let input: HookInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(_) => return 0, // malformed input: allow normal flow
    };
    let Some(new_cmd) = rewrite_decision(&input.tool_name, &input.tool_input.command) else {
        return 0;
    };
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: "allow",
            updated_input: UpdatedInput { command: new_cmd },
        },
    };
    if let Ok(s) = serde_json::to_string(&output) {
        println!("{}", s);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_plain_bash_command() {
        let out = rewrite_decision("Bash", "git status").unwrap();
        assert_eq!(out, "vallum run -- bash -c 'git status'");
    }

    #[test]
    fn wraps_full_pipeline_via_bash_c() {
        let out = rewrite_decision("Bash", "git status | head").unwrap();
        assert_eq!(out, "vallum run -- bash -c 'git status | head'");
    }

    #[test]
    fn escapes_single_quotes() {
        let out = rewrite_decision("Bash", "echo 'hi there'").unwrap();
        assert_eq!(out, r#"vallum run -- bash -c 'echo '\''hi there'\'''"#);
    }

    #[test]
    fn skips_tui_head() {
        assert!(rewrite_decision("Bash", "vim foo.txt").is_none());
        assert!(rewrite_decision("Bash", "  less log.txt").is_none());
        assert!(rewrite_decision("Bash", "tmux attach").is_none());
    }

    #[test]
    fn skips_already_vallum() {
        assert!(rewrite_decision("Bash", "vallum run echo hi").is_none());
    }

    #[test]
    fn skips_non_bash_tool() {
        assert!(rewrite_decision("Edit", "git status").is_none());
        assert!(rewrite_decision("", "git status").is_none());
    }

    #[test]
    fn skips_empty_command() {
        assert!(rewrite_decision("Bash", "").is_none());
        assert!(rewrite_decision("Bash", "   ").is_none());
    }
}
