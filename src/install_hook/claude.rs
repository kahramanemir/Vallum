//! Claude Code installer: merges a `PreToolUse` entry into settings.json.

use super::Level;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Resolve the settings.json path for the given level.
pub fn settings_path(level: Level) -> Result<PathBuf, String> {
    match level {
        Level::User => {
            let home = dirs::home_dir().ok_or("could not determine home directory")?;
            Ok(home.join(".claude").join("settings.json"))
        }
        Level::Project => {
            let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
            Ok(cwd.join(".claude").join("settings.json"))
        }
    }
}

/// Return true if `settings` already has a Vallum hook entry.
pub fn has_vallum_hook(settings: &Value) -> bool {
    settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().any(entry_is_vallum))
        .unwrap_or(false)
}

fn entry_is_vallum(entry: &Value) -> bool {
    let Some(hooks) = entry.get("hooks").and_then(|h| h.as_array()) else {
        return false;
    };
    hooks.iter().any(|h| {
        h.get("command")
            .and_then(|c| c.as_str())
            .map(|s| s.contains("vallum hook"))
            .unwrap_or(false)
    })
}

/// Tool-name matcher for the PreToolUse entry: Bash plus the native file
/// tools gated by `file_decision`. Regex-alternation per Claude Code's
/// matcher semantics.
pub(crate) const MATCHER: &str = "Bash|Write|Edit|MultiEdit|NotebookEdit|Read";

/// The exact JSON entry we add to hooks.PreToolUse.
fn vallum_entry() -> Value {
    json!({
        "matcher": MATCHER,
        "hooks": [
            { "type": "command", "command": "vallum hook" }
        ]
    })
}

/// True when a Vallum entry exists AND already carries the current matcher.
pub fn vallum_matcher_current(settings: &Value) -> bool {
    settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter().any(|e| {
                entry_is_vallum(e) && e.get("matcher").and_then(|m| m.as_str()) == Some(MATCHER)
            })
        })
        .unwrap_or(false)
}

/// Add the Vallum entry. If `force`, replace existing Vallum entries. Without
/// `force`, no-op when a current entry is present, but migrate (replace) an
/// entry whose matcher is outdated.
pub fn add_vallum(settings: &mut Value, force: bool) -> Result<bool, String> {
    if has_vallum_hook(settings) {
        if !force && vallum_matcher_current(settings) {
            return Ok(false);
        }
        // Outdated matcher (or force): migrate by replace.
        remove_vallum(settings);
    }
    let hooks = settings
        .as_object_mut()
        .ok_or_else(|| "settings root is not a JSON object".to_string())?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let pre = hooks
        .as_object_mut()
        .ok_or_else(|| "the \"hooks\" key is not a JSON object".to_string())?
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    let arr = pre
        .as_array_mut()
        .ok_or_else(|| "hooks.PreToolUse is not a JSON array".to_string())?;
    arr.push(vallum_entry());
    Ok(true)
}

/// Remove every entry whose hooks[].command contains "vallum hook".
pub fn remove_vallum(settings: &mut Value) -> bool {
    let Some(arr) = settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
        .and_then(|p| p.as_array_mut())
    else {
        return false;
    };
    let before = arr.len();
    arr.retain(|e| !entry_is_vallum(e));
    before != arr.len()
}

pub fn install(level: Level, force: bool) -> Result<String, String> {
    super::merge_install(&settings_path(level)?, force, add_vallum, "Claude Code")
}

pub fn uninstall(level: Level) -> Result<String, String> {
    super::merge_uninstall(&settings_path(level)?, remove_vallum, "Claude Code")
}

#[cfg(test)]
mod tests {
    use super::super::read_settings;
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "vallum_install_hook_claude_{tag}_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn install_into_missing_file_creates_it() {
        let dir = temp_dir("missing_file");
        let path = dir.join("settings.json");
        let mut settings = read_settings(&path).unwrap();
        assert!(add_vallum(&mut settings, false).unwrap());
        let s = serde_json::to_string(&settings).unwrap();
        fs::write(&path, &s).unwrap();
        let after = read_settings(&path).unwrap();
        assert!(has_vallum_hook(&after));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_preserves_other_hooks_and_top_level_fields() {
        let dir = temp_dir("preserves_fields");
        let path = dir.join("settings.json");
        let existing = json!({
            "theme": "dark",
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Edit", "hooks": [{ "type": "command", "command": "echo edit-hook" }] }
                ]
            }
        });
        fs::write(&path, serde_json::to_string(&existing).unwrap()).unwrap();
        let mut settings = read_settings(&path).unwrap();
        assert!(add_vallum(&mut settings, false).unwrap());
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().any(|e| e["matcher"] == "Edit"));
        assert!(arr.iter().any(|e| e["matcher"] == MATCHER));
        assert_eq!(settings["theme"], "dark");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent_without_force() {
        let mut settings = json!({});
        assert!(add_vallum(&mut settings, false).unwrap());
        assert!(!add_vallum(&mut settings, false).unwrap());
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn install_force_replaces_existing() {
        let mut settings = json!({});
        add_vallum(&mut settings, false).unwrap();
        assert!(add_vallum(&mut settings, true).unwrap());
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn uninstall_removes_only_vallum_entry() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Edit", "hooks": [{ "type": "command", "command": "echo edit" }] },
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "vallum hook" }] }
                ]
            }
        });
        assert!(remove_vallum(&mut settings));
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "Edit");
    }

    #[test]
    fn add_vallum_errors_on_malformed_hooks_key() {
        let mut v = serde_json::json!({ "hooks": "not an object" });
        let err = add_vallum(&mut v, false).unwrap_err();
        assert!(err.contains("hooks"), "{err}");
    }

    #[test]
    fn entry_uses_file_tool_matcher() {
        let e = vallum_entry();
        assert_eq!(e["matcher"], "Bash|Write|Edit|MultiEdit|NotebookEdit|Read");
    }

    #[test]
    fn old_bash_only_entry_is_migrated_without_force() {
        let mut settings = json!({
            "hooks": { "PreToolUse": [
                { "matcher": "Bash",
                  "hooks": [{ "type": "command", "command": "vallum hook" }] }
            ]}
        });
        assert!(!vallum_matcher_current(&settings));
        let changed = add_vallum(&mut settings, false).unwrap();
        assert!(
            changed,
            "outdated matcher must migrate on plain install-hook"
        );
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        let ours: Vec<_> = arr
            .iter()
            .filter(|e| e["hooks"][0]["command"] == "vallum hook")
            .collect();
        assert_eq!(ours.len(), 1, "no duplicate vallum entries");
        assert_eq!(ours[0]["matcher"], MATCHER);
    }

    #[test]
    fn current_entry_is_idempotent_without_force() {
        let mut settings = json!({ "hooks": { "PreToolUse": [] } });
        assert!(add_vallum(&mut settings, false).unwrap());
        assert!(vallum_matcher_current(&settings));
        assert!(
            !add_vallum(&mut settings, false).unwrap(),
            "second run is a no-op"
        );
    }
}
