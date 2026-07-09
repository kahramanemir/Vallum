//! Codex CLI installer: merges a `PreToolUse` entry into ~/.codex/hooks.json.

use serde_json::{json, Value};
use std::path::PathBuf;

pub fn config_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".codex").join("hooks.json"))
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

pub fn has_hook(settings: &Value) -> bool {
    settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().any(entry_is_vallum))
        .unwrap_or(false)
}

/// The exact JSON entry we add to hooks.PreToolUse.
fn vallum_entry() -> Value {
    json!({
        "matcher": "Bash",
        "hooks": [
            { "type": "command", "command": "vallum hook --agent codex" }
        ]
    })
}

pub fn add(settings: &mut Value, force: bool) -> Result<bool, String> {
    if has_hook(settings) {
        if !force {
            return Ok(false);
        }
        remove(settings);
    }
    let hooks = settings
        .as_object_mut()
        .ok_or_else(|| "settings root is not a JSON object".to_string())?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let arr = hooks
        .as_object_mut()
        .ok_or_else(|| "the \"hooks\" key is not a JSON object".to_string())?
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    let arr = arr
        .as_array_mut()
        .ok_or_else(|| "hooks.PreToolUse is not a JSON array".to_string())?;
    arr.push(vallum_entry());
    Ok(true)
}

pub fn remove(settings: &mut Value) -> bool {
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

pub fn install(force: bool) -> Result<String, String> {
    super::merge_install(&config_path()?, force, add, "Codex CLI")
}

pub fn uninstall() -> Result<String, String> {
    super::merge_uninstall(&config_path()?, remove, "Codex CLI")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn add_into_empty_sets_version_and_entry() {
        let mut settings = json!({});
        assert!(add(&mut settings, false).unwrap());
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "Bash");
        assert_eq!(arr[0]["hooks"][0]["command"], "vallum hook --agent codex");
        assert!(has_hook(&settings));
    }

    #[test]
    fn add_is_idempotent_and_force_replaces() {
        let mut settings = json!({});
        assert!(add(&mut settings, false).unwrap());
        assert!(!add(&mut settings, false).unwrap());
        assert!(add(&mut settings, true).unwrap());
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn add_preserves_unrelated_hooks_and_keys() {
        let mut settings = json!({
            "theme": "dark",
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Edit", "hooks": [{ "type": "command", "command": "echo edit" }] }
                ]
            }
        });
        assert!(add(&mut settings, false).unwrap());
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(settings["theme"], "dark");
        assert_eq!(settings["hooks"]["PreToolUse"][0]["matcher"], "Edit");
    }

    #[test]
    fn remove_deletes_only_vallum_entry() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Edit", "hooks": [{ "type": "command", "command": "echo edit" }] },
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "vallum hook --agent codex" }] }
                ]
            }
        });
        assert!(remove(&mut settings));
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "Edit");
        assert!(!remove(&mut settings));
    }

    #[test]
    fn add_errors_on_malformed_hooks_key() {
        let mut v = serde_json::json!({ "hooks": "not an object" });
        let err = add(&mut v, false).unwrap_err();
        assert!(err.contains("hooks"), "{err}");
    }
}
