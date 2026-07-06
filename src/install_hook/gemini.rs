//! Gemini CLI installer: merges a `BeforeTool` entry into
//! ~/.gemini/settings.json.

use serde_json::{json, Value};
use std::path::PathBuf;

pub fn config_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".gemini").join("settings.json"))
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
        .and_then(|h| h.get("BeforeTool"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().any(entry_is_vallum))
        .unwrap_or(false)
}

/// The exact JSON entry we add to hooks.BeforeTool.
fn vallum_entry() -> Value {
    json!({
        "matcher": "run_shell_command",
        "hooks": [
            { "type": "command", "command": "vallum hook --agent gemini" }
        ]
    })
}

pub fn add(settings: &mut Value, force: bool) -> bool {
    if has_hook(settings) {
        if !force {
            return false;
        }
        remove(settings);
    }
    let hooks = settings
        .as_object_mut()
        .expect("settings root must be an object")
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let arr = hooks
        .as_object_mut()
        .expect("hooks must be an object")
        .entry("BeforeTool")
        .or_insert_with(|| json!([]));
    let arr = arr.as_array_mut().expect("BeforeTool must be an array");
    arr.push(vallum_entry());
    true
}

pub fn remove(settings: &mut Value) -> bool {
    let Some(arr) = settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut("BeforeTool"))
        .and_then(|p| p.as_array_mut())
    else {
        return false;
    };
    let before = arr.len();
    arr.retain(|e| !entry_is_vallum(e));
    before != arr.len()
}

pub fn install(force: bool) -> Result<String, String> {
    super::merge_install(&config_path()?, force, add, "Gemini CLI")
}

pub fn uninstall() -> Result<String, String> {
    super::merge_uninstall(&config_path()?, remove, "Gemini CLI")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn add_into_empty_sets_version_and_entry() {
        let mut settings = json!({});
        assert!(add(&mut settings, false));
        let arr = settings["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "run_shell_command");
        assert_eq!(arr[0]["hooks"][0]["command"], "vallum hook --agent gemini");
        assert!(has_hook(&settings));
    }

    #[test]
    fn add_is_idempotent_and_force_replaces() {
        let mut settings = json!({});
        assert!(add(&mut settings, false));
        assert!(!add(&mut settings, false));
        assert!(add(&mut settings, true));
        let arr = settings["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn add_preserves_unrelated_hooks_and_keys() {
        let mut settings = json!({
            "theme": "dark",
            "hooks": {
                "BeforeTool": [
                    { "matcher": "write_file", "hooks": [{ "type": "command", "command": "other" }] }
                ]
            }
        });
        assert!(add(&mut settings, false));
        let arr = settings["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(settings["theme"], "dark");
        assert_eq!(settings["hooks"]["BeforeTool"][0]["matcher"], "write_file");
    }

    #[test]
    fn remove_deletes_only_vallum_entry() {
        let mut settings = json!({
            "hooks": {
                "BeforeTool": [
                    { "matcher": "write_file", "hooks": [{ "type": "command", "command": "other" }] },
                    { "matcher": "run_shell_command", "hooks": [{ "type": "command", "command": "vallum hook --agent gemini" }] }
                ]
            }
        });
        assert!(remove(&mut settings));
        let arr = settings["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "write_file");
        assert!(!remove(&mut settings));
    }
}
