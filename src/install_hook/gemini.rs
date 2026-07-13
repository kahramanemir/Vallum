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

/// Every hook command under hooks.BeforeTool[].hooks[].command.
pub fn list_hook_commands(settings: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(entries) = settings
        .get("hooks")
        .and_then(|h| h.get("BeforeTool"))
        .and_then(|p| p.as_array())
    else {
        return out;
    };
    for entry in entries {
        if let Some(hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
            for h in hooks {
                if let Some(cmd) = h.get("command").and_then(|c| c.as_str()) {
                    out.push(cmd.to_string());
                }
            }
        }
    }
    out
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
        .entry("BeforeTool")
        .or_insert_with(|| json!([]));
    let arr = arr
        .as_array_mut()
        .ok_or_else(|| "hooks.BeforeTool is not a JSON array".to_string())?;
    arr.push(vallum_entry());
    Ok(true)
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
        assert!(add(&mut settings, false).unwrap());
        let arr = settings["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "run_shell_command");
        assert_eq!(arr[0]["hooks"][0]["command"], "vallum hook --agent gemini");
        assert!(has_hook(&settings));
    }

    #[test]
    fn add_is_idempotent_and_force_replaces() {
        let mut settings = json!({});
        assert!(add(&mut settings, false).unwrap());
        assert!(!add(&mut settings, false).unwrap());
        assert!(add(&mut settings, true).unwrap());
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
        assert!(add(&mut settings, false).unwrap());
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

    #[test]
    fn add_errors_on_malformed_hooks_key() {
        let mut v = serde_json::json!({ "hooks": "not an object" });
        let err = add(&mut v, false).unwrap_err();
        assert!(err.contains("hooks"), "{err}");
    }

    #[test]
    fn list_hook_commands_reads_entries() {
        let settings = serde_json::json!({
            "hooks": { "BeforeTool": [
                { "hooks": [{ "type": "command", "command": "vallum hook --agent gemini" }] }
            ]}
        });
        assert_eq!(
            list_hook_commands(&settings),
            vec!["vallum hook --agent gemini".to_string()]
        );
    }
}
