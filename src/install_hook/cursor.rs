//! Cursor installer: merges a `beforeShellExecution` entry into
//! ~/.cursor/hooks.json.

use serde_json::{json, Value};
use std::path::PathBuf;

pub fn config_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".cursor").join("hooks.json"))
}

fn entry_is_vallum(entry: &Value) -> bool {
    entry
        .get("command")
        .and_then(|c| c.as_str())
        .map(|s| s.contains("vallum hook"))
        .unwrap_or(false)
}

pub fn has_hook(settings: &Value) -> bool {
    settings
        .get("hooks")
        .and_then(|h| h.get("beforeShellExecution"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().any(entry_is_vallum))
        .unwrap_or(false)
}

pub fn add(settings: &mut Value, force: bool) -> bool {
    if has_hook(settings) {
        if !force {
            return false;
        }
        remove(settings);
    }
    let root = settings
        .as_object_mut()
        .expect("settings root must be an object");
    root.entry("version").or_insert(json!(1));
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    let arr = hooks
        .as_object_mut()
        .expect("hooks must be an object")
        .entry("beforeShellExecution")
        .or_insert_with(|| json!([]));
    let arr = arr
        .as_array_mut()
        .expect("beforeShellExecution must be an array");
    arr.push(json!({ "command": "vallum hook --agent cursor" }));
    true
}

pub fn remove(settings: &mut Value) -> bool {
    let Some(arr) = settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut("beforeShellExecution"))
        .and_then(|p| p.as_array_mut())
    else {
        return false;
    };
    let before = arr.len();
    arr.retain(|e| !entry_is_vallum(e));
    before != arr.len()
}

pub fn install(force: bool) -> Result<String, String> {
    super::merge_install(&config_path()?, force, add, "Cursor")
}

pub fn uninstall() -> Result<String, String> {
    super::merge_uninstall(&config_path()?, remove, "Cursor")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn add_into_empty_sets_version_and_entry() {
        let mut settings = json!({});
        assert!(add(&mut settings, false));
        assert_eq!(settings["version"], 1);
        let arr = settings["hooks"]["beforeShellExecution"]
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["command"], "vallum hook --agent cursor");
        assert!(has_hook(&settings));
    }

    #[test]
    fn add_is_idempotent_and_force_replaces() {
        let mut settings = json!({});
        assert!(add(&mut settings, false));
        assert!(!add(&mut settings, false));
        assert!(add(&mut settings, true));
        let arr = settings["hooks"]["beforeShellExecution"]
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn add_preserves_unrelated_hooks_and_keys() {
        let mut settings = json!({
            "version": 1,
            "theme": "dark",
            "hooks": {
                "beforeShellExecution": [ { "command": "other-tool check" } ],
                "afterFileEdit": [ { "command": "fmt-on-save" } ]
            }
        });
        assert!(add(&mut settings, false));
        let arr = settings["hooks"]["beforeShellExecution"]
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(settings["theme"], "dark");
        assert_eq!(
            settings["hooks"]["afterFileEdit"][0]["command"],
            "fmt-on-save"
        );
    }

    #[test]
    fn remove_deletes_only_vallum_entry() {
        let mut settings = json!({
            "hooks": {
                "beforeShellExecution": [
                    { "command": "other-tool check" },
                    { "command": "vallum hook --agent cursor" }
                ]
            }
        });
        assert!(remove(&mut settings));
        let arr = settings["hooks"]["beforeShellExecution"]
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["command"], "other-tool check");
        assert!(!remove(&mut settings));
    }
}
