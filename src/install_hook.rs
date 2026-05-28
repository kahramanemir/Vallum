// src/install_hook.rs — install/uninstall the Vallum PreToolUse hook in
// Claude Code's settings.json.

use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub enum Level {
    User,
    Project,
}

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

/// Read settings.json into a serde_json::Value. Missing file → empty object.
/// Malformed file → Err with a hint to restore from backup.
pub fn read_settings(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(json!({}));
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str::<Value>(&raw).map_err(|e| {
        format!(
            "{} is not valid JSON ({e}); aborting to avoid clobbering it — restore from the most recent .bak-* if needed",
            path.display()
        )
    })
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

/// The exact JSON entry we add to hooks.PreToolUse.
fn vallum_entry() -> Value {
    json!({
        "matcher": "Bash",
        "hooks": [
            { "type": "command", "command": "vallum hook" }
        ]
    })
}

/// Add the Vallum entry. If `force`, replace existing Vallum entries; else
/// no-op when one is already present.
pub fn add_vallum(settings: &mut Value, force: bool) -> bool {
    if has_vallum_hook(settings) {
        if !force {
            return false;
        }
        // Remove existing vallum entries first.
        remove_vallum(settings);
    }
    let hooks = settings
        .as_object_mut()
        .expect("settings root must be an object")
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let pre = hooks
        .as_object_mut()
        .expect("hooks must be an object")
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    let arr = pre.as_array_mut().expect("PreToolUse must be an array");
    arr.push(vallum_entry());
    true
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

fn backup_suffix() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(".bak-{ts}")
}

/// Backup, atomic-write replacement. Returns the backup path if one was made.
fn write_atomic_with_backup(path: &Path, contents: &str) -> Result<Option<PathBuf>, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let backup = if path.exists() {
        let mut bk = path.as_os_str().to_owned();
        bk.push(backup_suffix());
        let bk_path = PathBuf::from(bk);
        fs::copy(path, &bk_path).map_err(|e| format!("backup {}: {e}", path.display()))?;
        Some(bk_path)
    } else {
        None
    };
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp-{}", std::process::id()));
    let tmp_path = PathBuf::from(tmp);
    fs::write(&tmp_path, contents).map_err(|e| format!("write {}: {e}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).map_err(|e| format!("rename {}: {e}", path.display()))?;
    Ok(backup)
}

/// Public install action.
pub fn install(level: Level, force: bool) -> Result<String, String> {
    let path = settings_path(level)?;
    let mut settings = read_settings(&path)?;
    if !settings.is_object() {
        return Err(format!("{} root is not a JSON object", path.display()));
    }
    let added = add_vallum(&mut settings, force);
    if !added {
        return Ok(format!(
            "Vallum hook already present in {}; pass --force to replace.",
            path.display()
        ));
    }
    let rendered =
        serde_json::to_string_pretty(&settings).map_err(|e| format!("serialize: {e}"))?;
    let backup = write_atomic_with_backup(&path, &rendered)?;
    Ok(match backup {
        Some(b) => format!(
            "Installed Vallum hook → {} (backup: {})",
            path.display(),
            b.display()
        ),
        None => format!("Installed Vallum hook → {}", path.display()),
    })
}

/// Public uninstall action.
pub fn uninstall(level: Level) -> Result<String, String> {
    let path = settings_path(level)?;
    if !path.exists() {
        return Ok(format!("{} does not exist; nothing to do.", path.display()));
    }
    let mut settings = read_settings(&path)?;
    if !settings.is_object() {
        return Err(format!("{} root is not a JSON object", path.display()));
    }
    let removed = remove_vallum(&mut settings);
    if !removed {
        return Ok(format!("No Vallum hook found in {}.", path.display()));
    }
    let rendered =
        serde_json::to_string_pretty(&settings).map_err(|e| format!("serialize: {e}"))?;
    let backup = write_atomic_with_backup(&path, &rendered)?;
    Ok(match backup {
        Some(b) => format!(
            "Removed Vallum hook from {} (backup: {})",
            path.display(),
            b.display()
        ),
        None => format!("Removed Vallum hook from {}", path.display()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "vallum_install_hook_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn install_into_missing_file_creates_it() {
        let dir = temp_dir();
        let path = dir.join("settings.json");
        let mut settings = read_settings(&path).unwrap();
        assert!(add_vallum(&mut settings, false));
        let s = serde_json::to_string(&settings).unwrap();
        fs::write(&path, &s).unwrap();
        let after = read_settings(&path).unwrap();
        assert!(has_vallum_hook(&after));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_preserves_other_hooks_and_top_level_fields() {
        let dir = temp_dir();
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
        assert!(add_vallum(&mut settings, false));
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().any(|e| e["matcher"] == "Edit"));
        assert!(arr.iter().any(|e| e["matcher"] == "Bash"));
        assert_eq!(settings["theme"], "dark");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_is_idempotent_without_force() {
        let mut settings = json!({});
        assert!(add_vallum(&mut settings, false));
        assert!(!add_vallum(&mut settings, false));
        let arr = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn install_force_replaces_existing() {
        let mut settings = json!({});
        add_vallum(&mut settings, false);
        assert!(add_vallum(&mut settings, true));
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
    fn read_settings_refuses_malformed_json() {
        let dir = temp_dir();
        let path = dir.join("settings.json");
        fs::write(&path, "{not valid json").unwrap();
        let err = read_settings(&path).unwrap_err();
        assert!(err.contains("not valid JSON"), "got: {err}");
        assert!(
            err.contains(".bak-"),
            "should hint at backup recovery; got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_creates_backup() {
        let dir = temp_dir();
        let path = dir.join("settings.json");
        fs::write(&path, r#"{"theme":"old"}"#).unwrap();
        let backup = write_atomic_with_backup(&path, r#"{"theme":"new"}"#).unwrap();
        let backup = backup.expect("backup expected when file pre-existed");
        let backup_contents = fs::read_to_string(&backup).unwrap();
        assert!(backup_contents.contains("\"old\""));
        let current = fs::read_to_string(&path).unwrap();
        assert!(current.contains("\"new\""));
        let _ = fs::remove_dir_all(&dir);
    }
}
