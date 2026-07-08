//! Install/uninstall Vallum's pre-exec hook in agent config files.
//! Shared JSON-merge machinery lives here; each agent has a module with its
//! config path, entry shape, and add/remove logic.

pub mod claude;
pub mod codex;
pub mod cursor;
pub mod gemini;

pub use claude::{has_vallum_hook, settings_path};

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub enum Level {
    User,
    Project,
}

/// Read a JSON config file into a serde_json::Value. Missing file → empty
/// object. Malformed file → Err with a hint to restore from backup.
pub fn read_settings(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str::<Value>(&raw).map_err(|e| {
        format!(
            "{} is not valid JSON ({e}); aborting to avoid clobbering it — restore from the most recent .bak-* if needed",
            path.display()
        )
    })
}

fn backup_suffix() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(".bak-{ts}")
}

/// Backup, atomic-write replacement. Returns the backup path if one was made.
pub(crate) fn write_atomic_with_backup(
    path: &Path,
    contents: &str,
) -> Result<Option<PathBuf>, String> {
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

/// Generic idempotent hook install: read (or create) the JSON file at `path`,
/// run the agent's `add`, and atomically write back with a backup.
pub(crate) fn merge_install(
    path: &Path,
    force: bool,
    add: impl Fn(&mut Value, bool) -> Result<bool, String>,
    label: &str,
) -> Result<String, String> {
    let mut settings = read_settings(path)?;
    if !settings.is_object() {
        return Err(format!("{} root is not a JSON object", path.display()));
    }
    let added = add(&mut settings, force).map_err(|e| format!("{}: {e}", path.display()))?;
    if !added {
        return Ok(format!(
            "Vallum {label} hook already present in {}; pass --force to replace.",
            path.display()
        ));
    }
    let rendered =
        serde_json::to_string_pretty(&settings).map_err(|e| format!("serialize: {e}"))?;
    let backup = write_atomic_with_backup(path, &rendered)?;
    Ok(match backup {
        Some(b) => format!(
            "Installed Vallum {label} hook → {} (backup: {})",
            path.display(),
            b.display()
        ),
        None => format!("Installed Vallum {label} hook → {}", path.display()),
    })
}

/// Generic hook uninstall: remove exactly what install added.
pub(crate) fn merge_uninstall(
    path: &Path,
    remove: impl Fn(&mut Value) -> bool,
    label: &str,
) -> Result<String, String> {
    if !path.exists() {
        return Ok(format!("{} does not exist; nothing to do.", path.display()));
    }
    let mut settings = read_settings(path)?;
    if !settings.is_object() {
        return Err(format!("{} root is not a JSON object", path.display()));
    }
    if !remove(&mut settings) {
        return Ok(format!(
            "No Vallum {label} hook found in {}.",
            path.display()
        ));
    }
    let rendered =
        serde_json::to_string_pretty(&settings).map_err(|e| format!("serialize: {e}"))?;
    let backup = write_atomic_with_backup(path, &rendered)?;
    Ok(match backup {
        Some(b) => format!(
            "Removed Vallum {label} hook from {} (backup: {})",
            path.display(),
            b.display()
        ),
        None => format!("Removed Vallum {label} hook from {}", path.display()),
    })
}

/// Agents Vallum can install a hook for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Cursor,
    Gemini,
    Codex,
}

/// Per-agent install. Non-Claude agents are user-level only; `level` is
/// validated at the CLI boundary before this is called.
pub fn install_agent(agent: Agent, level: Level, force: bool) -> Result<String, String> {
    match agent {
        Agent::Claude => claude::install(level, force),
        Agent::Cursor => cursor::install(force),
        Agent::Gemini => gemini::install(force),
        Agent::Codex => codex::install(force),
    }
}

pub fn uninstall_agent(agent: Agent, level: Level) -> Result<String, String> {
    match agent {
        Agent::Claude => claude::uninstall(level),
        Agent::Cursor => cursor::uninstall(),
        Agent::Gemini => gemini::uninstall(),
        Agent::Codex => codex::uninstall(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "vallum_install_hook_mod_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
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
