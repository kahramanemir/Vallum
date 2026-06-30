//! Append-only writer for the raw and sanitized audit logs under `~/.vallum/logs`.

use chrono::Local;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn default_log_path(filename: &str) -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".vallum").join("logs").join(filename)
    } else {
        PathBuf::from(filename)
    }
}

pub fn resolve_log_path(filename: &str, log_dir: Option<&Path>) -> PathBuf {
    match log_dir {
        Some(dir) => dir.join(filename),
        None => default_log_path(filename),
    }
}

pub fn write_log_to_path(path: &Path, cmd_context: &str, output: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = crate::fsutil::open_append_private(path)?;

    let timestamp = Local::now().to_rfc3339();
    let log_entry = format!(
        "[{}]\nCommand: {}\nOutput:\n{}\n---------------------------\n",
        timestamp, cmd_context, output
    );

    file.write_all(log_entry.as_bytes())
}

pub fn write_log(
    filename: &str,
    cmd_context: &str,
    output: &str,
    log_dir: Option<&Path>,
) -> std::io::Result<()> {
    let path = resolve_log_path(filename, log_dir);
    write_log_to_path(&path, cmd_context, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn default_log_path_uses_vallum_logs_directory() {
        let path = default_log_path("raw.local.log");
        assert!(path.ends_with(Path::new(".vallum").join("logs").join("raw.local.log")));
    }

    #[test]
    fn resolve_log_path_uses_custom_directory_when_provided() {
        let path = resolve_log_path("raw.local.log", Some(Path::new("/tmp/vallum-logs")));
        assert_eq!(path, Path::new("/tmp/vallum-logs").join("raw.local.log"));
    }

    #[test]
    fn test_log_writing() {
        let tmp = std::env::temp_dir().join("vallum_test_audit_log");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let test_file = tmp.join("test_raw.log");
        write_log_to_path(&test_file, "ls", "raw output").unwrap();

        let content = fs::read_to_string(&test_file).unwrap();
        assert!(content.contains("Command: ls"));
        assert!(content.contains("raw output"));
        let _ = fs::remove_dir_all(&tmp);
    }
}
