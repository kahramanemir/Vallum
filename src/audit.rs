//! Append-only writer for the raw and sanitized audit logs under `~/.vallum/logs`.

use chrono::Local;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Line that terminates one log entry. A payload line matching it exactly
/// would forge an entry boundary, so `neutralize_delimiter` escapes it.
/// `logchain::DELIM` aliases this so both log formats stay in sync.
pub(crate) const ENTRY_DELIMITER: &str = "---------------------------";

pub fn default_log_path(filename: &str) -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".vallum").join("logs").join(filename))
}

/// None when no override is configured and the home directory is unknown —
/// callers must skip or fail, never fall back to the working directory (a repo
/// cwd would leak raw logs and let checked-in files pose as Vallum state).
pub fn resolve_log_path(filename: &str, log_dir: Option<&Path>) -> Option<PathBuf> {
    match log_dir {
        Some(dir) => Some(dir.join(filename)),
        None => default_log_path(filename),
    }
}

/// C0 control chars and DEL → backslash escapes, so the single-line fields of
/// a log entry cannot be broken across lines or carry terminal escapes.
fn escape_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Escape any payload line that exactly matches the entry delimiter so
/// captured output cannot forge an entry boundary.
fn neutralize_delimiter(s: &str) -> String {
    if !s.contains(ENTRY_DELIMITER) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 4);
    for (i, line) in s.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if line.strip_suffix('\r').unwrap_or(line) == ENTRY_DELIMITER {
            out.push('\\');
        }
        out.push_str(line);
    }
    out
}

pub fn write_log_to_path(path: &Path, cmd_context: &str, output: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = crate::fsutil::open_append_private(path)?;
    // Large appends to a regular file are not atomic; serialize whole entries
    // under flock so concurrent `vallum run`s cannot interleave mid-entry.
    crate::fsutil::lock_exclusive(&file)?;

    let timestamp = Local::now().to_rfc3339();
    let log_entry = format!(
        "[{}]\nCommand: {}\nOutput:\n{}\n{}\n",
        timestamp,
        escape_control(cmd_context),
        neutralize_delimiter(output),
        ENTRY_DELIMITER
    );

    file.write_all(log_entry.as_bytes())
}

pub fn write_log(
    filename: &str,
    cmd_context: &str,
    output: &str,
    log_dir: Option<&Path>,
) -> std::io::Result<()> {
    let Some(path) = resolve_log_path(filename, log_dir) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no home directory and no [audit] log_dir — refusing to log into the working directory",
        ));
    };
    write_log_to_path(&path, cmd_context, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn default_log_path_uses_vallum_logs_directory() {
        let path = default_log_path("raw.local.log").expect("home dir in test env");
        assert!(path.ends_with(Path::new(".vallum").join("logs").join("raw.local.log")));
    }

    #[test]
    fn resolve_log_path_uses_custom_directory_when_provided() {
        let path = resolve_log_path("raw.local.log", Some(Path::new("/tmp/vallum-logs"))).unwrap();
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

    #[test]
    fn command_field_stays_one_line() {
        let tmp = std::env::temp_dir().join("vallum_test_audit_escape");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let test_file = tmp.join("raw.log");
        write_log_to_path(&test_file, "ls\nCommand: forged\x1b[31m", "out").unwrap();

        let content = fs::read_to_string(&test_file).unwrap();
        assert!(content.contains("Command: ls\\nCommand: forged\\x1b[31m"));
        assert_eq!(
            content
                .lines()
                .filter(|l| l.starts_with("Command: "))
                .count(),
            1,
            "injected newline must not mint a second Command: line: {content}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn output_cannot_forge_entry_boundary() {
        let tmp = std::env::temp_dir().join("vallum_test_audit_delim");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let test_file = tmp.join("raw.log");
        let payload = format!("real output\n{ENTRY_DELIMITER}\n[fake ts]\nCommand: forged");
        write_log_to_path(&test_file, "ls", &payload).unwrap();

        let content = fs::read_to_string(&test_file).unwrap();
        let boundary_lines = content.lines().filter(|l| *l == ENTRY_DELIMITER).count();
        assert_eq!(boundary_lines, 1, "only the real terminator: {content}");
        assert!(content.contains(&format!("\\{ENTRY_DELIMITER}")));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn write_log_without_home_or_log_dir_errors_instead_of_cwd() {
        // Only meaningful to simulate via the resolver: a None resolution must
        // surface as an error from write_log, never a cwd-relative write.
        assert!(resolve_log_path("x.log", Some(Path::new("/tmp/t"))).is_some());
        // The write_log error path is exercised directly:
        if default_log_path("x.log").is_none() {
            assert!(write_log("x.log", "c", "o", None).is_err());
        }
    }
}
