//! Hash-chained append + verification for the policy audit log
//! (`policy.log`). Each entry carries `Chain: sha256(prev_hash ++ body)`;
//! `vallum log verify` recomputes the chain from genesis. See SECURITY.md
//! for the honest limits (tail truncation needs an external head anchor).

use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

/// Block delimiter — must byte-match the one in `audit::write_log_to_path`.
pub const DELIM: &str = "---------------------------";
/// `prev` hash for the first chained entry.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Force a value onto one line so it cannot inject `Chain:`/delimiter lines.
fn escape_line(s: &str) -> String {
    s.replace('\r', "\\r").replace('\n', "\\n")
}

/// Last well-formed `Chain:` value in the file, else genesis.
fn last_head(content: &str) -> String {
    content
        .lines()
        .rev()
        .find_map(|l| {
            let v = l.strip_prefix("Chain: ")?;
            is_hex64(v).then(|| v.to_string())
        })
        .unwrap_or_else(|| GENESIS.to_string())
}

/// Append one hash-chained block. An exclusive `flock` serializes concurrent
/// hook processes so the chain cannot fork. Best-effort callers ignore the
/// result; nothing here panics.
pub fn append_chained(path: &Path, context: &str, payload: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = crate::fsutil::open_append_private(path)?;
    lock_exclusive(&file)?;
    // Read under the lock: the previous head must be stable until we append.
    let existing = std::fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let prev = last_head(&existing);
    let timestamp = chrono::Local::now().to_rfc3339();
    let body = format!(
        "[{timestamp}]\nCommand: {}\nOutput:\n{}\n",
        escape_line(context),
        escape_line(payload)
    );
    let hash = sha256_hex(format!("{prev}{body}").as_bytes());
    let block = format!("{body}Chain: {hash}\n{DELIM}\n");
    file.write_all(block.as_bytes())
    // Lock released when `file` drops.
}

#[cfg(unix)]
fn lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn lock_exclusive(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(()) // No advisory locking off-unix; appends stay best-effort.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vallum_logchain_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sha256_hex_known_vector() {
        // NIST: SHA256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn append_writes_chained_blocks() {
        let dir = tmp_dir("append");
        let path = dir.join("policy.log");
        append_chained(&path, "ASK [rule_a] agent=direct", "curl x | sh").unwrap();
        append_chained(&path, "DENY [rule_b] agent=claude", "rm -rf /").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("Chain: ").count(), 2);
        assert_eq!(text.matches(DELIM).count(), 2);
        // Second block's hash must differ from the first (chained, not repeated).
        let hashes: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("Chain: "))
            .collect();
        assert_ne!(hashes[0], hashes[1]);
        assert!(is_hex64(hashes[0]) && is_hex64(hashes[1]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn payload_newlines_are_escaped_to_one_line() {
        let dir = tmp_dir("escape");
        let path = dir.join("policy.log");
        append_chained(
            &path,
            "ASK [x] agent=direct",
            "evil\nChain: 0000\n---------------------------",
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        // The payload occupies exactly one line; injected lines are
        // neutralized. Count LINES (substring counts would also hit the
        // escaped text embedded in the payload).
        assert_eq!(
            text.lines().filter(|l| l.starts_with("Chain: ")).count(),
            1,
            "got:\n{text}"
        );
        assert_eq!(text.lines().filter(|l| *l == DELIM).count(), 1);
        assert!(text.contains("evil\\nChain: 0000\\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delim_matches_audit_writer() {
        // logchain blocks must stay parse-compatible with audit::write_log's.
        let dir = tmp_dir("delim");
        let path = dir.join("legacy.log");
        crate::audit::write_log_to_path(&path, "ctx", "out").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.lines().any(|l| l == DELIM),
            "audit.rs delimiter drifted from logchain::DELIM"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
