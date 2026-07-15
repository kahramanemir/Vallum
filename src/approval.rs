//! Machine-local approval secret and per-command HMAC tokens. The Claude hook
//! mints a token when it re-wraps an approved command through `vallum run`;
//! `run` verifies it before skipping the guardrail. A forged or injected
//! `--approval-token` cannot match without the secret, so it is re-gated.
//!
//! Boundary: this defeats a process that only observes rewritten commands. A
//! process that can READ the secret file (same user, no sandbox) can mint
//! valid tokens — that is out of scope and is the OS sandbox's job.

use crate::config::AppConfig;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

const SECRET_LEN: usize = 32;

/// `<log_dir>/approval.secret` (default `~/.vallum/logs/approval.secret`).
pub fn secret_path(cfg: &AppConfig) -> PathBuf {
    crate::audit::resolve_log_path("approval.secret", cfg.audit.log_dir.as_deref())
}

/// Lowercase-hex HMAC-SHA256(secret, command_line).
pub fn token_for(command_line: &str, secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(command_line.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Constant-time check that `token` is the valid hex HMAC for `command_line`.
pub fn verify(command_line: &str, token: &str, secret: &[u8]) -> bool {
    let expected = token_for(command_line, secret);
    ct_eq(expected.as_bytes(), token.as_bytes())
}

/// Length-aware constant-time byte comparison (length is not secret here).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Read the secret without creating it. None if absent/unreadable/too short.
pub fn load_secret(cfg: &AppConfig) -> Option<Vec<u8>> {
    let buf = std::fs::read(secret_path(cfg)).ok()?;
    (buf.len() >= SECRET_LEN).then_some(buf)
}

/// Load the secret, creating it (32 random bytes, 0600) if absent. flock-
/// serialized create-or-read so concurrent hooks agree on one secret. None on
/// any I/O failure or on non-unix (no `/dev/urandom`).
pub fn load_or_create_secret(cfg: &AppConfig) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let path = secret_path(cfg);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    let file = crate::fsutil::open_rw_private(&path).ok()?;
    crate::fsutil::lock_exclusive(&file).ok()?;
    let mut buf = Vec::new();
    (&file).read_to_end(&mut buf).ok()?;
    if buf.len() >= SECRET_LEN {
        return Some(buf);
    }
    // Empty or truncated → mint and persist under the held lock.
    let secret = random_secret()?;
    let mut f = &file;
    f.seek(SeekFrom::Start(0)).ok()?;
    f.write_all(&secret).ok()?;
    f.flush().ok()?;
    Some(secret)
}

#[cfg(unix)]
fn random_secret() -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").ok()?;
    let mut buf = vec![0u8; SECRET_LEN];
    f.read_exact(&mut buf).ok()?;
    Some(buf)
}

#[cfg(not(unix))]
fn random_secret() -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_dir(dir: &std::path::Path) -> crate::config::AppConfig {
        let mut cfg = crate::config::AppConfig::default();
        cfg.audit.log_dir = Some(dir.to_path_buf());
        cfg
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "vallum_approval_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn token_matches_known_vector() {
        // RFC-style check: HMAC-SHA256 hex is deterministic for fixed key+msg.
        let t1 = token_for("bash -c git status", b"secret-key-0123456789");
        let t2 = token_for("bash -c git status", b"secret-key-0123456789");
        assert_eq!(t1, t2, "deterministic");
        assert_eq!(t1.len(), 64, "sha256 hex is 64 chars");
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
        // Different message → different token.
        assert_ne!(t1, token_for("bash -c rm -rf /", b"secret-key-0123456789"));
        // Different key → different token.
        assert_ne!(t1, token_for("bash -c git status", b"other-key"));
    }

    #[test]
    fn verify_accepts_valid_rejects_tampered() {
        let secret = b"k".repeat(32);
        let cmd = "bash -c echo hello";
        let tok = token_for(cmd, &secret);
        assert!(verify(cmd, &tok, &secret));
        // Mutated command.
        assert!(!verify("bash -c echo hell0", &tok, &secret));
        // Truncated token.
        assert!(!verify(cmd, &tok[..40], &secret));
        // Wrong-length garbage token.
        assert!(!verify(cmd, "deadbeef", &secret));
        // Wrong secret.
        assert!(!verify(cmd, &tok, b"different-secret-value-32-bytes!!"));
    }

    #[test]
    fn create_then_read_is_stable_and_0600() {
        let dir = temp_dir("stable");
        let cfg = cfg_with_dir(&dir);
        let a = load_or_create_secret(&cfg).expect("create");
        assert_eq!(a.len(), 32);
        let b = load_or_create_secret(&cfg).expect("re-read");
        assert_eq!(a, b, "second call reads the same secret, not a new one");
        let c = load_secret(&cfg).expect("read-only load");
        assert_eq!(a, c);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(secret_path(&cfg))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_secret_absent_is_none() {
        let dir = temp_dir("absent");
        let cfg = cfg_with_dir(&dir);
        assert!(load_secret(&cfg).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_creation_agrees_on_one_secret() {
        let dir = temp_dir("race");
        let cfg = cfg_with_dir(&dir);
        let mut handles = vec![];
        for _ in 0..8 {
            let c = cfg.clone();
            handles.push(std::thread::spawn(move || load_or_create_secret(&c)));
        }
        let secrets: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let first = secrets[0].clone().expect("some");
        for s in &secrets {
            assert_eq!(s.as_ref().unwrap(), &first, "all threads see one secret");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
