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

/// Where and why the chain broke. `index` is the 1-based block number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakInfo {
    pub index: usize,
    pub timestamp: String,
    pub reason: String,
}

/// Result of verifying one policy.log's content.
#[derive(Debug, Clone)]
pub struct ChainReport {
    pub total: usize,
    pub chained: usize,
    pub legacy: usize,
    pub head: Option<String>,
    pub break_at: Option<BreakInfo>,
}

impl ChainReport {
    pub fn intact(&self) -> bool {
        self.break_at.is_none()
    }
}

/// Verify a full policy.log body. Pure: string in, report out. Blocks before
/// the first `Chain:` block are legacy (unverifiable); from there on every
/// hash is recomputed from genesis and the first break stops the scan.
pub fn verify_content(content: &str) -> ChainReport {
    let mut report = ChainReport {
        total: 0,
        chained: 0,
        legacy: 0,
        head: None,
        break_at: None,
    };
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    for line in content.lines() {
        if line == DELIM {
            blocks.push(std::mem::take(&mut cur));
        } else {
            cur.push(line);
        }
    }
    let trailing = cur; // lines after the last delimiter (torn write?)

    let mut prev = GENESIS.to_string();
    let mut in_chain = false;
    for (i, lines) in blocks.iter().enumerate() {
        report.total += 1;
        let index = i + 1;
        let timestamp = lines.first().copied().unwrap_or("?").to_string();
        // The writer always emits `Chain:` as the block's LAST line. Anchor
        // detection there so a payload line that itself starts with `Chain: `
        // (payloads are escaped to one line, but can still start that way)
        // cannot masquerade as the chain line.
        let is_chained = lines.last().is_some_and(|l| l.starts_with("Chain: "));
        if !is_chained {
            if in_chain {
                report.break_at = Some(BreakInfo {
                    index,
                    timestamp,
                    reason: "unchained block after the chain started (inserted or rewritten)"
                        .to_string(),
                });
                return report;
            }
            report.legacy += 1;
            continue;
        }
        in_chain = true;
        let pos = lines.len() - 1;
        let value = lines[pos].strip_prefix("Chain: ").unwrap_or("");
        if !is_hex64(value) {
            report.break_at = Some(BreakInfo {
                index,
                timestamp,
                reason: "malformed Chain: line".to_string(),
            });
            return report;
        }
        let body: String = lines[..pos].iter().map(|l| format!("{l}\n")).collect();
        let expected = sha256_hex(format!("{prev}{body}").as_bytes());
        if expected != value {
            report.break_at = Some(BreakInfo {
                index,
                timestamp,
                reason:
                    "hash mismatch (entry edited, or an earlier chained entry removed/reordered)"
                        .to_string(),
            });
            return report;
        }
        prev = value.to_string();
        report.chained += 1;
        report.head = Some(prev.clone());
    }

    if trailing.iter().any(|l| !l.trim().is_empty()) {
        if in_chain {
            report.break_at = Some(BreakInfo {
                index: report.total + 1,
                timestamp: trailing.first().copied().unwrap_or("?").to_string(),
                reason: "incomplete trailing block (torn write or tampering)".to_string(),
            });
        } else {
            report.total += 1;
            report.legacy += 1;
        }
    }
    report
}

/// I/O wrapper. `Ok(None)` = file absent (nothing to verify).
pub fn verify_file(path: &Path) -> Result<Option<ChainReport>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(Some(verify_content(&String::from_utf8_lossy(&bytes))))
}

/// Human report + exit code (0 intact / 20 tamper evidence). `expect_head`
/// must already be lowercase hex (the CLI validates).
pub fn render_report(path: &Path, r: &ChainReport, expect_head: Option<&str>) -> (String, i32) {
    let mut out = String::new();
    out.push_str(&format!("policy.log chain — {}\n", path.display()));
    out.push_str(&format!(
        "entries: {} total, {} chained, {} legacy (pre-chain, unverifiable)\n",
        r.total, r.chained, r.legacy
    ));
    if let Some(b) = &r.break_at {
        out.push_str(&format!(
            "✗ chain BROKEN at block {} {} — {}\n",
            b.index, b.timestamp, b.reason
        ));
        return (out, 20);
    }
    let Some(head) = &r.head else {
        if expect_head.is_some() {
            out.push_str("✗ expected a chained head but the log has no chained entries\n");
            return (out, 20);
        }
        out.push_str("no chained entries yet — chain starts with the next Ask/Deny verdict\n");
        return (out, 0);
    };
    out.push_str(&format!("head: {head}\n"));
    match expect_head {
        Some(exp) if exp == head => {
            out.push_str("✓ chain intact, head matches the external anchor\n");
            (out, 0)
        }
        Some(_) => {
            out.push_str("✗ head MISMATCH — log truncated or rewritten since the anchored head\n");
            (out, 20)
        }
        None => {
            out.push_str(
                "✓ chain intact (store the head externally; verify later with --expect-head)\n",
            );
            (out, 0)
        }
    }
}

/// CLI entry: resolve the policy.log path from config, verify, print, and
/// return the process exit code (0 intact, 20 tamper evidence, 125 usage/IO).
pub fn run_verify(expect_head: Option<&str>, cfg: &crate::config::AppConfig) -> i32 {
    let normalized = expect_head.map(|s| s.to_ascii_lowercase());
    if let Some(h) = &normalized {
        if !is_hex64(h) {
            eprintln!("log verify: --expect-head must be 64 hex characters");
            return 125;
        }
    }
    let path = crate::audit::resolve_log_path("policy.log", cfg.audit.log_dir.as_deref());
    match verify_file(&path) {
        Err(e) => {
            eprintln!("log verify: {e}");
            125
        }
        Ok(None) => {
            println!(
                "no policy.log at {} — nothing to verify (absence alone is not tamper evidence)",
                path.display()
            );
            0
        }
        Ok(Some(report)) => {
            let (text, code) = render_report(&path, &report, normalized.as_deref());
            print!("{text}");
            code
        }
    }
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

    /// Build a file with `n` chained entries and return its content.
    fn chained_file(dir: &std::path::Path, n: usize) -> (std::path::PathBuf, String) {
        let path = dir.join("policy.log");
        for i in 0..n {
            append_chained(&path, &format!("ASK [rule_{i}] agent=direct"), "cmd").unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        (path, text)
    }

    #[test]
    fn verify_intact_chain() {
        let dir = tmp_dir("v_ok");
        let (_, text) = chained_file(&dir, 3);
        let r = verify_content(&text);
        assert!(r.intact(), "{:?}", r.break_at);
        assert_eq!((r.total, r.chained, r.legacy), (3, 3, 0));
        assert!(r.head.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_edited_payload() {
        let dir = tmp_dir("v_edit");
        let (_, text) = chained_file(&dir, 3);
        let tampered = text.replacen("rule_1", "rule_X", 1);
        let r = verify_content(&tampered);
        let b = r.break_at.expect("must break");
        assert_eq!(b.index, 2);
        assert!(b.reason.contains("hash mismatch"), "{}", b.reason);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_corrupt_chain_line() {
        let dir = tmp_dir("v_corrupt");
        let (_, text) = chained_file(&dir, 2);
        // Corrupt the first Chain: value's first hex char to 'z'.
        let pos = text.find("Chain: ").unwrap() + "Chain: ".len();
        let mut t = text.clone();
        t.replace_range(pos..pos + 1, "z");
        let r = verify_content(&t);
        assert!(!r.intact());
        assert!(r.break_at.unwrap().reason.contains("malformed"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_detects_deleted_middle_block() {
        let dir = tmp_dir("v_del");
        let (_, text) = chained_file(&dir, 3);
        // Remove the middle block (between 1st and 2nd delimiter).
        let blocks: Vec<&str> = text.split_inclusive(&format!("{DELIM}\n")).collect();
        let t = format!("{}{}", blocks[0], blocks[2]);
        let r = verify_content(&t);
        assert!(!r.intact());
        assert_eq!(r.break_at.unwrap().index, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_legacy_prefix_then_chain_is_intact() {
        let dir = tmp_dir("v_legacy");
        let path = dir.join("policy.log");
        crate::audit::write_log_to_path(&path, "ASK [old] agent=direct", "old cmd").unwrap();
        append_chained(&path, "ASK [new] agent=direct", "new cmd").unwrap();
        let r = verify_content(&std::fs::read_to_string(&path).unwrap());
        assert!(r.intact(), "{:?}", r.break_at);
        assert_eq!((r.total, r.chained, r.legacy), (2, 1, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_unchained_block_after_chain_breaks() {
        let dir = tmp_dir("v_after");
        let (path, _) = chained_file(&dir, 1);
        crate::audit::write_log_to_path(&path, "ASK [sneak] agent=direct", "x").unwrap();
        let r = verify_content(&std::fs::read_to_string(&path).unwrap());
        assert!(!r.intact());
        assert!(r.break_at.unwrap().reason.contains("unchained"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_incomplete_tail_after_chain_breaks() {
        let dir = tmp_dir("v_tail");
        let (_, text) = chained_file(&dir, 1);
        let t = format!("{text}[2026-07-14T00:00:00+00:00]\nCommand: torn");
        let r = verify_content(&t);
        assert!(!r.intact());
        assert!(r.break_at.unwrap().reason.contains("incomplete"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_truncation_is_invisible_without_anchor() {
        // Documented limit: dropping the last block leaves an intact chain.
        let dir = tmp_dir("v_trunc");
        let (_, text) = chained_file(&dir, 3);
        let blocks: Vec<&str> = text.split_inclusive(&format!("{DELIM}\n")).collect();
        let t = format!("{}{}", blocks[0], blocks[1]);
        let r = verify_content(&t);
        assert!(r.intact());
        assert_eq!(r.chained, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_file_absent_is_none() {
        let dir = tmp_dir("v_absent");
        assert!(verify_file(&dir.join("nope.log")).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn payload_starting_with_chain_prefix_still_verifies() {
        let dir = tmp_dir("v_chainpayload");
        let path = dir.join("policy.log");
        append_chained(
            &path,
            "ASK [r] agent=direct",
            "Chain: 0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        append_chained(&path, "ASK [r2] agent=direct", "cmd").unwrap();
        let r = verify_content(&std::fs::read_to_string(&path).unwrap());
        assert!(r.intact(), "{:?}", r.break_at);
        assert_eq!(r.chained, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_report_codes() {
        let dir = tmp_dir("render");
        let (path, text) = chained_file(&dir, 2);
        let r = verify_content(&text);
        let head = r.head.clone().unwrap();
        assert_eq!(render_report(&path, &r, None).1, 0);
        assert_eq!(render_report(&path, &r, Some(&head)).1, 0);
        assert_eq!(render_report(&path, &r, Some(GENESIS)).1, 20);
        let broken = verify_content(&text.replacen("rule_0", "rule_Z", 1));
        assert_eq!(render_report(&path, &broken, None).1, 20);
        let empty = verify_content("");
        assert_eq!(render_report(&path, &empty, Some(GENESIS)).1, 20);
        assert_eq!(render_report(&path, &empty, None).1, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_appends_do_not_fork_the_chain() {
        let dir = tmp_dir("conc");
        let path = dir.join("policy.log");
        let mut handles = Vec::new();
        for t in 0..8 {
            let p = path.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..5 {
                    append_chained(&p, &format!("ASK [t{t}_{i}] agent=direct"), "cmd").unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let r = verify_content(&std::fs::read_to_string(&path).unwrap());
        assert!(r.intact(), "{:?}", r.break_at);
        assert_eq!(r.chained, 40);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_verify_paths_and_codes() {
        let dir = tmp_dir("run_verify");
        let mut cfg = crate::config::AppConfig::default();
        cfg.audit.log_dir = Some(dir.clone());
        // Absent file → 0 (absence is not tamper evidence).
        assert_eq!(run_verify(None, &cfg), 0);
        // Bad --expect-head → 125 usage error.
        assert_eq!(run_verify(Some("nothex"), &cfg), 125);
        // Intact chain → 0.
        let path = dir.join("policy.log");
        append_chained(&path, "ASK [r] agent=direct", "cmd").unwrap();
        assert_eq!(run_verify(None, &cfg), 0);
        // Wrong anchor → 20.
        assert_eq!(run_verify(Some(GENESIS), &cfg), 20);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
