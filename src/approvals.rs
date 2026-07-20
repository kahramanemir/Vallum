//! HMAC-signed approval cache: remembers a human-approved Ask (exact
//! command + cwd + rule) for a bounded TTL so the identical command is not
//! re-asked. Fed only by real approval evidence — a hook-minted token
//! verifying in `vallum run`, or a direct-mode TTY "y" — and consulted only
//! by the Claude hook and direct `vallum run`. Entries are HMACed with the
//! machine approval secret: same trust boundary as `approval.secret` itself
//! (a same-user process that can read the secret can mint entries; that is
//! the OS sandbox's job). Every failure mode — missing/corrupt/forged/expired
//! entry, cwd mismatch, unreadable secret — is a cache miss that re-asks:
//! tampering can only produce MORE asking, never less.

use crate::config::AppConfig;
use std::path::PathBuf;

/// Rules whose approved Asks may be remembered. Deliberately hard-coded and
/// narrow: recurring workflow commands whose effect is pinned by the command
/// line itself. Destructive rules, credential reads, agent-config writes,
/// Vallum self-protection, and remote-fetch-exec rules are never cached (for
/// `curl x | sh`-class commands an identical line does not imply an identical
/// payload).
pub const CACHE_ELIGIBLE_RULES: &[&str] = &[
    "git_push_force",
    "git_clean_force",
    "write_crontab",
    "write_git_hooks",
];

#[derive(serde::Serialize, serde::Deserialize)]
struct Entry {
    v: u32,
    ts: u64,
    cwd: String,
    rule: String,
    cmd: String,
    mac: String,
}

/// One valid, unexpired cache entry as shown by `vallum approvals list`.
pub struct ListedEntry {
    pub ts: u64,
    pub rule: String,
    pub cwd: String,
    pub cmd: String,
}

/// `<log_dir>/approvals.jsonl`, next to `approval.secret`.
pub fn approvals_path(cfg: &AppConfig) -> Option<PathBuf> {
    crate::audit::resolve_log_path("approvals.jsonl", cfg.audit.log_dir.as_deref())
}

pub fn eligible(rule: &str) -> bool {
    CACHE_ELIGIBLE_RULES.contains(&rule)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mac_for(cmd: &str, cwd: &str, rule: &str, ts: u64, secret: &[u8]) -> String {
    crate::approval::token_for(&format!("v1\0{cmd}\0{cwd}\0{rule}\0{ts}"), secret)
}

fn ttl_secs(cfg: &AppConfig) -> u64 {
    cfg.security.approval_cache_ttl_days.saturating_mul(86_400)
}

fn entry_valid(e: &Entry, now: u64, ttl: u64, secret: &[u8]) -> bool {
    e.v == 1
        && now.saturating_sub(e.ts) <= ttl
        && crate::approval::ct_eq(
            mac_for(&e.cmd, &e.cwd, &e.rule, e.ts, secret).as_bytes(),
            e.mac.as_bytes(),
        )
}

/// Record a human-approved Ask. No-op unless the cache is enabled and the
/// rule is eligible; creates the machine secret if absent (same behavior as
/// the hook). Best-effort — never blocks or errors.
pub fn record(cfg: &AppConfig, cmd: &str, cwd: &str, rule: &str) {
    if !cfg.security.approval_cache || !eligible(rule) {
        return;
    }
    // Idempotent while a valid entry exists: the TTL is anchored at the
    // ORIGINAL human approval. Every cache hit re-runs a token-carrying
    // `vallum run` that lands back here — appending again would both
    // duplicate the line and silently roll the expiry forward, turning
    // "valid for 14 days after a human said yes" into "valid forever for a
    // daily command". An EXPIRED entry does not block a fresh re-approval.
    if lookup(cfg, cmd, cwd, rule) {
        return;
    }
    let Some(secret) = crate::approval::load_or_create_secret(cfg) else {
        return;
    };
    let Some(path) = approvals_path(cfg) else {
        return;
    };
    let ts = now_unix();
    let entry = Entry {
        v: 1,
        ts,
        cwd: cwd.to_string(),
        rule: rule.to_string(),
        cmd: cmd.to_string(),
        mac: mac_for(cmd, cwd, rule, ts, &secret),
    };
    let Ok(line) = serde_json::to_string(&entry) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = crate::fsutil::open_append_private(&path) {
        use std::io::Write;
        let _ = crate::fsutil::lock_exclusive(&f);
        let _ = writeln!(f, "{line}");
    }
}

/// True when a valid, unexpired cached approval exists for exactly this
/// command + cwd + rule. Read-only: never creates the secret or the file.
pub fn lookup(cfg: &AppConfig, cmd: &str, cwd: &str, rule: &str) -> bool {
    if !cfg.security.approval_cache || !eligible(rule) {
        return false;
    }
    let Some(secret) = crate::approval::load_secret(cfg) else {
        return false;
    };
    let Some(path) = approvals_path(cfg) else {
        return false;
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        return false;
    };
    let now = now_unix();
    let ttl = ttl_secs(cfg);
    body.lines().any(|line| {
        serde_json::from_str::<Entry>(line).is_ok_and(|e| {
            e.cmd == cmd && e.cwd == cwd && e.rule == rule && entry_valid(&e, now, ttl, &secret)
        })
    })
}

/// Valid, unexpired entries; rewrites the file in place (under the lock) with
/// only those, pruning expired/forged/corrupt lines. Without a readable
/// secret nothing can be verified: returns empty and leaves the file alone.
pub fn list_and_prune(cfg: &AppConfig) -> Vec<ListedEntry> {
    let Some(secret) = crate::approval::load_secret(cfg) else {
        return Vec::new();
    };
    let Some(path) = approvals_path(cfg) else {
        return Vec::new();
    };
    let Ok(file) = crate::fsutil::open_rw_private(&path) else {
        return Vec::new();
    };
    if crate::fsutil::lock_exclusive(&file).is_err() {
        return Vec::new();
    }
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut body = String::new();
    if (&file).read_to_string(&mut body).is_err() {
        return Vec::new();
    }
    let now = now_unix();
    let ttl = ttl_secs(cfg);
    let mut kept_lines = String::new();
    let mut kept = Vec::new();
    for line in body.lines() {
        let Ok(e) = serde_json::from_str::<Entry>(line) else {
            continue;
        };
        if entry_valid(&e, now, ttl, &secret) {
            kept_lines.push_str(line);
            kept_lines.push('\n');
            kept.push(ListedEntry {
                ts: e.ts,
                rule: e.rule,
                cwd: e.cwd,
                cmd: e.cmd,
            });
        }
    }
    let mut f = &file;
    if f.seek(SeekFrom::Start(0)).is_ok() && file.set_len(0).is_ok() {
        let _ = f.write_all(kept_lines.as_bytes());
        let _ = f.flush();
    }
    kept
}

/// Remove all cached approvals. Returns how many non-empty lines were removed
/// (0 when the file did not exist).
pub fn clear(cfg: &AppConfig) -> std::io::Result<u64> {
    let Some(path) = approvals_path(cfg) else {
        return Ok(0);
    };
    match std::fs::read_to_string(&path) {
        Ok(body) => {
            let n = body.lines().filter(|l| !l.trim().is_empty()).count() as u64;
            std::fs::remove_file(&path)?;
            Ok(n)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_dir(dir: &std::path::Path) -> AppConfig {
        let mut cfg = AppConfig::default();
        cfg.audit.log_dir = Some(dir.to_path_buf());
        cfg
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "vallum_approvals_{}_{}_{}",
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
    fn record_then_lookup_roundtrip() {
        let dir = temp_dir("roundtrip");
        let cfg = cfg_with_dir(&dir);
        record(&cfg, "git push --force", "/repo", "git_push_force");
        assert!(lookup(&cfg, "git push --force", "/repo", "git_push_force"));
        // Different command, cwd, or rule → miss.
        assert!(!lookup(
            &cfg,
            "git push --force origin x",
            "/repo",
            "git_push_force"
        ));
        assert!(!lookup(
            &cfg,
            "git push --force",
            "/other",
            "git_push_force"
        ));
        assert!(!lookup(
            &cfg,
            "git push --force",
            "/repo",
            "git_clean_force"
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_is_idempotent_while_a_valid_entry_exists() {
        let dir = temp_dir("idem");
        let cfg = cfg_with_dir(&dir);
        record(&cfg, "git push --force", "/repo", "git_push_force");
        let path = approvals_path(&cfg).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        assert_eq!(first.lines().count(), 1);
        // A cache-hit token run re-enters record() on every use: it must
        // neither duplicate the line nor roll the ts (TTL anchors at the
        // original human approval).
        record(&cfg, "git push --force", "/repo", "git_push_force");
        let second = std::fs::read_to_string(&path).unwrap();
        assert_eq!(second, first, "no duplicate line, no ts refresh");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ineligible_rule_is_never_recorded_or_found() {
        let dir = temp_dir("inelig");
        let cfg = cfg_with_dir(&dir);
        record(&cfg, "cat /etc/shadow", "/repo", "read_sensitive_creds");
        assert!(
            approvals_path(&cfg).map(|p| !p.exists()).unwrap_or(true),
            "ineligible record must not create the file"
        );
        assert!(!lookup(
            &cfg,
            "cat /etc/shadow",
            "/repo",
            "read_sensitive_creds"
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_cache_noops() {
        let dir = temp_dir("disabled");
        let mut cfg = cfg_with_dir(&dir);
        cfg.security.approval_cache = false;
        record(&cfg, "git push --force", "/repo", "git_push_force");
        assert!(!lookup(&cfg, "git push --force", "/repo", "git_push_force"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lookup_without_secret_is_false_and_creates_nothing() {
        let dir = temp_dir("nosecret");
        let cfg = cfg_with_dir(&dir);
        assert!(!lookup(&cfg, "git push --force", "/repo", "git_push_force"));
        assert!(
            !dir.join("approval.secret").exists(),
            "lookup must not mint a secret"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_entry_is_a_miss() {
        let dir = temp_dir("tamper");
        let cfg = cfg_with_dir(&dir);
        record(&cfg, "git push --force", "/repo", "git_push_force");
        let path = approvals_path(&cfg).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        // Swap the recorded command for another one without re-MACing.
        let forged = body.replace("git push --force", "git push --force origin prod");
        std::fs::write(&path, forged).unwrap();
        assert!(!lookup(
            &cfg,
            "git push --force origin prod",
            "/repo",
            "git_push_force"
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_entry_is_a_miss_and_pruned() {
        let dir = temp_dir("expired");
        let cfg = cfg_with_dir(&dir);
        let secret = crate::approval::load_or_create_secret(&cfg).unwrap();
        let old_ts = now_unix() - ttl_secs(&cfg) - 10;
        let e = Entry {
            v: 1,
            ts: old_ts,
            cwd: "/repo".into(),
            rule: "git_push_force".into(),
            cmd: "git push --force".into(),
            mac: mac_for(
                "git push --force",
                "/repo",
                "git_push_force",
                old_ts,
                &secret,
            ),
        };
        let path = approvals_path(&cfg).unwrap();
        std::fs::write(&path, format!("{}\n", serde_json::to_string(&e).unwrap())).unwrap();
        assert!(!lookup(&cfg, "git push --force", "/repo", "git_push_force"));
        assert!(list_and_prune(&cfg).is_empty());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "",
            "expired entry pruned"
        );
        // An expired entry never blocks a fresh human re-approval.
        record(&cfg, "git push --force", "/repo", "git_push_force");
        assert!(lookup(&cfg, "git push --force", "/repo", "git_push_force"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_lines_are_skipped_valid_ones_survive() {
        let dir = temp_dir("corrupt");
        let cfg = cfg_with_dir(&dir);
        record(&cfg, "git push --force", "/repo", "git_push_force");
        let path = approvals_path(&cfg).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("not-json\n{body}")).unwrap();
        assert!(lookup(&cfg, "git push --force", "/repo", "git_push_force"));
        let kept = list_and_prune(&cfg);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].cmd, "git push --force");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_removes_all_and_reports_count() {
        let dir = temp_dir("clear");
        let cfg = cfg_with_dir(&dir);
        record(&cfg, "git push --force", "/repo", "git_push_force");
        record(&cfg, "git clean -fd", "/repo", "git_clean_force");
        assert_eq!(clear(&cfg).unwrap(), 2);
        assert_eq!(clear(&cfg).unwrap(), 0, "second clear finds nothing");
        assert!(!lookup(&cfg, "git push --force", "/repo", "git_push_force"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
