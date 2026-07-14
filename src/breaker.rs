//! Blast-radius circuit breaker: counts guardrail Ask/Deny verdicts in a
//! sliding window (state file under flock); past the threshold, every
//! command is denied until the cooldown expires or `vallum unlock`.

use chrono::{DateTime, Duration, Local};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

/// An active lock: commands are denied until `until`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trip {
    pub until: String, // rfc3339
    pub threshold: u32,
    pub window_secs: u64,
}

/// Resolve the state file the same way every other Vallum state/log file
/// resolves: `[audit] log_dir` override, else ~/.vallum/logs.
pub fn state_path(cfg: &crate::config::AppConfig) -> PathBuf {
    crate::audit::resolve_log_path("breaker.state", cfg.audit.log_dir.as_deref())
}

/// Parsed state: in-window verdict timestamps + active lock expiry.
/// Malformed and out-of-window lines are dropped (self-healing).
fn parse_and_prune(
    content: &str,
    now: DateTime<Local>,
    window_secs: u64,
) -> (Vec<DateTime<Local>>, Option<DateTime<Local>>) {
    let cutoff = now - Duration::seconds(window_secs as i64);
    let mut events = Vec::new();
    let mut lock: Option<DateTime<Local>> = None;
    for line in content.lines() {
        if let Some(ts) = line.strip_prefix("v ") {
            if let Ok(t) = DateTime::parse_from_rfc3339(ts.trim()) {
                let t = t.with_timezone(&Local);
                if t > cutoff {
                    events.push(t);
                }
            }
        } else if let Some(ts) = line.strip_prefix("locked ") {
            if let Ok(t) = DateTime::parse_from_rfc3339(ts.trim()) {
                let t = t.with_timezone(&Local);
                if t > now && lock.is_none() {
                    lock = Some(t);
                }
            }
        }
        // Anything else: malformed — dropped.
    }
    (events, lock)
}

fn render(events: &[DateTime<Local>], lock: Option<&DateTime<Local>>) -> String {
    let mut out = String::new();
    for e in events {
        out.push_str(&format!("v {}\n", e.to_rfc3339()));
    }
    if let Some(l) = lock {
        out.push_str(&format!("locked {}\n", l.to_rfc3339()));
    }
    out
}

/// Read-only trip probe. Missing/unreadable file → None (fail-open here is
/// deliberate: a broken state file must not brick every command; recording
/// self-heals it on the next verdict).
pub fn active_trip_at(path: &Path, threshold: u32, window_secs: u64) -> Option<Trip> {
    let content = std::fs::read_to_string(path).ok()?;
    let (_, lock) = parse_and_prune(&content, Local::now(), window_secs);
    lock.map(|until| Trip {
        until: until.to_rfc3339(),
        threshold,
        window_secs,
    })
}

/// Record one Ask/Deny verdict under an exclusive flock; prune; trip when
/// the in-window count reaches `threshold` and no lock is active. Returns
/// `Some(Trip)` exactly when THIS call created the lock.
pub fn record_at(
    path: &Path,
    threshold: u32,
    window_secs: u64,
    cooldown_secs: u64,
) -> std::io::Result<Option<Trip>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = crate::fsutil::open_rw_private(path)?;
    crate::fsutil::lock_exclusive(&file)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let now = Local::now();
    let (mut events, lock) = parse_and_prune(&content, now, window_secs);
    events.push(now);
    let tripped = if lock.is_none() && events.len() as u32 >= threshold {
        Some(now + Duration::seconds(cooldown_secs as i64))
    } else {
        None
    };
    let effective = tripped.or(lock);
    let rendered = render(&events, effective.as_ref());
    file.seek(std::io::SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(rendered.as_bytes())?;
    Ok(tripped.map(|until| Trip {
        until: until.to_rfc3339(),
        threshold,
        window_secs,
    }))
}

/// Remove an active lock (flocked). `Ok(Some(expiry))` = a lock was cleared.
pub fn unlock_at(path: &Path) -> Result<Option<String>, String> {
    match path.try_exists() {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(e) => return Err(format!("stat {}: {e}", path.display())),
    }
    let mut file = crate::fsutil::open_rw_private(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    crate::fsutil::lock_exclusive(&file).map_err(|e| format!("lock {}: {e}", path.display()))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let now = Local::now();
    // Unlock is a deliberate human action — grant a fresh window, so a new
    // burst still re-trips but the old (already-punished) one doesn't. We only
    // need the lock here; the in-window events are discarded on purpose.
    let (_events, lock) = parse_and_prune(&content, now, 86_400);
    let rendered = render(&[], None);
    file.seek(std::io::SeekFrom::Start(0))
        .and_then(|_| file.set_len(0))
        .and_then(|_| file.write_all(rendered.as_bytes()))
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(lock.map(|l| l.to_rfc3339()))
}

/// Cfg-level probe used on every command.
pub fn active_trip(cfg: &crate::config::AppConfig) -> Option<Trip> {
    if !cfg.security.circuit_breaker {
        return None;
    }
    active_trip_at(
        &state_path(cfg),
        cfg.security.breaker_threshold,
        cfg.security.breaker_window_secs,
    )
}

/// Cfg-level recorder used on every Ask/Deny verdict. Best-effort; a trip
/// is also written to policy.log (rule `circuit_breaker`) for forensics.
pub fn record_and_check(cfg: &crate::config::AppConfig) {
    if !cfg.security.circuit_breaker {
        return;
    }
    let tripped = record_at(
        &state_path(cfg),
        cfg.security.breaker_threshold,
        cfg.security.breaker_window_secs,
        cfg.security.breaker_cooldown_secs,
    )
    .ok()
    .flatten();
    if let Some(trip) = tripped {
        let verdict = crate::policy::PolicyVerdict {
            action: crate::policy::PolicyAction::Deny,
            reason: trip_reason(&trip),
            rule_name: "circuit_breaker".to_string(),
        };
        crate::policy::audit::log_verdict(&verdict, "(circuit breaker tripped)", "breaker", cfg);
    }
}

/// Cfg-level unlock used by `vallum unlock`.
pub fn unlock(cfg: &crate::config::AppConfig) -> Result<Option<String>, String> {
    unlock_at(&state_path(cfg))
}

/// The deny reason shown for every command while locked.
pub fn trip_reason(trip: &Trip) -> String {
    format!(
        "circuit breaker: {} dangerous-command attempts within {}s — all \
         commands blocked until {} (run `vallum unlock` to clear now)",
        trip.threshold, trip.window_secs, trip.until
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Local};

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vallum_breaker_{tag}_{}_{}",
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
    fn records_accumulate_and_trip_at_threshold() {
        let dir = tmp("trip");
        let p = dir.join("breaker.state");
        for i in 0..4 {
            assert!(
                record_at(&p, 5, 60, 300).unwrap().is_none(),
                "must not trip at event {}",
                i + 1
            );
            assert!(active_trip_at(&p, 5, 60).is_none());
        }
        let trip = record_at(&p, 5, 60, 300).unwrap().expect("5th event trips");
        assert_eq!(trip.threshold, 5);
        assert!(active_trip_at(&p, 5, 60).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn window_prunes_old_events() {
        let dir = tmp("prune");
        let p = dir.join("breaker.state");
        // 4 events well outside a 60s window + 1 fresh one → no trip.
        let old = (Local::now() - Duration::seconds(3600)).to_rfc3339();
        let mut s = String::new();
        for _ in 0..4 {
            s.push_str(&format!("v {old}\n"));
        }
        std::fs::write(&p, s).unwrap();
        assert!(record_at(&p, 5, 60, 300).unwrap().is_none());
        // Pruned: only the fresh event remains on disk.
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_lock_clears_itself() {
        let dir = tmp("expire");
        let p = dir.join("breaker.state");
        let past = (Local::now() - Duration::seconds(10)).to_rfc3339();
        std::fs::write(&p, format!("locked {past}\n")).unwrap();
        assert!(active_trip_at(&p, 5, 60).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_double_trip_while_locked() {
        let dir = tmp("double");
        let p = dir.join("breaker.state");
        let future = (Local::now() + Duration::seconds(300)).to_rfc3339();
        std::fs::write(&p, format!("locked {future}\n")).unwrap();
        // Recording while locked neither re-trips nor duplicates the lock.
        assert!(record_at(&p, 1, 60, 300).unwrap().is_none());
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            text.lines().filter(|l| l.starts_with("locked ")).count(),
            1,
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_removes_lock_and_reports() {
        let dir = tmp("unlock");
        let p = dir.join("breaker.state");
        let future = (Local::now() + Duration::seconds(300)).to_rfc3339();
        std::fs::write(
            &p,
            format!("v {}\nlocked {future}\n", Local::now().to_rfc3339()),
        )
        .unwrap();
        let cleared = unlock_at(&p).unwrap();
        assert_eq!(cleared, Some(future));
        assert!(active_trip_at(&p, 5, 60).is_none());
        // Unlock resets the event counter too: a fresh window, not an
        // instant re-trip from the old burst.
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            !text.contains("v "),
            "unlock must clear in-window events: {text}"
        );
        // Second unlock: nothing to clear.
        assert_eq!(unlock_at(&p).unwrap(), None);
        // Absent file: also fine.
        assert_eq!(unlock_at(&dir.join("nope.state")).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_lines_are_dropped_not_fatal() {
        let dir = tmp("malformed");
        let p = dir.join("breaker.state");
        std::fs::write(&p, "garbage\nv not-a-date\nlocked also-bad\n").unwrap();
        assert!(active_trip_at(&p, 5, 60).is_none());
        assert!(record_at(&p, 5, 60, 300).unwrap().is_none());
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            text.lines().count(),
            1,
            "only the fresh event survives: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_records_trip_exactly_once() {
        let dir = tmp("conc");
        let p = dir.join("breaker.state");
        let mut handles = Vec::new();
        let trips = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for _ in 0..8 {
            let p = p.clone();
            let trips = trips.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..5 {
                    if record_at(&p, 10, 60, 300).unwrap().is_some() {
                        trips.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(trips.load(std::sync::atomic::Ordering::SeqCst), 1);
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(
            text.lines().filter(|l| l.starts_with("locked ")).count(),
            1,
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
