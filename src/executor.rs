//! Run the child command with concurrent capture, a byte cap, a timeout,
//! inherited stdin, and an optional live tee.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Exit code used when a command is killed for exceeding its timeout
/// (matches the convention of the `timeout(1)` utility).
const TIMEOUT_EXIT_CODE: i32 = 124;

type Collected = Arc<Mutex<Vec<(usize, String)>>>;

fn spawn_reader<R: Read + Send + 'static>(
    stream: R,
    collected: Collected,
    seq: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicUsize>,
    max_output_bytes: usize,
    tee: Option<Arc<Mutex<File>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    // Tee first (best effort): mirror raw bytes so a watcher
                    // sees everything the child produced, even lines that the
                    // byte cap will later drop.
                    if let Some(t) = tee.as_ref() {
                        if let Ok(mut f) = t.lock() {
                            let _ = f.write_all(&buf);
                        }
                    }

                    // Lossy UTF-8 (matches the old from_utf8_lossy behavior); a
                    // single invalid byte must not abort capture.
                    let line = String::from_utf8_lossy(&buf).into_owned();
                    let prev = total_bytes.fetch_add(line.len(), Ordering::SeqCst);
                    if prev + line.len() <= max_output_bytes {
                        let n = seq.fetch_add(1, Ordering::SeqCst);
                        collected.lock().unwrap().push((n, line));
                    }
                    // Over cap: keep draining so the child never blocks, but discard.
                }
                Err(_) => break,
            }
        }
    })
}

/// Forcefully terminate a timed-out child. On unix the child is its own
/// process-group leader (see the spawn in `execute_command`), so its PGID
/// equals its PID; signalling the negative PID kills the whole group —
/// grandchildren spawned via a shell included — which closes the captured
/// output pipes so the reader threads reach EOF promptly. On other platforms
/// we fall back to killing the direct child only.
fn kill_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        // Negative PID targets the entire process group. Errors (e.g. the group
        // already exited) are intentionally ignored.
        let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub fn execute_command(
    cmd: &str,
    args: &[String],
    max_output_bytes: usize,
    timeout_secs: u64,
    tee_path: Option<&Path>,
) -> Result<(String, i32), String> {
    let tee_file: Option<Arc<Mutex<File>>> = tee_path.and_then(|p| {
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!("vallum: tee disabled (mkdir {}: {})", parent.display(), e);
                    return None;
                }
            }
        }
        match crate::fsutil::open_append_private(p) {
            Ok(f) => Some(Arc::new(Mutex::new(f))),
            Err(e) => {
                eprintln!("vallum: tee disabled (open {}: {})", p.display(), e);
                None
            }
        }
    });

    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // On unix, run the child in its own process group so a timeout can kill the
    // whole tree. A shell like `sh -c 'sleep 30'` forks a grandchild; killing
    // only the direct child would orphan it, and it would keep the captured
    // output pipes open until it exits on its own — hanging the reader joins.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to spawn command: {}", e))?;

    let stdout = child.stdout.take().ok_or("missing stdout pipe")?;
    let stderr = child.stderr.take().ok_or("missing stderr pipe")?;

    let collected: Collected = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicUsize::new(0));
    let total_bytes = Arc::new(AtomicUsize::new(0));

    let h_out = spawn_reader(
        stdout,
        Arc::clone(&collected),
        Arc::clone(&seq),
        Arc::clone(&total_bytes),
        max_output_bytes,
        tee_file.as_ref().map(Arc::clone),
    );
    let h_err = spawn_reader(
        stderr,
        Arc::clone(&collected),
        Arc::clone(&seq),
        Arc::clone(&total_bytes),
        max_output_bytes,
        tee_file.as_ref().map(Arc::clone),
    );

    let timeout = if timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(timeout_secs))
    };
    let start = Instant::now();
    let mut timed_out = false;
    let exit_code;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code().unwrap_or(1);
                break;
            }
            Ok(None) => {
                if let Some(t) = timeout {
                    if start.elapsed() >= t {
                        kill_process_tree(&mut child);
                        timed_out = true;
                        exit_code = TIMEOUT_EXIT_CODE;
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("Failed to wait: {}", e)),
        }
    }

    // Reader threads finish once the pipes hit EOF (the kill above closes them).
    let _ = h_out.join();
    let _ = h_err.join();

    let mut lines = Arc::try_unwrap(collected)
        .map(|m| m.into_inner().unwrap())
        .unwrap_or_else(|arc| arc.lock().unwrap().clone());
    lines.sort_by_key(|(n, _)| *n);

    let mut result = String::new();
    for (_, line) in lines {
        result.push_str(&line);
    }

    if total_bytes.load(Ordering::SeqCst) > max_output_bytes {
        result.push_str(&format!(
            "\n[output capped at {} bytes]\n",
            max_output_bytes
        ));
    }
    if timed_out {
        result.push_str(&format!("\n[timed out after {}s]\n", timeout_secs));
    }

    Ok((result, exit_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_echo() {
        let (output, exit_code) =
            execute_command("echo", &["hello".to_string()], 10 * 1024 * 1024, 0, None).unwrap();
        assert_eq!(output, "hello\n");
        assert_eq!(exit_code, 0);
    }

    #[test]
    fn test_exit_code_propagates() {
        let (_out, code) = execute_command(
            "sh",
            &["-c".to_string(), "exit 7".to_string()],
            10 * 1024 * 1024,
            0,
            None,
        )
        .unwrap();
        assert_eq!(code, 7);
    }

    #[test]
    fn test_output_cap_marks_truncation() {
        // `seq 1 1000` is well over 100 bytes.
        let (out, _code) = execute_command(
            "sh",
            &["-c".to_string(), "seq 1 1000".to_string()],
            100,
            0,
            None,
        )
        .unwrap();
        assert!(out.contains("[output capped at 100 bytes]"));
        // Stored body stays bounded near the cap (allow slack for the marker).
        assert!(out.len() < 400);
    }

    #[test]
    fn test_timeout_kills_child() {
        // `sleep 30` would run for 30s if the timeout did nothing; with a 1s
        // timeout the child is killed early. The functional guarantee that the
        // timeout fired is `code == 124` plus the marker. The wall-clock bound
        // (< 15s) only proves we did NOT run to natural completion (30s); it is
        // intentionally generous because a tight bound is flaky under parallel
        // test contention on loaded CI runners, where the polling thread that
        // detects the 1s timeout can be starved for several seconds.
        let start = std::time::Instant::now();
        let (out, code) = execute_command(
            "sh",
            &["-c".to_string(), "sleep 30".to_string()],
            10 * 1024 * 1024,
            1,
            None,
        )
        .unwrap();
        assert_eq!(code, 124);
        assert!(out.contains("[timed out after 1s]"));
        assert!(
            start.elapsed().as_secs() < 15,
            "took {}s — timeout did not cut the command short",
            start.elapsed().as_secs()
        );
    }

    #[test]
    fn tee_writes_each_line_to_file_and_returns_normal_output() {
        use std::io::Read;
        let tmp = std::env::temp_dir().join(format!(
            "vallum_exec_tee_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let tee = tmp.join("live.log");

        let (out, code) = execute_command(
            "sh",
            &["-c".to_string(), "printf 'line1\\nline2\\n'".to_string()],
            10 * 1024 * 1024,
            0,
            Some(&tee),
        )
        .unwrap();

        assert_eq!(code, 0);
        assert!(out.contains("line1"));
        assert!(out.contains("line2"));

        let mut tee_contents = String::new();
        std::fs::File::open(&tee)
            .unwrap()
            .read_to_string(&mut tee_contents)
            .unwrap();
        assert!(tee_contents.contains("line1"));
        assert!(tee_contents.contains("line2"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn tee_open_failure_falls_back_to_capture() {
        // A path whose parent definitely cannot be created (under /dev/null/…)
        // should disable tee silently without breaking capture.
        let bad = std::path::PathBuf::from("/dev/null/vallum-tee-cannot-exist/live.log");
        let (out, code) = execute_command(
            "echo",
            &["hello".to_string()],
            10 * 1024 * 1024,
            0,
            Some(&bad),
        )
        .unwrap();
        assert_eq!(code, 0);
        assert!(out.contains("hello"));
    }
}
