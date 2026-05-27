// src/executor.rs
use std::io::{BufRead, BufReader, Read};
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
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    // Lossy UTF-8 (matches the old from_utf8_lossy behavior); a single
                    // invalid byte must not abort capture.
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

pub fn execute_command(
    cmd: &str,
    args: &[String],
    max_output_bytes: usize,
    timeout_secs: u64,
) -> Result<(String, i32), String> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
    );
    let h_err = spawn_reader(
        stderr,
        Arc::clone(&collected),
        Arc::clone(&seq),
        Arc::clone(&total_bytes),
        max_output_bytes,
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
                        let _ = child.kill();
                        let _ = child.wait();
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
            execute_command("echo", &["hello".to_string()], 10 * 1024 * 1024, 0).unwrap();
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
        )
        .unwrap();
        assert_eq!(code, 7);
    }

    #[test]
    fn test_output_cap_marks_truncation() {
        // `seq 1 1000` is well over 100 bytes.
        let (out, _code) =
            execute_command("sh", &["-c".to_string(), "seq 1 1000".to_string()], 100, 0).unwrap();
        assert!(out.contains("[output capped at 100 bytes]"));
        // Stored body stays bounded near the cap (allow slack for the marker).
        assert!(out.len() < 400);
    }

    #[test]
    fn test_timeout_kills_child() {
        let start = std::time::Instant::now();
        let (out, code) = execute_command(
            "sh",
            &["-c".to_string(), "sleep 5".to_string()],
            10 * 1024 * 1024,
            1,
        )
        .unwrap();
        assert_eq!(code, 124);
        assert!(out.contains("[timed out after 1s]"));
        assert!(start.elapsed().as_secs() < 4);
    }
}
