// src/executor.rs
use std::process::{Command, Stdio};

pub fn execute_command(cmd: &str, args: &[String]) -> Result<(String, i32), String> {
    let child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn command: {}", e))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait: {}", e))?;

    let mut result = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    if !stderr_str.is_empty() {
        result.push_str(&stderr_str);
    }

    let exit_code = output.status.code().unwrap_or(1);

    // For MVP, we'll just return the combined output. Later we'll implement streaming.
    Ok((result, exit_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_echo() {
        let (output, exit_code) = execute_command("echo", &["hello".to_string()]).unwrap();
        assert_eq!(output, "hello\n");
        assert_eq!(exit_code, 0);
    }
}
