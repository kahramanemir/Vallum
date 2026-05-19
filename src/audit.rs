// src/audit.rs
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;

pub fn write_log(filename: &str, cmd_context: &str, output: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    let timestamp = Local::now().to_rfc3339();
    let log_entry = format!(
        "[{}]\nCommand: {}\nOutput:\n{}\n---------------------------\n",
        timestamp, cmd_context, output
    );

    file.write_all(log_entry.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_log_writing() {
        let test_file = "test_raw.log";
        let _ = fs::remove_file(test_file);
        write_log(test_file, "ls", "raw output").unwrap();

        let content = fs::read_to_string(test_file).unwrap();
        assert!(content.contains("Command: ls"));
        assert!(content.contains("raw output"));
        let _ = fs::remove_file(test_file);
    }
}
