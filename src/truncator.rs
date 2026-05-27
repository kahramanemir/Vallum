pub fn smart_truncate(input: &str, head_limit: usize, tail_limit: usize) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let total_lines = lines.len();

    if total_lines <= head_limit + tail_limit {
        return input.to_string();
    }

    let mut result = String::new();
    let mut error_lines = Vec::new();
    let mut hidden_count = 0;

    for (i, line) in lines.iter().enumerate() {
        if i < head_limit {
            result.push_str(line);
            result.push('\n');
        } else if i >= total_lines - tail_limit {
            continue; // Will add at the end
        } else {
            if line.contains("Error") || line.contains("Exception") || line.contains("panic") {
                error_lines.push(*line);
            } else {
                hidden_count += 1;
            }
        }
    }

    if !error_lines.is_empty() {
        result.push_str(&format!("\n[IMPORTANT {} lines]\n", error_lines.len()));
        for err in error_lines {
            result.push_str(err);
            result.push('\n');
        }
    }

    if hidden_count > 0 {
        result.push_str(&format!("\n[... {} lines hidden ...]\n\n", hidden_count));
    }

    result.push_str(&format!("[TAIL {} lines]\n", tail_limit));
    for line in &lines[total_lines - tail_limit..total_lines] {
        result.push_str(line);
        result.push('\n');
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_short_output() {
        let input = "Line 1\nLine 2\nLine 3\n";
        assert_eq!(smart_truncate(input, 5, 5), input); // No change if lines < limit
    }

    #[test]
    fn test_truncate_long_output() {
        let input = "1\n2\n3\n4\n5\nError: Boom\n6\n7\n8\n9\n10\n11\n";
        // head: 2, tail: 2. Should keep error line.
        let result = smart_truncate(input, 2, 2);
        assert!(result.contains("1\n2\n"));
        assert!(result.contains("Error: Boom"));
        assert!(result.contains("10\n11\n"));
        assert!(result.contains("hidden"));
    }
}
