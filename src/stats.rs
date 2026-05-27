// src/stats.rs
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
struct Record {
    cmd: String,
    args: Vec<String>,
    tokens_before: usize,
    tokens_after: usize,
}

pub struct Report {
    pub total_commands: usize,
    pub total_before: usize,
    pub total_after: usize,
    /// (display_label, saved_tokens, before_total)
    pub by_command: Vec<(String, usize, usize)>,
}

pub fn aggregate(path: &Path) -> std::io::Result<Report> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            return Ok(Report {
                total_commands: 0,
                total_before: 0,
                total_after: 0,
                by_command: Vec::new(),
            });
        }
    };

    let mut total_before = 0usize;
    let mut total_after = 0usize;
    let mut total_commands = 0usize;
    let mut by_cmd: HashMap<String, (usize, usize)> = HashMap::new();

    for line in content.lines() {
        if let Ok(rec) = serde_json::from_str::<Record>(line) {
            total_before += rec.tokens_before;
            total_after += rec.tokens_after;
            total_commands += 1;

            let key = if rec.args.is_empty() {
                rec.cmd.clone()
            } else {
                format!("{} {}", rec.cmd, rec.args.join(" "))
            };
            let entry = by_cmd.entry(key).or_insert((0, 0));
            entry.0 += rec.tokens_before;
            entry.1 += rec.tokens_after;
        }
    }

    let mut by_command: Vec<(String, usize, usize)> = by_cmd
        .into_iter()
        .map(|(k, (b, a))| (k, b.saturating_sub(a), b))
        .collect();
    by_command.sort_by_key(|r| std::cmp::Reverse(r.1));

    Ok(Report {
        total_commands,
        total_before,
        total_after,
        by_command,
    })
}

pub fn print_report(r: &Report) {
    let saved = r.total_before.saturating_sub(r.total_after);
    let pct = if r.total_before > 0 {
        (saved as f64 / r.total_before as f64) * 100.0
    } else {
        0.0
    };

    println!("Vallum — Token savings report");
    println!("─────────────────────────────────────────");
    println!("Commands run:        {}", r.total_commands);
    println!("Tokens (raw):        {}", r.total_before);
    println!("Tokens (sanitized):  {}", r.total_after);
    println!("Saved:               {}  ({:.1}%)", saved, pct);

    if r.by_command.is_empty() {
        return;
    }

    println!();
    println!("Top savings by command");
    println!("─────────────────────────────────────────");
    for (label, saved, before) in r.by_command.iter().take(5) {
        let p = if *before > 0 {
            (*saved as f64 / *before as f64) * 100.0
        } else {
            0.0
        };
        println!("{:24} {:>8} saved  ({:.0}%)", label, saved, p);
    }
}

pub fn reset(path: &Path) -> std::io::Result<()> {
    println!(
        "This will delete all stats at {:?}. Type 'reset' to confirm.",
        path
    );
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() == "reset" {
        if path.exists() {
            fs::remove_file(path).ok();
        }
        println!("Stats cleared.");
    } else {
        println!("Cancelled.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_savings_total() {
        let tmp = std::env::temp_dir().join("vallum_test_stats_total");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("stats.jsonl");
        fs::write(
            &path,
            "{\"ts\":\"x\",\"cmd\":\"ls\",\"args\":[],\"tokens_before\":100,\"tokens_after\":40,\"optimizer\":null,\"exit_code\":0}\n\
             {\"ts\":\"x\",\"cmd\":\"git\",\"args\":[\"status\"],\"tokens_before\":500,\"tokens_after\":50,\"optimizer\":\"git_status\",\"exit_code\":0}\n",
        )
        .unwrap();

        let report = aggregate(&path).unwrap();
        assert_eq!(report.total_commands, 2);
        assert_eq!(report.total_before, 600);
        assert_eq!(report.total_after, 90);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn tolerant_parse_skips_corrupt_lines() {
        let tmp = std::env::temp_dir().join("vallum_test_stats_corrupt");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("stats.jsonl");
        fs::write(
            &path,
            "{\"ts\":\"x\",\"cmd\":\"ls\",\"args\":[],\"tokens_before\":100,\"tokens_after\":40,\"optimizer\":null,\"exit_code\":0}\n\
             this is not valid json\n\
             {\"ts\":\"x\",\"cmd\":\"pwd\",\"args\":[],\"tokens_before\":10,\"tokens_after\":5,\"optimizer\":null,\"exit_code\":0}\n",
        )
        .unwrap();

        let report = aggregate(&path).unwrap();
        assert_eq!(report.total_commands, 2);
        assert_eq!(report.total_before, 110);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn top_n_sorted_by_absolute_savings() {
        let tmp = std::env::temp_dir().join("vallum_test_stats_topn");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("stats.jsonl");
        fs::write(
            &path,
            "{\"ts\":\"x\",\"cmd\":\"ls\",\"args\":[],\"tokens_before\":10,\"tokens_after\":2,\"optimizer\":null,\"exit_code\":0}\n\
             {\"ts\":\"x\",\"cmd\":\"git\",\"args\":[\"status\"],\"tokens_before\":1000,\"tokens_after\":100,\"optimizer\":\"git_status\",\"exit_code\":0}\n",
        )
        .unwrap();

        let report = aggregate(&path).unwrap();
        assert_eq!(report.by_command[0].0, "git status");
        assert!(report.by_command[0].1 > report.by_command[1].1);
        let _ = fs::remove_dir_all(&tmp);
    }
}
