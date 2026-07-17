//! Human and JSON renderers for a skills `ScanReport`. Mirrors mcp/report.rs:
//! control chars in untrusted doc-derived text are escaped, and color is gated
//! on an interactive stdout.

use crate::skills::{ScanReport, Severity};
use serde::Serialize;

fn color_enabled() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM")
            .map(|t| t != "dumb")
            .unwrap_or(true)
}

fn header(text: &str, use_color: bool) -> String {
    if use_color {
        format!("\x1b[1;38;5;178m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Escape control characters before printing untrusted, file-derived text.
/// The scan's whole job is to look at attacker-controlled files; without this a
/// crafted line could emit escape sequences and forge a clean verdict.
fn safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::High => "HIGH",
        Severity::Warning => "warn",
    }
}

pub fn render_human(report: &ScanReport, usage_error: bool) {
    let use_color = color_enabled();

    for w in &report.warnings {
        eprintln!("skills scan: {}", safe(w));
    }

    if report.findings.is_empty() {
        // Suppress the clean line under a usage error so a partial scan cannot
        // read as a green result.
        if !usage_error && report.files_scanned > 0 {
            println!("No issues found.");
        }
        return;
    }

    println!(
        "{}",
        header(
            &format!(
                "Scanned {} file(s), {} doc(s) — {} finding(s):",
                report.files_scanned,
                report.docs,
                report.findings.len()
            ),
            use_color
        )
    );
    for f in &report.findings {
        println!(
            "  [{}] {} ({}): {}",
            severity_label(f.severity),
            safe(&f.doc),
            safe(&f.file.display().to_string()),
            safe(&f.detail),
        );
    }
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    file: String,
    doc: &'a str,
    check: &'a crate::skills::CheckKind,
    severity: &'a Severity,
    detail: &'a str,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    files_scanned: usize,
    docs: usize,
    usage_error: bool,
    findings: Vec<JsonFinding<'a>>,
    warnings: &'a [String],
}

pub fn render_json(report: &ScanReport, usage_error: bool) {
    let findings: Vec<JsonFinding> = report
        .findings
        .iter()
        .map(|f| JsonFinding {
            file: f.file.display().to_string(),
            doc: &f.doc,
            check: &f.check,
            severity: &f.severity,
            detail: &f.detail,
        })
        .collect();
    let out = JsonReport {
        files_scanned: report.files_scanned,
        docs: report.docs,
        usage_error,
        findings,
        warnings: &report.warnings,
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_chars_are_escaped() {
        // A doc name that tries to clear the screen and forge a clean verdict.
        let escaped = safe("x\x1b[2J\x1b[HNo issues found.");
        assert!(!escaped.contains('\x1b'));
        assert!(escaped.contains("\\x1b"));
    }
}
