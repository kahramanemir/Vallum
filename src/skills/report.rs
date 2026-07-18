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
    for w in &report.warnings {
        eprintln!("skills scan: {}", safe(w));
    }
    print!("{}", render_human_to(report, usage_error));
}

/// The stdout portion of the human report, as text. Split from `render_human`
/// so tests can assert on the rendered output without capturing stdout.
fn render_human_to(report: &ScanReport, usage_error: bool) -> String {
    use std::fmt::Write;
    let use_color = color_enabled();
    let mut out = String::new();

    if report.findings.is_empty() {
        // Suppress the clean line under a usage error so a partial scan cannot
        // read as a green result.
        if !usage_error && report.files_scanned > 0 {
            out.push_str("No issues found.\n");
        }
        // The skip count is a factual tally, not a verdict — it prints whenever
        // binaries were skipped, even under a usage error.
        if report.binary_skipped > 0 {
            let _ = writeln!(out, "  ({} binary file(s) skipped)", report.binary_skipped);
        }
        return out;
    }

    let _ = writeln!(
        out,
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
    if report.binary_skipped > 0 {
        let _ = writeln!(out, "  ({} binary file(s) skipped)", report.binary_skipped);
    }
    for f in &report.findings {
        let _ = writeln!(
            out,
            "  [{}] {} ({}): {}",
            severity_label(f.severity),
            safe(&f.doc),
            safe(&f.file.display().to_string()),
            safe(&f.detail),
        );
    }
    out
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    file: String,
    doc: &'a str,
    doc_kind: &'a crate::skills::model::DocKind,
    check: &'a crate::skills::CheckKind,
    severity: &'a Severity,
    detail: &'a str,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    files_scanned: usize,
    docs: usize,
    usage_error: bool,
    binary_skipped: usize,
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
            doc_kind: &f.doc_kind,
            check: &f.check,
            severity: &f.severity,
            detail: &f.detail,
        })
        .collect();
    let out = JsonReport {
        files_scanned: report.files_scanned,
        docs: report.docs,
        usage_error,
        binary_skipped: report.binary_skipped,
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

    fn clean_report(binary_skipped: usize) -> ScanReport {
        ScanReport {
            files_scanned: 1,
            docs: 1,
            findings: vec![],
            warnings: vec![],
            binary_skipped,
        }
    }

    #[test]
    fn clean_scan_with_binary_skips_prints_count() {
        let text = render_human_to(&clean_report(1), false);
        assert!(text.contains("No issues found."));
        assert!(
            text.contains("(1 binary file(s) skipped)"),
            "skip count must print on clean scans too: {text:?}"
        );
    }

    #[test]
    fn clean_scan_without_binary_skips_has_no_count_line() {
        let text = render_human_to(&clean_report(0), false);
        assert!(text.contains("No issues found."));
        assert!(!text.contains("binary file(s) skipped"), "{text:?}");
    }

    #[test]
    fn usage_error_suppresses_clean_line_but_not_skip_count() {
        let text = render_human_to(&clean_report(2), true);
        assert!(
            !text.contains("No issues found."),
            "false-green suppression must stay: {text:?}"
        );
        assert!(
            text.contains("(2 binary file(s) skipped)"),
            "count is a factual tally, not a verdict: {text:?}"
        );
    }
}
