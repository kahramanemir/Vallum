//! Human and JSON renderers for a `ScanReport`.

use crate::mcp::{Finding, ScanReport};
use serde::Serialize;

/// Bronze section header, matching the CLI help palette.
fn header(text: &str) -> String {
    format!("\x1b[1;38;5;178m{text}\x1b[0m")
}

pub fn render_human(report: &ScanReport) {
    if report.files_scanned == 0 && report.warnings.is_empty() {
        println!("No MCP configuration found.");
        return;
    }
    println!(
        "{}",
        header(&format!(
            "Scanned {} file(s), {} server(s)",
            report.files_scanned, report.servers
        ))
    );
    for w in &report.warnings {
        println!("  warning: {w}");
    }
    if report.findings.is_empty() {
        println!("No issues found.");
        return;
    }
    // Group by server for display.
    let mut sorted: Vec<&Finding> = report.findings.iter().collect();
    sorted.sort_by(|a, b| a.server.cmp(&b.server));
    let mut current = "";
    for f in sorted {
        if f.server != current {
            println!("\n{}", header(&f.server));
            current = &f.server;
        }
        let sev = match f.severity {
            crate::mcp::Severity::High => "HIGH",
            crate::mcp::Severity::Warning => "warn",
        };
        let check = match f.check {
            crate::mcp::CheckKind::EnvSecret => "env-secret",
            crate::mcp::CheckKind::LaunchCommand => "launch-command",
            crate::mcp::CheckKind::DescriptionInjection => "description-injection",
        };
        println!("  [{sev}] {check}: {}", f.detail);
    }
}

#[derive(Serialize)]
struct Summary {
    clean: bool,
    warnings: usize,
    high: usize,
}

#[derive(Serialize)]
struct JsonOut<'a> {
    files_scanned: usize,
    servers: usize,
    findings: &'a [Finding],
    warnings: &'a [String],
    summary: Summary,
}

pub fn render_json(report: &ScanReport) {
    let high = report
        .findings
        .iter()
        .filter(|f| f.severity == crate::mcp::Severity::High)
        .count();
    let out = JsonOut {
        files_scanned: report.files_scanned,
        servers: report.servers,
        findings: &report.findings,
        warnings: &report.warnings,
        summary: Summary {
            clean: report.findings.is_empty(),
            warnings: report.findings.len() - high,
            high,
        },
    };
    match serde_json::to_string(&out) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("mcp scan: JSON serialization failed: {e}"),
    }
}
