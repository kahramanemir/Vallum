//! Human and JSON renderers for a `ScanReport`.

use crate::mcp::{Finding, ScanReport};
use serde::Serialize;

/// Bronze section header, matching the CLI help palette. Plain when color is
/// off (piped output, `NO_COLOR`, or `TERM=dumb`) — same policy as the welcome
/// screen and the install picker.
fn header(text: &str, use_color: bool) -> String {
    if use_color {
        format!("\x1b[1;38;5;178m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Color only on an interactive stdout with `NO_COLOR` unset and `TERM != dumb`.
fn color_enabled() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM")
            .map(|t| t != "dumb")
            .unwrap_or(true)
}

/// Escape control characters before printing untrusted config-derived text
/// (server names, env keys) to the terminal. The scan's whole job is to look
/// at attacker-controlled MCP configs; without this, a server named
/// `x\x1b[2J\x1b[HNo issues found.` could clear the screen and forge a clean
/// verdict in the human output. This is display hygiene, not detection.
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

pub fn render_human(report: &ScanReport, usage_error: bool) {
    if report.files_scanned == 0 && report.warnings.is_empty() {
        // Nothing was successfully scanned. On a usage error the specific cause
        // already went to stderr, so stay silent rather than print a reassuring
        // "No MCP configuration found." that reads like a clean result.
        if !usage_error {
            println!("No MCP configuration found.");
        }
        return;
    }
    let use_color = color_enabled();
    println!(
        "{}",
        header(
            &format!(
                "Scanned {} file(s), {} server(s)",
                report.files_scanned, report.servers
            ),
            use_color
        )
    );
    for w in &report.warnings {
        println!("  warning: {}", safe(w));
    }
    if report.findings.is_empty() {
        // Don't claim a clean result when a usage error (e.g. a malformed
        // explicit path) meant we couldn't fully complete the scan — the
        // warning above already carried the cause and the exit code is 125.
        if !usage_error {
            println!("No issues found.");
        }
        return;
    }
    // Group by server for display.
    let mut sorted: Vec<&Finding> = report.findings.iter().collect();
    sorted.sort_by(|a, b| a.server.cmp(&b.server));
    let mut current = "";
    for f in sorted {
        if f.server != current {
            println!("\n{}", header(&safe(&f.server), use_color));
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
        println!("  [{sev}] {check}: {}", safe(&f.detail));
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

pub fn render_json(report: &ScanReport, usage_error: bool) {
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
            // A usage/read error (exit 125) is not a clean result, even when no
            // findings were produced — never report clean:true alongside 125.
            clean: report.findings.is_empty() && !usage_error,
            warnings: report.findings.len() - high,
            high,
        },
    };
    match serde_json::to_string(&out) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("mcp scan: JSON serialization failed: {e}"),
    }
}
