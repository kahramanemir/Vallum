//! Static MCP configuration scanner: discover config files and flag embedded
//! secrets, risky launch commands, and injection in embedded descriptions.
//! Read-only — connects to nothing, launches nothing, modifies nothing.

pub mod discover;
pub mod model;
pub mod scan;

pub use scan::{CheckKind, Finding, Severity};

pub mod report;

use crate::config::AppConfig;
use crate::policy::Policy;
use std::path::PathBuf;

/// The accumulated result of a scan across one or more config files.
pub struct ScanReport {
    pub files_scanned: usize,
    pub servers: usize,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

/// Exit code from findings: 0 clean, 10 warnings-class, 20 high-severity.
/// A usage/read error on an explicit path forces 125 and wins over findings.
pub fn exit_code(report: &ScanReport, usage_error: bool) -> i32 {
    if usage_error {
        return 125;
    }
    if report.findings.iter().any(|f| f.severity == Severity::High) {
        return 20;
    }
    if !report.findings.is_empty() {
        return 10;
    }
    0
}

/// Discover (or take explicit) MCP config files and scan each. Returns the
/// accumulated report and whether a usage error occurred (missing/unreadable/
/// malformed explicit path).
pub fn collect(explicit_paths: &[PathBuf], cfg: &AppConfig) -> (ScanReport, bool) {
    let mut usage_error = false;
    let targets: Vec<PathBuf> = if explicit_paths.is_empty() {
        discover::existing_config_paths()
    } else {
        let mut t = Vec::new();
        for p in explicit_paths {
            if p.exists() {
                t.push(p.clone());
            } else {
                eprintln!("mcp scan: {}: no such file", p.display());
                usage_error = true;
            }
        }
        t
    };

    // Compile the guardrail once (shared across files); None when disabled.
    let policy = if cfg.security.guardrail {
        Policy::compile(&cfg.policy).ok()
    } else {
        None
    };

    let mut report = ScanReport {
        files_scanned: 0,
        servers: 0,
        findings: Vec::new(),
        warnings: Vec::new(),
    };

    for path in &targets {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                report.files_scanned += 1;
                match model::parse_file(path, &text) {
                    Ok(servers) => {
                        report.servers += servers.len();
                        report
                            .findings
                            .extend(scan::scan_servers(&servers, policy.as_ref(), cfg));
                    }
                    Err(e) => {
                        report.warnings.push(format!("{}: {e}", path.display()));
                        // A malformed *explicit* path is a usage error (parallel
                        // to an unreadable one), so CI gets a non-zero exit
                        // instead of a silent green on a corrupted config. A
                        // malformed *discovered* file stays a non-fatal warning.
                        if explicit_paths.iter().any(|p| p == path) {
                            usage_error = true;
                        }
                    }
                }
            }
            Err(e) => {
                report.warnings.push(format!("{}: {e}", path.display()));
                // An explicit path that exists but cannot be read is a usage error.
                if explicit_paths.iter().any(|p| p == path) {
                    usage_error = true;
                }
            }
        }
    }
    (report, usage_error)
}

/// Discover (or take explicit) MCP config files, scan each, render, and return
/// the process exit code.
pub fn run_scan(explicit_paths: &[PathBuf], json: bool, cfg: &AppConfig) -> i32 {
    let (report, usage_error) = collect(explicit_paths, cfg);
    if json {
        report::render_json(&report, usage_error);
    } else {
        report::render_human(&report, usage_error);
    }
    exit_code(&report, usage_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::scan::{CheckKind, Finding, Severity};
    use std::path::PathBuf;

    fn finding(sev: Severity) -> Finding {
        Finding {
            file: PathBuf::from("/x"),
            server: "s".to_string(),
            check: CheckKind::EnvSecret,
            severity: sev,
            detail: String::new(),
        }
    }

    fn report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            files_scanned: 1,
            servers: 1,
            findings,
            warnings: vec![],
        }
    }

    #[test]
    fn clean_report_exits_zero() {
        assert_eq!(exit_code(&report(vec![]), false), 0);
    }

    #[test]
    fn warning_finding_exits_ten() {
        assert_eq!(
            exit_code(&report(vec![finding(Severity::Warning)]), false),
            10
        );
    }

    #[test]
    fn high_finding_exits_twenty() {
        assert_eq!(exit_code(&report(vec![finding(Severity::High)]), false), 20);
    }

    #[test]
    fn usage_error_forces_125_over_findings() {
        assert_eq!(exit_code(&report(vec![finding(Severity::High)]), true), 125);
    }

    #[test]
    fn collect_returns_report_and_usage_flag() {
        let dir = std::env::temp_dir().join(format!("vallum_mcp_collect_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("mcp.json");
        std::fs::write(
            &p,
            r#"{"mcpServers":{"s":{"command":"npx","args":["x"],"env":{"API_KEY":"sk-live-1234567890abcdef"}}}}"#,
        )
        .unwrap();
        let cfg = AppConfig::default();
        let (report, usage_error) = collect(&[p], &cfg);
        assert!(!usage_error);
        assert_eq!(report.files_scanned, 1);
        assert!(!report.findings.is_empty(), "embedded secret must be found");
        // Missing explicit path → usage error.
        let (_, usage_error) = collect(&[PathBuf::from("/no/such/file.json")], &cfg);
        assert!(usage_error);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
