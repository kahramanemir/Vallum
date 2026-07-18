//! Static scanner for agent skill files (`SKILL.md`) and agent context files
//! (`CLAUDE.md`, `AGENTS.md`, …). Read-only; reuses Vallum's scrubber, policy,
//! and injection engines — no new detection logic lives here.

pub mod discover;
pub mod model;
pub mod report;
pub mod scan;

pub use scan::{CheckKind, Finding, Severity};

use crate::config::AppConfig;
use crate::policy::Policy;
use std::path::PathBuf;

/// Accumulated result of a scan across one or more docs.
pub struct ScanReport {
    pub files_scanned: usize,
    pub docs: usize,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

/// Exit code: 0 clean, 10 findings, 20 any High, 125 usage error (wins).
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

/// Discover (or take explicit) skill/context files, scan each, render, and
/// return the process exit code.
pub fn run_scan(explicit_paths: &[PathBuf], json: bool, cfg: &AppConfig) -> i32 {
    let mut usage_error = false;

    let targets: Vec<discover::Target> = if explicit_paths.is_empty() {
        discover::existing_targets()
    } else {
        let (targets, missing) = discover::resolve_explicit(explicit_paths);
        for m in &missing {
            eprintln!("skills scan: {}: no scannable file", m.display());
            usage_error = true;
        }
        targets
    };

    let policy = if cfg.security.guardrail {
        Policy::compile(&cfg.policy).ok()
    } else {
        None
    };

    let mut report = ScanReport {
        files_scanned: 0,
        docs: 0,
        findings: Vec::new(),
        warnings: Vec::new(),
    };

    let mut docs = Vec::new();
    for t in &targets {
        match std::fs::read_to_string(&t.path) {
            Ok(text) => {
                report.files_scanned += 1;
                docs.push(model::parse_doc(&t.path, t.kind, &text));
            }
            Err(e) => {
                report.warnings.push(format!("{}: {e}", t.path.display()));
                // In explicit mode every target came from an explicit arg (a named file
                // or a file found by walking a named directory), so an unreadable target
                // is a usage error — CI must not exit green on a file it could not read.
                // Auto-discover mode (empty explicit_paths) keeps read errors non-fatal.
                if !explicit_paths.is_empty() {
                    usage_error = true;
                }
            }
        }
    }
    report.docs = docs.len();

    let mut findings = scan::scan_docs(&docs, policy.as_ref(), cfg);
    scan::add_combined_signatures(&mut findings);
    report.findings = findings;

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
    use crate::skills::model::DocKind;
    use crate::skills::scan::{CheckKind, Finding, Severity};
    use std::path::PathBuf;

    fn f(sev: Severity) -> Finding {
        Finding {
            file: PathBuf::from("/x"),
            doc: "d".into(),
            doc_kind: DocKind::Skill,
            check: CheckKind::Secret,
            severity: sev,
            detail: String::new(),
            skill_root: None,
        }
    }
    fn report(findings: Vec<Finding>) -> ScanReport {
        ScanReport {
            files_scanned: 1,
            docs: 1,
            findings,
            warnings: vec![],
        }
    }

    #[test]
    fn clean_exits_zero() {
        assert_eq!(exit_code(&report(vec![]), false), 0);
    }
    #[test]
    fn warning_exits_ten() {
        assert_eq!(exit_code(&report(vec![f(Severity::Warning)]), false), 10);
    }
    #[test]
    fn high_exits_twenty() {
        assert_eq!(exit_code(&report(vec![f(Severity::High)]), false), 20);
    }
    #[test]
    fn usage_error_forces_125() {
        assert_eq!(exit_code(&report(vec![f(Severity::High)]), true), 125);
    }

    #[test]
    fn run_scan_on_missing_explicit_path_is_125() {
        let cfg = AppConfig::default();
        let code = run_scan(&[PathBuf::from("/no/such/file-xyz.md")], true, &cfg);
        assert_eq!(code, 125);
    }
}
