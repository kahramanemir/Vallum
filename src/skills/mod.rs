//! Static scanner for agent skill files (`SKILL.md`) and agent context files
//! (`CLAUDE.md`, `AGENTS.md`, …). Read-only; reuses Vallum's scrubber, policy,
//! and injection engines — no new detection logic lives here.

pub mod discover;
pub mod model;
pub mod report;
pub mod scan;

pub use scan::{CheckKind, Finding, Severity};

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
}
