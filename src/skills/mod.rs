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

/// Aux files larger than this are not scanned (and never truncated-then-
/// scanned — partial scanning is exactly the ClawHub scanner bypass); they
/// yield an aux_too_large Warning instead.
const MAX_AUX_BYTES: u64 = 5 * 1024 * 1024;

/// Well-known binary extensions skipped silently (counted in the report).
const BINARY_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "svgz", "pdf", "zip", "tar", "gz", "tgz", "bz2",
    "xz", "7z", "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "mov", "wasm", "class", "jar",
    "so", "dylib", "a", "o", "bin", "exe", "dat", "sqlite", "db",
];

/// Accumulated result of a scan across one or more docs.
pub struct ScanReport {
    pub files_scanned: usize,
    pub docs: usize,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
    pub binary_skipped: usize,
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

/// Discover (or take explicit) skill/context files and scan each. Returns the
/// accumulated report and whether a usage error occurred.
pub fn collect(explicit_paths: &[PathBuf], cfg: &AppConfig) -> (ScanReport, bool) {
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
        binary_skipped: 0,
    };

    let mut docs = Vec::new();
    let mut aux_findings: Vec<Finding> = Vec::new();
    for t in &targets {
        if t.kind == model::DocKind::Aux {
            let ext = t
                .path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase());
            if let Some(e) = ext {
                if BINARY_EXTS.contains(&e.as_str()) {
                    report.binary_skipped += 1;
                    continue;
                }
            }
            let root = t.skill_root.clone().unwrap_or_default();
            let display = model::aux_display(&t.path, &root);
            let too_large = std::fs::metadata(&t.path)
                .map(|m| m.len() > MAX_AUX_BYTES)
                .unwrap_or(false);
            if too_large {
                aux_findings.push(Finding {
                    file: t.path.clone(),
                    doc: display,
                    doc_kind: model::DocKind::Aux,
                    check: CheckKind::AuxTooLarge,
                    severity: Severity::Warning,
                    detail: format!(
                        "file exceeds {MAX_AUX_BYTES} bytes — not scanned (never truncated-then-scanned)"
                    ),
                    skill_root: t.skill_root.clone(),
                });
                continue;
            }
            match std::fs::read_to_string(&t.path) {
                Ok(text) => {
                    report.files_scanned += 1;
                    docs.push(model::aux_doc(&t.path, &root, &text));
                }
                Err(e) => {
                    aux_findings.push(Finding {
                        file: t.path.clone(),
                        doc: display,
                        doc_kind: model::DocKind::Aux,
                        check: CheckKind::AuxUnreadable,
                        severity: Severity::Warning,
                        detail: format!(
                            "unreadable or non-UTF8 ({e}) — a non-UTF8 script still runs under bash"
                        ),
                        skill_root: t.skill_root.clone(),
                    });
                }
            }
            continue;
        }
        // Markdown targets: existing behavior, byte-identical (incl. explicit-mode
        // read error → usage_error), plus skill_root propagation.
        match std::fs::read_to_string(&t.path) {
            Ok(text) => {
                report.files_scanned += 1;
                let mut doc = model::parse_doc(&t.path, t.kind, &text);
                doc.skill_root = t.skill_root.clone();
                docs.push(doc);
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
    findings.extend(aux_findings);
    scan::add_combined_signatures(&mut findings);
    report.findings = findings;

    (report, usage_error)
}

/// Discover (or take explicit) skill/context files, scan each, render, and
/// return the process exit code.
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
            binary_skipped: 0,
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

    #[test]
    fn aux_binary_extension_is_skipped_and_counted() {
        let d = std::env::temp_dir().join(format!("vallum_aux_bin_{}", std::process::id()));
        std::fs::create_dir_all(d.join("s")).unwrap();
        std::fs::write(d.join("s").join("SKILL.md"), "clean\n").unwrap();
        std::fs::write(d.join("s").join("logo.png"), [0xffu8, 0xd8, 0x00]).unwrap();
        let cfg = AppConfig::default();
        let code = run_scan(std::slice::from_ref(&d), true, &cfg);
        assert_eq!(code, 0, "binary skip must not produce findings");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn aux_non_utf8_nonbinary_ext_yields_warning_finding_not_125() {
        let d = std::env::temp_dir().join(format!("vallum_aux_utf8_{}", std::process::id()));
        std::fs::create_dir_all(d.join("s")).unwrap();
        std::fs::write(d.join("s").join("SKILL.md"), "clean\n").unwrap();
        std::fs::write(d.join("s").join("payload.txt"), [0xffu8, 0xfe, 0x00]).unwrap();
        let cfg = AppConfig::default();
        let code = run_scan(std::slice::from_ref(&d), true, &cfg);
        assert_eq!(
            code, 10,
            "non-UTF8 aux = Warning finding (silent skip is an evasion)"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn collect_returns_report_and_usage_flag() {
        let d = std::env::temp_dir().join(format!("vallum_skills_collect_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("s")).unwrap();
        std::fs::write(d.join("s").join("SKILL.md"), "clean\n").unwrap();
        let cfg = AppConfig::default();
        let (report, usage_error) = collect(std::slice::from_ref(&d), &cfg);
        assert!(!usage_error);
        assert_eq!(report.files_scanned, 1);
        let (_, usage_error) = collect(&[PathBuf::from("/no/such/file-xyz.md")], &cfg);
        assert!(usage_error);
        let _ = std::fs::remove_dir_all(&d);
    }
}
