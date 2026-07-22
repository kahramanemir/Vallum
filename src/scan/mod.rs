//! Unified CI-facing scanner: MCP configs + skills/context files + config
//! validity + policy.log chain, one exit code, human/JSON/SARIF output.
//! Read-only, static, no network — same posture as the underlying scanners.

pub mod sarif;

use crate::config::AppConfig;
use std::path::PathBuf;

/// Output format for `vallum scan`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

/// A finding produced by the scan-level checks (not by the two content
/// scanners): config hygiene and log-chain integrity.
pub struct ExtraFinding {
    /// Namespaced rule id: `doctor/config` or `doctor/log-chain`.
    pub rule: String,
    pub severity_high: bool,
    pub file: PathBuf,
    pub detail: String,
}

pub struct UnifiedReport {
    pub mcp: crate::mcp::ScanReport,
    pub skills: crate::skills::ScanReport,
    pub extra: Vec<ExtraFinding>,
    pub usage_error: bool,
}

/// Basenames routed to the MCP scanner when given explicitly or found in a
/// named directory. Everything else goes to the skills walker.
const MCP_BASENAMES: &[&str] = &[".mcp.json", "mcp.json", "claude_desktop_config.json"];

/// Split explicit paths: known MCP config files (and the well-known MCP
/// locations directly under a named directory) go to mcp; every path also
/// goes to skills when it is a directory or a non-MCP file.
fn split_paths(paths: &[PathBuf]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut mcp = Vec::new();
    let mut skills = Vec::new();
    for p in paths {
        if p.is_dir() {
            for candidate in [p.join(".mcp.json"), p.join(".vscode").join("mcp.json")] {
                if candidate.is_file() {
                    mcp.push(candidate);
                }
            }
            skills.push(p.clone());
        } else {
            let base = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if MCP_BASENAMES.contains(&base.as_str()) {
                mcp.push(p.clone());
            } else {
                skills.push(p.clone());
            }
        }
    }
    (mcp, skills)
}

/// Config-hygiene findings: unknown `[policy] disabled` names and unknown
/// `[optimizer] disabled` names (the config itself parsed — a config that
/// fails to load never reaches this point; that is exit 125 in main).
fn config_findings(cfg: &AppConfig) -> Vec<ExtraFinding> {
    let config_path = crate::config::config_path_from_env_or_default();
    let mut known_rules = crate::policy::builtin_names();
    known_rules.extend(crate::policy::file_rules::rule_names());
    let mut out = Vec::new();
    for d in &cfg.policy.disabled {
        if !known_rules.contains(&d.as_str()) {
            out.push(ExtraFinding {
                rule: "doctor/config".to_string(),
                severity_high: false,
                file: config_path.clone(),
                detail: format!("unknown name in [policy] disabled: {d}"),
            });
        }
    }
    for d in &cfg.optimizer.disabled {
        if !crate::optimizer::names().contains(&d.as_str()) {
            out.push(ExtraFinding {
                rule: "doctor/config".to_string(),
                severity_high: false,
                file: config_path.clone(),
                detail: format!("unknown name in [optimizer] disabled: {d}"),
            });
        }
    }
    if let Some(p) = &cfg.project {
        if let Some(reason) = &p.rejected {
            out.push(ExtraFinding {
                rule: "doctor/config".to_string(),
                severity_high: false,
                file: p.path.clone(),
                detail: format!("project config rejected: {reason}"),
            });
        }
    }
    out
}

/// Chain finding: verify policy.log iff it exists. Broken chain is High
/// (tamper evidence); an unverifiable file is a Warning; absence is nothing.
fn chain_finding(cfg: &AppConfig) -> Option<ExtraFinding> {
    let path = crate::audit::resolve_log_path("policy.log", cfg.audit.log_dir.as_deref())?;
    match crate::logchain::verify_file(&path) {
        Ok(None) => None,
        Ok(Some(report)) => match report.break_at {
            None => None,
            Some(b) => Some(ExtraFinding {
                rule: "doctor/log-chain".to_string(),
                severity_high: true,
                file: path,
                detail: format!(
                    "policy.log hash chain broken at block {} — tamper evidence",
                    b.index
                ),
            }),
        },
        Err(e) => Some(ExtraFinding {
            rule: "doctor/log-chain".to_string(),
            severity_high: false,
            file: path,
            detail: format!("could not verify policy.log: {e}"),
        }),
    }
}

pub fn collect_unified(paths: &[PathBuf], cfg: &AppConfig) -> UnifiedReport {
    let (mcp_paths, skills_paths) = split_paths(paths);
    // With no explicit paths both scanners run their own discovery. With
    // explicit paths, a side with nothing routed to it scans nothing (an
    // empty explicit list would trigger discovery — guard it).
    let (mcp, mcp_err) = if paths.is_empty() {
        crate::mcp::collect(&[], cfg)
    } else if mcp_paths.is_empty() {
        (
            crate::mcp::ScanReport {
                files_scanned: 0,
                servers: 0,
                findings: Vec::new(),
                warnings: Vec::new(),
            },
            false,
        )
    } else {
        crate::mcp::collect(&mcp_paths, cfg)
    };
    let (skills, skills_err) = if paths.is_empty() {
        crate::skills::collect(&[], cfg)
    } else if skills_paths.is_empty() {
        (
            crate::skills::ScanReport {
                files_scanned: 0,
                docs: 0,
                findings: Vec::new(),
                warnings: Vec::new(),
                binary_skipped: 0,
            },
            false,
        )
    } else {
        crate::skills::collect(&skills_paths, cfg)
    };
    let mut extra = config_findings(cfg);
    extra.extend(chain_finding(cfg));
    UnifiedReport {
        mcp,
        skills,
        extra,
        usage_error: mcp_err || skills_err,
    }
}

/// 0 clean, 10 warning-class, 20 any High, 125 usage error (wins).
pub fn unified_exit_code(r: &UnifiedReport) -> i32 {
    if r.usage_error {
        return 125;
    }
    let any_high = r
        .mcp
        .findings
        .iter()
        .any(|f| f.severity == crate::mcp::Severity::High)
        || r.skills
            .findings
            .iter()
            .any(|f| f.severity == crate::skills::Severity::High)
        || r.extra.iter().any(|e| e.severity_high);
    if any_high {
        return 20;
    }
    if !r.mcp.findings.is_empty() || !r.skills.findings.is_empty() || !r.extra.is_empty() {
        return 10;
    }
    0
}

/// Render the unified report and return the exit code. `full` appends the
/// environment half of doctor for local use (never valid with SARIF — the
/// CLI rejects that combination before calling here).
pub fn run(paths: &[PathBuf], format: OutputFormat, full: bool, cfg: &AppConfig) -> i32 {
    let report = collect_unified(paths, cfg);
    match format {
        OutputFormat::Human => render_human(&report, cfg, full),
        OutputFormat::Json => render_json(&report),
        OutputFormat::Sarif => println!("{}", sarif::render(&report)),
    }
    unified_exit_code(&report)
}

fn render_human(r: &UnifiedReport, cfg: &AppConfig, full: bool) {
    println!("── mcp ──");
    crate::mcp::report::render_human(&r.mcp, r.usage_error);
    println!("\n── skills ──");
    crate::skills::report::render_human(&r.skills, r.usage_error);
    if !r.extra.is_empty() {
        println!("\n── config/chain ──");
        for e in &r.extra {
            let sev = if e.severity_high { "HIGH" } else { "warn" };
            println!("  [{sev}] {}: {} ({})", e.rule, e.detail, e.file.display());
        }
    }
    if full {
        // Environment half for local use: hooks, PATH, log dir, breaker.
        println!("\n── environment (--full) ──");
        // doctor::run prints its own report; its exit code is advisory here
        // (scan's own exit code is computed from findings only).
        let _ = crate::doctor::run();
    }
    let code = unified_exit_code(r);
    println!(
        "\nscan result: {}",
        match code {
            0 => "clean".to_string(),
            10 => "findings (warning)".to_string(),
            20 => "findings (HIGH)".to_string(),
            other => format!("error ({other})"),
        }
    );
    let _ = cfg;
}

#[derive(serde::Serialize)]
struct JsonExtra<'a> {
    rule: &'a str,
    severity: &'a str,
    file: String,
    detail: &'a str,
}

fn render_json(r: &UnifiedReport) {
    // Aggregate JSON: reuse each side's serializable pieces.
    let extras: Vec<JsonExtra> = r
        .extra
        .iter()
        .map(|e| JsonExtra {
            rule: &e.rule,
            severity: if e.severity_high { "high" } else { "warning" },
            file: e.file.display().to_string(),
            detail: &e.detail,
        })
        .collect();
    let out = serde_json::json!({
        "usage_error": r.usage_error,
        "mcp": {
            "files_scanned": r.mcp.files_scanned,
            "servers": r.mcp.servers,
            "findings": r.mcp.findings,
            "warnings": r.mcp.warnings,
        },
        "skills": {
            "files_scanned": r.skills.files_scanned,
            "docs": r.skills.docs,
            "binary_skipped": r.skills.binary_skipped,
            // skills findings serialize file as PathBuf; keep the same shape
            // the skills JSON renderer uses (display strings) via a mapped list.
            "findings": r.skills.findings.iter().map(|f| serde_json::json!({
                "file": f.file.display().to_string(),
                "doc": f.doc,
                "check": f.check,
                "severity": f.severity,
                "detail": f.detail,
            })).collect::<Vec<_>>(),
            "warnings": r.skills.warnings,
        },
        "extra": extras,
        "exit_code": unified_exit_code(r),
    });
    println!("{}", serde_json::to_string(&out).unwrap_or_default());
}

/// SessionStart quick scan: discovery-scoped, ALWAYS exit 0, silent when
/// clean, one-line summary as SessionStart additionalContext when not. A
/// broken config degrades to silence — a scanner must never break session
/// start.
pub fn run_hook_context() -> i32 {
    let Ok(cfg) = AppConfig::load() else {
        return 0;
    };
    let (mcp, _) = crate::mcp::collect(&[], &cfg);
    let (skills, _) = crate::skills::collect(&[], &cfg);
    let total = mcp.findings.len() + skills.findings.len();
    if total == 0 {
        return 0;
    }
    let high = mcp
        .findings
        .iter()
        .filter(|f| f.severity == crate::mcp::Severity::High)
        .count()
        + skills
            .findings
            .iter()
            .filter(|f| f.severity == crate::skills::Severity::High)
            .count();
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": format!(
                "vallum scan: {total} finding(s) ({high} high) — run 'vallum scan' for details"
            ),
        }
    });
    if let Ok(s) = serde_json::to_string(&out) {
        println!("{s}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mcp_report(high: bool, any: bool) -> crate::mcp::ScanReport {
        let findings = if any {
            vec![crate::mcp::Finding {
                file: PathBuf::from("/x"),
                server: "s".into(),
                check: crate::mcp::CheckKind::EnvSecret,
                severity: if high {
                    crate::mcp::Severity::High
                } else {
                    crate::mcp::Severity::Warning
                },
                detail: String::new(),
            }]
        } else {
            vec![]
        };
        crate::mcp::ScanReport {
            files_scanned: 1,
            servers: 1,
            findings,
            warnings: vec![],
        }
    }

    fn skills_report() -> crate::skills::ScanReport {
        crate::skills::ScanReport {
            files_scanned: 0,
            docs: 0,
            findings: vec![],
            warnings: vec![],
            binary_skipped: 0,
        }
    }

    fn unified(high: bool, any: bool, extra_high: Option<bool>, usage: bool) -> UnifiedReport {
        let extra = match extra_high {
            None => vec![],
            Some(h) => vec![ExtraFinding {
                rule: "doctor/log-chain".into(),
                severity_high: h,
                file: PathBuf::from("/log"),
                detail: "d".into(),
            }],
        };
        UnifiedReport {
            mcp: mcp_report(high, any),
            skills: skills_report(),
            extra,
            usage_error: usage,
        }
    }

    #[test]
    fn exit_code_matrix() {
        assert_eq!(unified_exit_code(&unified(false, false, None, false)), 0);
        assert_eq!(unified_exit_code(&unified(false, true, None, false)), 10);
        assert_eq!(unified_exit_code(&unified(true, true, None, false)), 20);
        assert_eq!(
            unified_exit_code(&unified(false, false, Some(false), false)),
            10
        );
        assert_eq!(
            unified_exit_code(&unified(false, false, Some(true), false)),
            20
        );
        assert_eq!(
            unified_exit_code(&unified(true, true, Some(true), true)),
            125
        );
    }

    #[test]
    fn split_paths_routes_known_mcp_names() {
        let d = std::env::temp_dir().join(format!("vallum_scan_split_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".vscode")).unwrap();
        std::fs::write(d.join(".mcp.json"), "{}").unwrap();
        std::fs::write(d.join(".vscode").join("mcp.json"), "{}").unwrap();
        std::fs::write(d.join("SKILL.md"), "x").unwrap();
        let (mcp, skills) = split_paths(&[d.clone(), d.join("SKILL.md"), d.join(".mcp.json")]);
        assert_eq!(
            mcp.len(),
            3,
            "dir yields two known files + explicit .mcp.json: {mcp:?}"
        );
        assert_eq!(skills.len(), 2, "dir + SKILL.md: {skills:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn config_findings_flag_unknown_disabled_names() {
        let mut cfg = AppConfig::default();
        cfg.policy.disabled = vec!["no_such_rule".into()];
        cfg.optimizer.disabled = vec!["no_such_optimizer".into()];
        let f = config_findings(&cfg);
        assert_eq!(f.len(), 2);
        assert!(f
            .iter()
            .all(|e| e.rule == "doctor/config" && !e.severity_high));
    }

    #[test]
    fn config_findings_include_rejected_project_file() {
        let cfg = AppConfig {
            project: Some(crate::config::ProjectProvenance {
                path: PathBuf::from("/repo/.vallum.toml"),
                accepted_rules: 0,
                rejected: Some("unknown field `security`".into()),
            }),
            ..Default::default()
        };
        let f = config_findings(&cfg);
        assert!(
            f.iter().any(|e| e.rule == "doctor/config"
                && e.detail.contains("project config rejected")
                && !e.severity_high),
            "{:?}",
            f.iter().map(|e| &e.detail).collect::<Vec<_>>()
        );
    }

    #[test]
    fn chain_finding_absent_log_is_none() {
        let mut cfg = AppConfig::default();
        let d = std::env::temp_dir().join(format!("vallum_scan_chain_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        cfg.audit.log_dir = Some(d.clone());
        assert!(chain_finding(&cfg).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
