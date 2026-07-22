//! SARIF 2.1.0 renderer for the unified scan report. Typed serde structs —
//! never string-built JSON. v1 honest scope: file-level locations only (the
//! finding models carry no line spans); files under the current working
//! directory get relative URIs (required for GitHub alert mapping), files
//! outside it keep absolute paths and will not map to repo alerts.

use super::UnifiedReport;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct Sarif {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<ResultObj>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver {
    name: &'static str,
    information_uri: &'static str,
    version: &'static str,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: String,
    short_description: Text,
}

#[derive(Serialize)]
struct Text {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultObj {
    rule_id: String,
    level: &'static str,
    message: Text,
    locations: Vec<Location>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

fn mcp_rule_id(check: &crate::mcp::CheckKind) -> &'static str {
    match check {
        crate::mcp::CheckKind::EnvSecret => "mcp/env-secret",
        crate::mcp::CheckKind::LaunchCommand => "mcp/launch-command",
        crate::mcp::CheckKind::DescriptionInjection => "mcp/description-injection",
    }
}

fn skills_rule_id(check: &crate::skills::CheckKind) -> &'static str {
    match check {
        crate::skills::CheckKind::Secret => "skills/secret",
        crate::skills::CheckKind::Injection => "skills/injection",
        crate::skills::CheckKind::FenceCommand => "skills/fence-command",
        crate::skills::CheckKind::InvisibleUnicode => "skills/invisible-unicode",
        crate::skills::CheckKind::CombinedSignature => "skills/combined-signature",
        crate::skills::CheckKind::AuxUnreadable => "skills/aux-unreadable",
        crate::skills::CheckKind::AuxTooLarge => "skills/aux-too-large",
    }
}

/// Relative URI under cwd (forward slashes), absolute otherwise.
fn uri_for(path: &Path) -> String {
    let cwd = std::env::current_dir().unwrap_or_default();
    match path.strip_prefix(&cwd) {
        Ok(rel) => rel.display().to_string().replace('\\', "/"),
        Err(_) => path.display().to_string(),
    }
}

fn result(rule_id: &str, high: bool, message: String, file: &Path) -> ResultObj {
    ResultObj {
        rule_id: rule_id.to_string(),
        level: if high { "error" } else { "warning" },
        message: Text { text: message },
        locations: vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation { uri: uri_for(file) },
            },
        }],
    }
}

pub fn render(r: &UnifiedReport) -> String {
    let mut results = Vec::new();
    for f in &r.mcp.findings {
        results.push(result(
            mcp_rule_id(&f.check),
            f.severity == crate::mcp::Severity::High,
            format!("[{}] {}", f.server, f.detail),
            &f.file,
        ));
    }
    for f in &r.skills.findings {
        results.push(result(
            skills_rule_id(&f.check),
            f.severity == crate::skills::Severity::High,
            format!("[{}] {}", f.doc, f.detail),
            &f.file,
        ));
    }
    for e in &r.extra {
        results.push(result(&e.rule, e.severity_high, e.detail.clone(), &e.file));
    }
    // Rules array: every distinct ruleId that appears, in first-seen order.
    let mut rules: Vec<Rule> = Vec::new();
    for res in &results {
        if !rules.iter().any(|ru| ru.id == res.rule_id) {
            rules.push(Rule {
                id: res.rule_id.clone(),
                short_description: Text {
                    text: res.rule_id.clone(),
                },
            });
        }
    }
    let sarif = Sarif {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "vallum",
                    information_uri: "https://github.com/kahramanemir/Vallum",
                    version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            results,
        }],
    };
    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn report_with_findings() -> UnifiedReport {
        UnifiedReport {
            mcp: crate::mcp::ScanReport {
                files_scanned: 1,
                servers: 1,
                findings: vec![crate::mcp::Finding {
                    file: PathBuf::from("/abs/outside.json"),
                    server: "srv".into(),
                    check: crate::mcp::CheckKind::EnvSecret,
                    severity: crate::mcp::Severity::High,
                    detail: "embedded secret".into(),
                }],
                warnings: vec![],
            },
            skills: crate::skills::ScanReport {
                files_scanned: 1,
                docs: 1,
                findings: vec![crate::skills::Finding {
                    file: std::env::current_dir().unwrap().join("SKILL.md"),
                    doc: "SKILL.md".into(),
                    doc_kind: crate::skills::model::DocKind::Skill,
                    check: crate::skills::CheckKind::Injection,
                    severity: crate::skills::Severity::Warning,
                    detail: "injection phrase".into(),
                    skill_root: None,
                }],
                warnings: vec![],
                binary_skipped: 0,
            },
            extra: vec![],
            usage_error: false,
        }
    }

    #[test]
    fn sarif_shape_and_severity_mapping() {
        let text = render(&report_with_findings());
        let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "vallum");
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "mcp/env-secret");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["ruleId"], "skills/injection");
        assert_eq!(results[1]["level"], "warning");
        // URI mapping: outside-cwd file stays absolute; cwd file is relative.
        let uri0 = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(uri0.starts_with('/'), "outside cwd stays absolute: {uri0}");
        let uri1 = results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(uri1, "SKILL.md", "under cwd becomes relative");
        // Every ruleId appears in driver.rules.
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["id"] == "mcp/env-secret"));
        assert!(rules.iter().any(|r| r["id"] == "skills/injection"));
    }
}
