//! Well-known skill/context file locations and explicit-argument resolution.
//! Bounded, symlink-free directory walking; absent files are simply not returned.

use crate::skills::model::DocKind;
use std::path::{Path, PathBuf};

const MAX_WALK_DEPTH: usize = 6;

pub struct Target {
    pub path: PathBuf,
    pub kind: DocKind,
    pub skill_root: Option<PathBuf>,
}

/// Recognize a file by name. Returns None for anything not a scan target.
pub fn classify(path: &Path) -> Option<DocKind> {
    let name = path.file_name()?.to_string_lossy();
    match name.as_ref() {
        "SKILL.md" => Some(DocKind::Skill),
        "CLAUDE.md" | "AGENTS.md" | "GEMINI.md" | "copilot-instructions.md" => {
            Some(DocKind::Context)
        }
        ".cursorrules" => Some(DocKind::Rules),
        _ if name.ends_with(".mdc") => Some(DocKind::Rules),
        _ => None,
    }
}

/// Every well-known location, present or not.
pub fn known_targets() -> Vec<Target> {
    let mut out = vec![
        Target {
            path: PathBuf::from("CLAUDE.md"),
            kind: DocKind::Context,
            skill_root: None,
        },
        Target {
            path: PathBuf::from("AGENTS.md"),
            kind: DocKind::Context,
            skill_root: None,
        },
        Target {
            path: PathBuf::from("GEMINI.md"),
            kind: DocKind::Context,
            skill_root: None,
        },
        Target {
            path: PathBuf::from(".cursorrules"),
            kind: DocKind::Rules,
            skill_root: None,
        },
        Target {
            path: PathBuf::from(".github").join("copilot-instructions.md"),
            kind: DocKind::Context,
            skill_root: None,
        },
    ];

    // Project skills + cursor rule files: walk shallow dirs for recognized names.
    for t in walk_targets(Path::new(".claude").join("skills").as_path()) {
        out.push(t);
    }
    for t in walk_targets(Path::new(".cursor").join("rules").as_path()) {
        out.push(t);
    }

    if let Some(home) = dirs::home_dir() {
        out.push(Target {
            path: home.join(".claude").join("CLAUDE.md"),
            kind: DocKind::Context,
            skill_root: None,
        });
        out.push(Target {
            path: home.join(".codex").join("AGENTS.md"),
            kind: DocKind::Context,
            skill_root: None,
        });
        for t in walk_targets(&home.join(".claude").join("skills")) {
            out.push(t);
        }
        for t in walk_targets(&home.join(".claude").join("plugins").join("cache")) {
            out.push(t);
        }
    }
    out
}

/// Known targets that currently exist on disk.
pub fn existing_targets() -> Vec<Target> {
    let mut targets: Vec<Target> = known_targets()
        .into_iter()
        .filter(|t| t.path.is_file())
        .collect();
    add_aux_targets(&mut targets);
    targets
}

/// Resolve explicit CLI args. Each is a file (classified by name; unrecognized
/// names are scanned as `Context` since the user asked explicitly) or a
/// directory (walked for recognized names). Returns targets plus a list of
/// args that are absent or are directories yielding zero recognized files.
pub fn resolve_explicit(paths: &[PathBuf]) -> (Vec<Target>, Vec<PathBuf>) {
    let mut targets = Vec::new();
    let mut missing = Vec::new();
    for p in paths {
        if p.is_file() {
            let kind = classify(p).unwrap_or(DocKind::Context);
            // A directly-named SKILL.md still groups for the per-file composite,
            // but never triggers aux collection of its siblings.
            let skill_root = if kind == DocKind::Skill {
                p.parent().map(Path::to_path_buf)
            } else {
                None
            };
            targets.push(Target {
                path: p.clone(),
                kind,
                skill_root,
            });
        } else if p.is_dir() {
            let mut walked = walk_targets(p);
            if walked.is_empty() {
                missing.push(p.clone());
            } else {
                add_aux_targets(&mut walked);
                targets.extend(walked);
            }
        } else {
            missing.push(p.clone());
        }
    }
    (targets, missing)
}

/// Depth-bounded, symlink-free walk collecting recognized files under `root`.
fn walk_targets(root: &Path) -> Vec<Target> {
    let mut out = Vec::new();
    walk_inner(root, 0, &mut out);
    out
}

fn walk_inner(dir: &Path, depth: usize, out: &mut Vec<Target>) {
    // Never follow a symlinked walk root (read_dir would transparently
    // traverse it). Entries discovered *inside* are already symlink-skipped
    // below; this closes the same hole at the root a caller hands us.
    if std::fs::symlink_metadata(dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return;
    }
    if depth > MAX_WALK_DEPTH {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue; // never follow symlinks
        }
        if meta.is_dir() {
            walk_inner(&path, depth + 1, out);
        } else if meta.is_file() {
            if let Some(kind) = classify(&path) {
                let skill_root = if kind == DocKind::Skill {
                    path.parent().map(Path::to_path_buf)
                } else {
                    None
                };
                out.push(Target {
                    path,
                    kind,
                    skill_root,
                });
            }
        }
    }
}

/// For every unique skill root among `targets`, walk the root and append every
/// regular, non-symlink file that classify() does not recognize as an Aux
/// target. SKILL.md siblings named CLAUDE.md etc. stay their classified kind.
pub fn add_aux_targets(targets: &mut Vec<Target>) {
    use std::collections::BTreeSet;
    let roots: BTreeSet<PathBuf> = targets
        .iter()
        .filter(|t| t.kind == DocKind::Skill)
        .filter_map(|t| t.skill_root.clone())
        .collect();
    for root in roots {
        let mut aux = Vec::new();
        aux_walk(&root, &root, 0, &mut aux);
        targets.extend(aux);
    }
}

fn aux_walk(root: &Path, dir: &Path, depth: usize, out: &mut Vec<Target>) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    if std::fs::symlink_metadata(dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            aux_walk(root, &path, depth + 1, out);
        } else if meta.is_file() && classify(&path).is_none() {
            out.push(Target {
                path,
                kind: DocKind::Aux,
                skill_root: Some(root.to_path_buf()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::model::DocKind;
    use std::fs;
    use std::path::PathBuf;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vallum_skills_disc_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn classify_recognizes_names() {
        assert_eq!(
            classify(std::path::Path::new("SKILL.md")),
            Some(DocKind::Skill)
        );
        assert_eq!(
            classify(std::path::Path::new("CLAUDE.md")),
            Some(DocKind::Context)
        );
        assert_eq!(
            classify(std::path::Path::new("AGENTS.md")),
            Some(DocKind::Context)
        );
        assert_eq!(
            classify(std::path::Path::new(".cursorrules")),
            Some(DocKind::Rules)
        );
        assert_eq!(
            classify(std::path::Path::new("rules.mdc")),
            Some(DocKind::Rules)
        );
        assert_eq!(classify(std::path::Path::new("README.md")), None);
    }

    #[test]
    fn known_targets_nonempty() {
        assert!(!known_targets().is_empty());
    }

    #[test]
    fn resolve_explicit_file_is_classified() {
        let d = tmp();
        let f = d.join("CLAUDE.md");
        fs::write(&f, "x").unwrap();
        let (targets, missing) = resolve_explicit(std::slice::from_ref(&f));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, DocKind::Context);
        assert!(missing.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn resolve_explicit_dir_walks_recognized_files() {
        let d = tmp();
        fs::create_dir_all(d.join("my-skill")).unwrap();
        fs::write(d.join("my-skill").join("SKILL.md"), "x").unwrap();
        fs::write(d.join("noise.txt"), "x").unwrap();
        let (targets, missing) = resolve_explicit(std::slice::from_ref(&d));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, DocKind::Skill);
        assert!(missing.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn resolve_explicit_empty_dir_is_reported_missing() {
        let d = tmp();
        let (targets, missing) = resolve_explicit(std::slice::from_ref(&d));
        assert!(targets.is_empty());
        assert_eq!(missing, vec![d.clone()]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn resolve_explicit_absent_path_is_reported_missing() {
        let p = PathBuf::from("/no/such/skills/here-xyz");
        let (targets, missing) = resolve_explicit(std::slice::from_ref(&p));
        assert!(targets.is_empty());
        assert_eq!(missing, vec![p]);
    }

    #[test]
    fn symlinked_walk_root_is_not_followed() {
        let d = tmp();
        // Real dir with a recognized file:
        let real = d.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("SKILL.md"), "x").unwrap();
        // A symlink pointing at it:
        let link = d.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // resolve_explicit on the symlinked dir must find nothing (root not followed) → missing.
        let (targets, missing) = resolve_explicit(std::slice::from_ref(&link));
        assert!(targets.is_empty(), "symlinked root must not be walked");
        assert_eq!(missing, vec![link]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn aux_targets_collected_under_skill_root() {
        let d = tmp();
        fs::create_dir_all(d.join("my-skill").join("scripts")).unwrap();
        fs::write(d.join("my-skill").join("SKILL.md"), "x").unwrap();
        fs::write(d.join("my-skill").join("payload.txt"), "x").unwrap();
        fs::write(d.join("my-skill").join("scripts").join("run.py"), "x").unwrap();
        let (targets, missing) = resolve_explicit(std::slice::from_ref(&d));
        assert!(missing.is_empty());
        let aux: Vec<_> = targets.iter().filter(|t| t.kind == DocKind::Aux).collect();
        assert_eq!(aux.len(), 2, "payload.txt + scripts/run.py");
        for t in &aux {
            assert_eq!(t.skill_root.as_deref(), Some(d.join("my-skill").as_path()));
        }
        // SKILL.md itself is a Skill target with skill_root set, not an Aux one.
        let skill: Vec<_> = targets
            .iter()
            .filter(|t| t.kind == DocKind::Skill)
            .collect();
        assert_eq!(skill.len(), 1);
        assert_eq!(
            skill[0].skill_root.as_deref(),
            Some(d.join("my-skill").as_path())
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn no_aux_collection_without_skill_md() {
        let d = tmp();
        fs::write(d.join("CLAUDE.md"), "x").unwrap();
        fs::write(d.join("random.txt"), "x").unwrap();
        let (targets, _missing) = resolve_explicit(std::slice::from_ref(&d));
        assert!(targets.iter().all(|t| t.kind != DocKind::Aux));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn explicit_skill_md_file_does_not_pull_aux_siblings() {
        let d = tmp();
        fs::create_dir_all(d.join("s")).unwrap();
        let f = d.join("s").join("SKILL.md");
        fs::write(&f, "x").unwrap();
        fs::write(d.join("s").join("payload.txt"), "x").unwrap();
        let (targets, _m) = resolve_explicit(std::slice::from_ref(&f));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, DocKind::Skill);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn aux_walk_skips_symlinked_files() {
        let d = tmp();
        fs::create_dir_all(d.join("s")).unwrap();
        fs::write(d.join("s").join("SKILL.md"), "x").unwrap();
        fs::write(d.join("outside.txt"), "x").unwrap();
        std::os::unix::fs::symlink(d.join("outside.txt"), d.join("s").join("link.txt")).unwrap();
        let (targets, _m) = resolve_explicit(std::slice::from_ref(&d));
        assert!(targets.iter().all(|t| t.kind != DocKind::Aux));
        let _ = fs::remove_dir_all(&d);
    }
}
