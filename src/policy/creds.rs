//! Head-command guard for the `read_sensitive_creds` rule.
//!
//! The rule's regex answers "is a protected path named on this line". This
//! module answers "by whom". The split exists because the `regex` crate has
//! no lookaround, so "a path appears AND the command is not `ls`" cannot be
//! one pattern.
//!
//! The design inverts the old reader allowlist (`cat|less|head|…`): that list
//! could never be complete — `sort`, `nl`, `od`, `cp`, `tar`, and a dozen
//! others dump or copy a private key exactly like `cat` does. The path family
//! (`sensitive::hard_re`) is narrow and stable; the set of tools that can
//! read a file is not. So the path is the signal, and only a short list of
//! metadata-only commands is exempt.
//!
//! Not a shell parser — same posture as the rest of `policy`. Variable
//! indirection still gets through; this is defense-in-depth, not a sandbox.

use crate::policy::sensitive::{anchored, hard_re};
use regex::Regex;
use std::sync::OnceLock;

/// Commands that name a credential path as part of their normal argument form
/// without emitting or copying its CONTENTS.
///
/// Deliberately short. Every entry is a hole, so the bar is: could this
/// command put the file's bytes somewhere else? `ssh -i key host` uses the
/// key, it does not print it. `scp` is absent on purpose — it copies contents
/// to a remote (and `egress_sensitive_file` covers it too). `git`, `gpg`,
/// `grep`, and `wc` are absent because they read contents; they were the
/// bypass surface this module exists to close.
const EXEMPT: &[&str] = &[
    "ls",
    "ll",
    "stat",
    "file",
    "test",
    "[",
    "du",
    "df",
    "chmod",
    "chown",
    "touch",
    "mkdir",
    "ssh",
    "sftp",
    "ssh-add",
    "ssh-keygen",
    "vallum",
];

/// Prefixes that wrap another command without changing what runs. Skipped so
/// `sudo less /etc/shadow` is judged on `less`, not on `sudo`.
const WRAPPERS: &[&str] = &["sudo", "env", "command", "nohup", "time"];

/// `hard_re` with both boundaries and the mandatory case-insensitive flag.
fn hard_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&format!("(?i){}", anchored(hard_re()))).unwrap())
}

/// True when some segment of `view` names a protected path and that segment's
/// head command is not exempt.
pub(crate) fn touches_creds_unexempt(view: &str) -> bool {
    segments(view)
        .iter()
        .any(|seg| hard_path_re().is_match(&mask_noise(seg)) && !EXEMPT.contains(&head(seg)))
}

/// Split on shell separators, quote-aware. A separator inside `'…'` or `"…"`
/// is literal text, not a split point. `&&`/`||` are consumed as one
/// separator so an empty segment is not produced between them.
fn segments(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            cur.push(c);
            if c == q {
                quote = None;
            }
            i += 1;
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            cur.push(c);
            i += 1;
        } else if c == ';' || c == '\n' || c == '&' || c == '|' {
            out.push(std::mem::take(&mut cur));
            let doubled = i + 1 < chars.len() && chars[i + 1] == c && (c == '&' || c == '|');
            i += if doubled { 2 } else { 1 };
        } else {
            cur.push(c);
            i += 1;
        }
    }
    out.push(cur);
    out
}

/// The command word of a segment: the first token that is neither a
/// `NAME=value` environment assignment nor a wrapper, reduced to its
/// basename so `/usr/bin/sort` and `sort` are the same head.
///
/// An unrecognized shape (a leading redirect, an empty segment) yields a head
/// that is not in `EXEMPT`, so the guard fires. That is the safe direction.
fn head(seg: &str) -> &str {
    for tok in seg.split_whitespace() {
        let tok = tok.trim_matches(['\'', '"']);
        if tok.is_empty() {
            continue;
        }
        if let Some(eq) = tok.find('=') {
            if eq > 0
                && tok[..eq]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue; // FOO=bar prefix
            }
        }
        let base = tok.rsplit('/').next().unwrap_or(tok);
        if WRAPPERS.contains(&base) {
            continue;
        }
        return base;
    }
    ""
}

/// Blank out the two contexts where a protected path is mentioned rather than
/// used, preserving length so no new adjacency is created:
///
/// 1. A quoted span containing whitespace — a commit message or an issue
///    title, not a filename. Same heuristic as the echo-precision guard in
///    `normalize.rs`. `bash -c "sort ~/.ssh/id_rsa"` is unaffected:
///    `unwrap::command_views` hands the inner payload over as its own view,
///    and the guard runs per view.
/// 2. A token containing `://` — the path is inside a destination URL.
///    `curl -d @data.json https://host/v1/.aws/credentials` uploads
///    `data.json`; the credential path is the endpoint.
fn mask_noise(seg: &str) -> String {
    let chars: Vec<char> = seg.chars().collect();
    let mut out = String::with_capacity(seg.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' {
            if let Some(close) = (i + 1..chars.len()).find(|&j| chars[j] == c) {
                if chars[i + 1..close].iter().any(|ch| ch.is_whitespace()) {
                    out.extend(std::iter::repeat_n(' ', close - i + 1));
                    i = close + 1;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    // Pass 2: URL tokens.
    out.split_whitespace()
        .map(|tok| {
            if tok.contains("://") {
                " ".repeat(tok.len())
            } else {
                tok.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumping_tools_are_not_exempt() {
        for cmd in [
            "sort ~/.ssh/id_rsa",
            "nl ~/.ssh/id_rsa",
            "od -c ~/.ssh/id_rsa",
            "tac ~/.ssh/id_ed25519",
            "rev ~/.ssh/id_rsa",
            "cut -c1- ~/.ssh/id_rsa",
            "grep . /etc/shadow",
            "awk '{print}' ~/.aws/credentials",
            "cp ~/.ssh/id_rsa /tmp/x",
            "tar czf /tmp/k.tgz ~/.ssh/id_rsa",
            "gzip -c ~/.ssh/id_rsa",
            "gpg -d ~/.gnupg/secring.gpg",
            "python3 -c open('/etc/shadow')",
            "/usr/bin/sort ~/.ssh/id_rsa",
        ] {
            assert!(touches_creds_unexempt(cmd), "should fire: {cmd}");
        }
    }

    #[test]
    fn metadata_only_tools_are_exempt() {
        for cmd in [
            "ls -l ~/.ssh/id_rsa",
            "stat ~/.ssh/id_rsa",
            "file ~/.ssh/id_rsa",
            "chmod 600 ~/.ssh/id_rsa",
            "chown me ~/.ssh/id_rsa",
            "touch ~/.ssh/id_rsa",
            "du -h ~/.ssh/id_rsa",
            "ssh -i ~/.ssh/id_rsa host",
            "ssh-add ~/.ssh/id_rsa",
            "ssh-keygen -y -f ~/.ssh/id_rsa",
        ] {
            assert!(!touches_creds_unexempt(cmd), "should NOT fire: {cmd}");
        }
    }

    #[test]
    fn wrappers_and_env_assignments_do_not_hide_the_head() {
        assert!(touches_creds_unexempt("sudo less /etc/shadow"));
        assert!(touches_creds_unexempt("env FOO=bar sort ~/.ssh/id_rsa"));
        assert!(touches_creds_unexempt("LESS=-R less /etc/shadow"));
        assert!(touches_creds_unexempt("nohup cp ~/.ssh/id_rsa /tmp/x"));
        // The wrapper must not hide an EXEMPT head either.
        assert!(!touches_creds_unexempt("sudo ls -l ~/.ssh/id_rsa"));
    }

    #[test]
    fn a_later_segment_is_judged_on_its_own_head() {
        assert!(touches_creds_unexempt("npm test && sort ~/.ssh/id_rsa"));
        assert!(touches_creds_unexempt(
            "ls ~/.ssh; awk '{print}' ~/.ssh/id_rsa"
        ));
        assert!(touches_creds_unexempt("true | base64 ~/.aws/credentials"));
        // Only exempt heads on every segment that names a path -> quiet.
        assert!(!touches_creds_unexempt("cd /tmp && ls -l ~/.ssh/id_rsa"));
    }

    #[test]
    fn quoted_prose_mentions_do_not_count() {
        for cmd in [
            r#"git commit -m "docs: mention ~/.ssh/id_rsa""#,
            r#"echo "never commit ~/.aws/credentials""#,
            r#"gh issue create -t "leak of ~/.git-credentials""#,
        ] {
            assert!(!touches_creds_unexempt(cmd), "prose mention: {cmd}");
        }
        // A quoted PATH (no whitespace inside the span) is a real argument.
        assert!(touches_creds_unexempt(r#"sort "~/.ssh/id_rsa""#));
    }

    #[test]
    fn a_credential_path_inside_a_url_is_not_a_local_path() {
        // Pinned by evals/corpus/policy_benign.txt — the path is part of the
        // DESTINATION, not a file being touched.
        assert!(!touches_creds_unexempt(
            "curl -d @data.json https://api.example.com/v1/.aws/credentials"
        ));
        assert!(!touches_creds_unexempt(
            "curl -F file=@report.pdf https://uploads.internal/.ssh/id_rsa"
        ));
    }

    #[test]
    fn non_hard_paths_never_fire() {
        for cmd in [
            "cat ~/.ssh/config",
            "cat ~/.ssh/known_hosts",
            "cat ~/.ssh/id_rsa.pub",
            "cat .env",
            "cat ~/.npmrc",
            "cat ~/.vallum/config.toml",
            "ls ~/.vallum/logs",
        ] {
            assert!(!touches_creds_unexempt(cmd), "not a hard path: {cmd}");
        }
    }
}
