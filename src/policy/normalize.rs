//! Shell no-op normalization: turn a command into ONE canonical candidate the
//! policy matcher can also try, collapsing shell rewrites that change a rule's
//! anchor token without changing what executes — quoting (`rm -rf "/"`),
//! backslash escapes (`rm -rf \/`), brace lists (`rm -rf /{bin,etc}`), and a
//! trailing `/.`. Composed on top of `normalize_for_match` so `$IFS` / empty-
//! quote / word-split obfuscation is handled first. Not a shell parser — this
//! only ADDS a match candidate; the raw command is matched separately.

use regex::Regex;
use std::sync::OnceLock;

/// Max comma-alternatives expanded for a single brace group.
const MAX_BRACE_ALTS: usize = 32;

/// Strip a one-level quoted span (single or double) whose inner text contains
/// no whitespace. A span WITH whitespace (`"rm -rf /"`) is left quoted — that is
/// the echo precision guard, the regex-world equivalent of `argv[0] == echo`.
fn dequote(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if c == '\'' || c == '"' {
            if let Some(close) = (i + 1..n).find(|&j| chars[j] == c) {
                let inner = &chars[i + 1..close];
                if !inner.iter().any(|ch| ch.is_whitespace()) {
                    out.extend(inner.iter());
                    i = close + 1;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Drop a backslash before any single non-whitespace char (`\/` -> `/`). A shell
/// no-op in unquoted context. Complements `normalize_for_match`, which already
/// handles `\<alnum>` and escaped spaces.
fn unescape(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < n {
        if chars[i] == '\\' && i + 1 < n && !chars[i + 1].is_whitespace() {
            out.push(chars[i + 1]);
            i += 2;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Expand the first comma-containing `{a,b,c}` brace group in place: the word
/// around the group is replicated once per alternative, space-joined
/// (`/{bin,etc}` -> `/bin /etc`). Bounded and non-nested; a group with no comma,
/// a nested brace, or more than `MAX_BRACE_ALTS` alternatives is left as-is.
/// One group is enough for the observed bypasses; the raw view still exists.
fn brace_expand(s: &str) -> String {
    let open = match s.find('{') {
        Some(o) => o,
        None => return s.to_string(),
    };
    let close = match s[open + 1..].find('}') {
        Some(c) => open + 1 + c,
        None => return s.to_string(),
    };
    let inner = &s[open + 1..close];
    if !inner.contains(',') || inner.contains('{') {
        return s.to_string();
    }
    let alts: Vec<&str> = inner.split(',').collect();
    if alts.len() > MAX_BRACE_ALTS {
        return s.to_string();
    }
    // UTF-8-safe word boundaries: advance past a whitespace char by its byte
    // length, never `+1` (a Unicode whitespace char may be multi-byte, and
    // slicing off a non-char-boundary panics — the command_views proptest feeds
    // arbitrary UTF-8).
    let word_start = match s[..open].char_indices().rev().find(|(_, c)| c.is_whitespace()) {
        Some((i, c)) => i + c.len_utf8(),
        None => 0,
    };
    let word_end = match s[close + 1..].char_indices().find(|(_, c)| c.is_whitespace()) {
        Some((i, _)) => close + 1 + i,
        None => s.len(),
    };
    let pre = &s[word_start..open];
    let post = &s[close + 1..word_end];
    let expanded: Vec<String> = alts.iter().map(|a| format!("{pre}{a}{post}")).collect();
    format!("{}{}{}", &s[..word_start], expanded.join(" "), &s[word_end..])
}

/// Collapse a `/.` path segment that is followed by `/`, whitespace, or the end
/// of the string, into `/` (`rm -rf /.` -> `rm -rf /`). A `/.` inside a name
/// (`~/.ssh`) is left alone. Uses a captured trailing char instead of lookahead
/// (the regex crate has none).
fn path_normalize(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"/\.(/|\s|$)").unwrap());
    re.replace_all(s, "/$1").to_string()
}

/// The full normalization: run the existing conservative de-obfuscator first,
/// then dequote, unescape, brace-expand, and path-normalize into one candidate.
pub(super) fn shell_normalize(cmd: &str) -> String {
    let base = super::normalize_for_match(cmd);
    let s = dequote(&base);
    let s = unescape(&s);
    let s = brace_expand(&s);
    path_normalize(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dequote_strips_whitespace_free_quoted_spans() {
        assert_eq!(dequote(r#"rm -rf "/""#), "rm -rf /");
        assert_eq!(dequote("rm -rf '/'"), "rm -rf /");
        assert_eq!(dequote(r#"rm "-rf" /"#), "rm -rf /");
        assert_eq!(dequote(r#"git push "--force""#), "git push --force");
    }

    #[test]
    fn dequote_keeps_spans_containing_whitespace() {
        // The echo precision guard: a quoted span with whitespace is NOT
        // unquoted, so `echo "rm -rf /"` never becomes a match candidate.
        assert_eq!(dequote(r#"echo "rm -rf /""#), r#"echo "rm -rf /""#);
        assert_eq!(
            dequote(r#"git commit -m "rm -rf cleanup""#),
            r#"git commit -m "rm -rf cleanup""#
        );
    }

    #[test]
    fn unescape_drops_backslash_before_punctuation() {
        assert_eq!(unescape(r"rm -rf \/"), "rm -rf /");
        assert_eq!(unescape(r"rm -rf /\."), "rm -rf /.");
    }

    #[test]
    fn brace_expand_expands_a_single_group_in_place() {
        assert_eq!(brace_expand("rm -rf /{bin,etc,usr}"), "rm -rf /bin /etc /usr");
        // `{/,}` -> alternatives `/` and empty
        assert_eq!(brace_expand("rm -rf {/,}"), "rm -rf / ");
    }

    #[test]
    fn brace_expand_leaves_non_lists_untouched() {
        assert_eq!(brace_expand("echo hello"), "echo hello");
        assert_eq!(
            brace_expand("rm -rf /path{no-comma}"),
            "rm -rf /path{no-comma}"
        );
    }

    #[test]
    fn path_normalize_collapses_trailing_dot() {
        assert_eq!(path_normalize("rm -rf /."), "rm -rf /");
        assert_eq!(path_normalize("rm -rf /. "), "rm -rf / ");
        // `/.` NOT followed by /, space or end is left alone (e.g. dotfiles)
        assert_eq!(path_normalize("cat ~/.ssh/id_rsa"), "cat ~/.ssh/id_rsa");
    }

    #[test]
    fn shell_normalize_composes_all_transforms() {
        assert_eq!(shell_normalize(r#"rm -rf "/""#), "rm -rf /");
        assert_eq!(shell_normalize(r"rm -rf \/"), "rm -rf /");
        assert_eq!(shell_normalize("rm -rf /."), "rm -rf /");
        assert_eq!(
            shell_normalize("rm -rf /{bin,etc,usr}"),
            "rm -rf /bin /etc /usr"
        );
        // combined $IFS + quote (normalize_for_match handles $IFS first)
        assert_eq!(shell_normalize(r#"rm${IFS}-rf${IFS}"/""#), "rm -rf /");
        // echo stays untouched (whitespace guard)
        assert_eq!(shell_normalize(r#"echo "rm -rf /""#), r#"echo "rm -rf /""#);
    }
}
