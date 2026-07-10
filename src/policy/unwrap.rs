//! Turn a command line into the bounded set of strings the policy matcher
//! should try: the raw line plus precision-safe views that surface a wrapped
//! or encoded inner command (shell `-c` / `eval` payloads, decoded `base64 -d`
//! output). Every view is text a shell genuinely executes, so reinterpreting
//! it never fires on a benign string that merely mentions a command.

use regex::Regex;
use std::sync::OnceLock;

/// Max recursion depth when unwrapping nested wrappers (`bash -c "sh -c ..."`).
const MAX_DEPTH: usize = 3;
/// Hard cap on the number of views returned, to bound pathological nesting.
const MAX_VIEWS: usize = 24;

/// Shell interpreters whose `-c` argument is executed as a command.
const INTERPRETERS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];
/// Shell control operators that, as a standalone token, end the current command
/// and start a new one (the next verb belongs to a fresh command group).
const SEPARATORS: &[&str] = &["|", "||", "&&", ";", ";;", "&", "|&", "(", "{"];
/// Command-group lead verbs that only PRINT their arguments — they never
/// execute an interpreter passed as an argument, so `echo bash -c '…'` is a
/// benign mention. Kept deliberately small: a missing entry only costs a
/// fail-safe extra Ask, whereas a wrong entry would silently skip a real exec.
const PRINT_LEADS: &[&str] = &["echo", "printf", ":"];
/// Cap on tokens scanned per command line.
const MAX_TOKENS: usize = 64;

/// Read one shell-ish word from the start of `s`, skipping leading whitespace.
/// A word is a single/double-quoted span (returned unquoted, one level) or a
/// run of non-whitespace. Returns the word and the remaining slice, or None if
/// only whitespace is left. Not a full shell parser — enough to find and unwrap
/// exec payloads.
fn read_word(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    let first = s.chars().next()?;
    if first == '\'' || first == '"' {
        let rest = &s[first.len_utf8()..];
        match rest.find(first) {
            Some(end) => Some((rest[..end].to_string(), &rest[end + first.len_utf8()..])),
            None => Some((rest.to_string(), "")),
        }
    } else {
        let end = s.find(char::is_whitespace).unwrap_or(s.len());
        Some((s[..end].to_string(), &s[end..]))
    }
}

/// Split a command line into shell-ish words via repeated `read_word`, bounded.
fn tokenize(cmd: &str) -> Vec<String> {
    let mut toks = Vec::new();
    let mut rest = cmd;
    while let Some((w, next)) = read_word(rest) {
        toks.push(w);
        if toks.len() >= MAX_TOKENS || next.len() >= rest.len() {
            break; // bound + no-progress guard
        }
        rest = next;
    }
    toks
}

/// Extract the arguments a shell would execute: an interpreter's `-c` argument
/// and an `eval` argument. Unquoted one level so the returned string is a clean
/// command line for re-evaluation.
///
/// Defaults to extracting (max recall — a wrapped danger should still be seen),
/// and suppresses only when the interpreter's command group is led by a
/// print-only verb (`echo bash -c '…'`, which a shell merely prints). This
/// keeps wrapper-prefixed real execs (`sudo`/`env`/`timeout`/`FOO=bar bash -c
/// '…'`) firing while dropping the benign mention. Being wrong about a lead
/// verb only costs a fail-safe extra Ask, never a missed exec.
fn extract_exec_payloads(cmd: &str) -> Vec<String> {
    let toks = tokenize(cmd);
    let mut out = Vec::new();
    // Lead verb of the current command group (reset at each separator, set to
    // the first non-assignment token after it). Skipping env-assignments lets
    // `FOO=bar bash -c '…'` still be led by `bash`.
    let mut group_lead: Option<&str> = None;
    for (i, t) in toks.iter().enumerate() {
        if is_separator(t) {
            group_lead = None;
            continue;
        }
        if group_lead.is_none() && !is_env_assignment(t) {
            group_lead = Some(t);
        }
        if group_lead.is_some_and(|v| PRINT_LEADS.contains(&v)) {
            continue; // benign mention — the group only prints its arguments
        }
        if t == "eval" {
            if let Some(p) = toks.get(i + 1) {
                if !p.is_empty() {
                    out.push(p.clone());
                }
            }
        }
        if INTERPRETERS.contains(&t.as_str()) {
            if let Some(pos) = toks[i + 1..].iter().position(|x| x == "-c") {
                // don't scan across a separator into the next command group
                let crossed = toks[i + 1..i + 1 + pos].iter().any(|x| is_separator(x));
                if !crossed {
                    if let Some(p) = toks.get(i + 1 + pos + 1) {
                        if !p.is_empty() {
                            out.push(p.clone());
                        }
                    }
                }
            }
        }
    }
    out
}

/// A standalone shell control operator token.
fn is_separator(tok: &str) -> bool {
    SEPARATORS.contains(&tok)
}

/// A leading environment assignment (`FOO=bar`) — a prefix that does not change
/// the command verb, so it is skipped when finding a group's lead.
fn is_env_assignment(tok: &str) -> bool {
    match tok.find('=') {
        Some(eq) if eq > 0 => {
            let name = &tok[..eq];
            name.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        _ => false,
    }
}

/// Cap on base64 tokens decoded per command line.
const MAX_DECODES: usize = 6;

/// Decode standard base64 (`+`/`/` alphabet, optional `=` padding) to a UTF-8
/// string. Returns None on an invalid character or non-UTF-8 output. Hand-rolled
/// to avoid a dependency; input is a single command-line token, so unbounded
/// growth is not a concern.
fn b64_decode(s: &str) -> Option<String> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut n = 0usize;
    for c in s.bytes().filter(|&b| b != b'=') {
        buf = (buf << 6) | val(c)?;
        bits += 6;
        n += 1;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    if n < 2 {
        return None;
    }
    String::from_utf8(out).ok()
}

/// If the command invokes `base64 -d`/`--decode`, decode base64-ish tokens and
/// return their UTF-8 output. Gating on the decode flag keeps this
/// attacker-specific: a benign command that merely contains a base64-looking
/// token is not decoded.
fn decode_base64_payloads(cmd: &str) -> Vec<String> {
    static DECODE: OnceLock<Regex> = OnceLock::new();
    let decode =
        DECODE.get_or_init(|| Regex::new(r"(?i)\bbase64\b[^|\n]*\s(?:-d|-D|--decode)\b").unwrap());
    if !decode.is_match(cmd) {
        return Vec::new();
    }
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    let token = TOKEN.get_or_init(|| Regex::new(r"[A-Za-z0-9+/]{8,}={0,2}").unwrap());
    let mut out = Vec::new();
    for m in token.find_iter(cmd).take(MAX_DECODES) {
        if let Some(decoded) = b64_decode(m.as_str()) {
            out.push(decoded);
        }
    }
    out
}

/// The raw command plus every precision-safe derived view, deduplicated and
/// bounded. View 0 is always the raw line, so raw matches are never lost.
pub fn command_views(cmd: &str) -> Vec<String> {
    let mut views: Vec<String> = Vec::new();
    let mut queue: Vec<(String, usize)> = vec![(cmd.to_string(), 0)];
    while let Some((c, depth)) = queue.pop() {
        if views.len() >= MAX_VIEWS {
            break;
        }
        if views.iter().any(|v| v == &c) {
            continue;
        }
        views.push(c.clone());
        if depth >= MAX_DEPTH {
            continue;
        }
        for payload in extract_exec_payloads(&c) {
            queue.push((payload, depth + 1));
        }
        for decoded in decode_base64_payloads(&c) {
            queue.push((decoded, depth + 1));
        }
    }
    views
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_line_is_always_view_zero() {
        let v = command_views("rm -rf /");
        assert_eq!(v[0], "rm -rf /");
    }

    #[test]
    fn deduplicates_identical_views() {
        let v = command_views("ls");
        assert_eq!(v.iter().filter(|s| *s == "ls").count(), 1);
    }

    #[test]
    fn reads_single_quoted_word() {
        let (w, rest) = read_word("'rm -rf /' next").unwrap();
        assert_eq!(w, "rm -rf /");
        assert_eq!(rest.trim_start(), "next");
    }

    #[test]
    fn reads_bare_word() {
        let (w, rest) = read_word("bash -c x").unwrap();
        assert_eq!(w, "bash");
        assert_eq!(rest.trim_start(), "-c x");
    }

    #[test]
    fn extracts_shell_dash_c_payload() {
        let p = extract_exec_payloads("bash -c 'rm -rf /'");
        assert!(p.contains(&"rm -rf /".to_string()), "got {p:?}");
    }

    #[test]
    fn extracts_eval_payload() {
        let p = extract_exec_payloads("eval \"rm -rf /\"");
        assert!(p.contains(&"rm -rf /".to_string()), "got {p:?}");
    }

    #[test]
    fn echo_is_not_an_interpreter() {
        let p = extract_exec_payloads("echo \"rm -rf /\"");
        assert!(p.is_empty(), "echo must not be unwrapped: {p:?}");
    }

    #[test]
    fn unwrapped_payload_becomes_a_view() {
        let v = command_views("bash -c 'rm -rf /'");
        assert!(v.contains(&"rm -rf /".to_string()), "views: {v:?}");
    }

    #[test]
    fn print_led_interpreter_mention_is_not_extracted() {
        // A group led by a print-only verb only prints its arguments, so the
        // interpreter mention is benign and nothing is extracted.
        assert!(extract_exec_payloads("echo bash -c 'rm -rf /'").is_empty());
        assert!(extract_exec_payloads("echo eval 'rm -rf /'").is_empty());
        assert!(extract_exec_payloads("printf '%s' bash -c 'rm -rf /'").is_empty());
    }

    #[test]
    fn interpreter_after_a_pipe_is_extracted() {
        // Piping into an interpreter IS a real exec — the group resets after
        // the `|` separator, so `bash` leads a fresh group.
        let p = extract_exec_payloads("echo foo | bash -c 'rm -rf /'");
        assert!(p.contains(&"rm -rf /".to_string()), "got {p:?}");
    }

    #[test]
    fn wrapper_prefixed_interpreter_is_extracted() {
        // sudo/env/timeout/env-assignment prefixes do execute the interpreter
        // they wrap — these must still be unwrapped (raw view doesn't catch
        // them because the closing quote defeats the rule's end anchor).
        for cmd in [
            "sudo bash -c 'rm -rf /'",
            "env bash -c 'rm -rf /'",
            "timeout 5 bash -c 'rm -rf /'",
            "FOO=bar bash -c 'rm -rf /'",
        ] {
            let p = extract_exec_payloads(cmd);
            assert!(p.contains(&"rm -rf /".to_string()), "{cmd} -> {p:?}");
        }
    }

    #[test]
    fn decodes_standard_base64() {
        // "rm -rf /" -> cm0gLXJmIC8=
        assert_eq!(b64_decode("cm0gLXJmIC8=").as_deref(), Some("rm -rf /"));
    }

    #[test]
    fn base64_only_decoded_when_decode_flag_present() {
        // No `base64 -d` in the line -> the token is not decoded.
        assert!(decode_base64_payloads("echo cm0gLXJmIC8=").is_empty());
        // With a decode invocation -> decoded.
        let p = decode_base64_payloads("echo cm0gLXJmIC8= | base64 -d | sh");
        assert!(p.contains(&"rm -rf /".to_string()), "got {p:?}");
    }

    #[test]
    fn encoded_payload_becomes_a_view() {
        let v = command_views("echo cm0gLXJmIC8= | base64 -d | sh");
        assert!(v.contains(&"rm -rf /".to_string()), "views: {v:?}");
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn command_views_never_panics(s in "[\\s\\S]{0,300}") {
            let v = command_views(&s);
            prop_assert!(v.len() <= super::MAX_VIEWS);
        }
    }
}
