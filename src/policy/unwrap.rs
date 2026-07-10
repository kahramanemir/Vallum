//! Turn a command line into the bounded set of strings the policy matcher
//! should try: the raw line plus precision-safe views that surface a wrapped
//! or encoded inner command (shell `-c` / `eval` payloads, decoded `base64 -d`
//! output). Every view is text a shell genuinely executes, so reinterpreting
//! it never fires on a benign string that merely mentions a command.

/// Max recursion depth when unwrapping nested wrappers (`bash -c "sh -c ..."`).
const MAX_DEPTH: usize = 3;
/// Hard cap on the number of views returned, to bound pathological nesting.
const MAX_VIEWS: usize = 24;

/// Shell interpreters whose `-c` argument is executed as a command.
const INTERPRETERS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];
/// Shell control operators that, as a standalone token, start a new command
/// position — the next token is a command verb, not an argument.
const SEPARATORS: &[&str] = &["|", "||", "&&", ";", ";;", "&", "|&", "(", "{"];
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
/// command line for re-evaluation. Only a token in *command position* (first
/// token, or right after a `|`/`;`/`&&`/... separator) is treated as an
/// interpreter or `eval`, so a literal mention as an argument
/// (`echo bash -c '…'`, which a shell only prints) is never extracted.
/// `echo`/`printf` are not interpreters either, so their quoted arguments are
/// left alone.
fn extract_exec_payloads(cmd: &str) -> Vec<String> {
    let toks = tokenize(cmd);
    let mut out = Vec::new();
    let mut cmd_pos = true;
    for (i, t) in toks.iter().enumerate() {
        if cmd_pos {
            if t == "eval" {
                if let Some(p) = toks.get(i + 1) {
                    if !p.is_empty() {
                        out.push(p.clone());
                    }
                }
            }
            if INTERPRETERS.contains(&t.as_str()) {
                if let Some(pos) = toks[i + 1..].iter().position(|x| x == "-c") {
                    // don't scan across a separator into the next command
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
        cmd_pos = is_separator(t);
    }
    out
}

/// A standalone shell control operator token.
fn is_separator(tok: &str) -> bool {
    SEPARATORS.contains(&tok)
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
    fn interpreter_as_argument_is_not_extracted() {
        // `bash`/`eval` only count in command position; as a literal argument
        // to echo the shell just prints them, so nothing is executed.
        assert!(extract_exec_payloads("echo bash -c 'rm -rf /'").is_empty());
        assert!(extract_exec_payloads("echo eval 'rm -rf /'").is_empty());
    }

    #[test]
    fn interpreter_after_a_pipe_is_extracted() {
        // Piping into an interpreter IS a real exec — command position resets
        // after the `|` separator.
        let p = extract_exec_payloads("echo foo | bash -c 'rm -rf /'");
        assert!(p.contains(&"rm -rf /".to_string()), "got {p:?}");
    }
}
