//! Turn a command line into the bounded set of strings the policy matcher
//! should try: the raw line plus precision-safe views that surface a wrapped
//! or encoded inner command (shell `-c` / `eval` payloads, decoded `base64 -d`
//! output). Every view is text a shell genuinely executes, so reinterpreting
//! it never fires on a benign string that merely mentions a command.

/// Max recursion depth when unwrapping nested wrappers (`bash -c "sh -c ..."`).
const MAX_DEPTH: usize = 3;
/// Hard cap on the number of views returned, to bound pathological nesting.
const MAX_VIEWS: usize = 24;

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
        // Derived views are added by later tasks (exec payloads, base64).
        let _ = &c;
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
}
