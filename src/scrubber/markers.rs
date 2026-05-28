// src/scrubber/markers.rs

/// Neutralize any wrapper markers embedded in the content so untrusted output
/// cannot forge an early close of the wrapper.
pub fn defang(text: &str) -> String {
    text.replace(
        "[UNTRUSTED TERMINAL OUTPUT START]",
        "(untrusted terminal output start)",
    )
    .replace(
        "[UNTRUSTED TERMINAL OUTPUT END]",
        "(untrusted terminal output end)",
    )
}
