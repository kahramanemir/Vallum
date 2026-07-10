//! Interactive multi-select picker for `install-hook`/`uninstall-hook`.
//! Pure selection state machine + rendering live here, separated from the
//! termios/ANSI layer so they are unit-testable without a TTY.
//! Ctrl-C/Ctrl-Z arrive as bytes (ISIG off) so cancel restores the
//! terminal; an external SIGTERM/SIGKILL bypasses the Drop guard and can
//! leave the terminal raw — `reset` / `stty sane` recovers.

use super::{agent_label, Agent, AgentStatus};

/// One selectable row.
#[derive(Debug, Clone)]
pub struct Row {
    pub agent: Agent,
    pub label: &'static str,
    pub hooked: bool,
    pub checked: bool,
}

impl Row {
    /// Install picker rows: every agent; detected-but-unhooked start checked.
    pub fn install_rows(statuses: &[(Agent, AgentStatus)]) -> Vec<Row> {
        statuses
            .iter()
            .map(|&(agent, s)| Row {
                agent,
                label: agent_label(agent),
                hooked: s.hooked,
                checked: s.detected && !s.hooked,
            })
            .collect()
    }

    /// Uninstall picker rows: only hooked agents, none preselected.
    pub fn uninstall_rows(statuses: &[(Agent, AgentStatus)]) -> Vec<Row> {
        statuses
            .iter()
            .filter(|(_, s)| s.hooked)
            .map(|&(agent, s)| Row {
                agent,
                label: agent_label(agent),
                hooked: s.hooked,
                checked: false,
            })
            .collect()
    }
}

/// A decoded keypress the picker reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Toggle,
    ToggleAll,
    Confirm,
    Cancel,
    Other,
}

/// Terminal outcome of the picker loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Confirmed,
    Cancelled,
}

/// Selection state: cursor position + per-row checkboxes.
pub struct SelectState {
    title: &'static str,
    rows: Vec<Row>,
    cursor: usize,
}

impl SelectState {
    /// `rows` must be non-empty — callers check before constructing.
    pub fn new(title: &'static str, rows: Vec<Row>) -> Self {
        assert!(!rows.is_empty(), "picker needs at least one row");
        SelectState {
            title,
            rows,
            cursor: 0,
        }
    }

    /// Apply one keypress. `Some` ends the loop; `None` keeps going.
    pub fn handle_key(&mut self, key: Key) -> Option<Outcome> {
        match key {
            Key::Up => {
                self.cursor = if self.cursor == 0 {
                    self.rows.len() - 1
                } else {
                    self.cursor - 1
                };
                None
            }
            Key::Down => {
                self.cursor = (self.cursor + 1) % self.rows.len();
                None
            }
            Key::Toggle => {
                self.rows[self.cursor].checked = !self.rows[self.cursor].checked;
                None
            }
            Key::ToggleAll => {
                let all = self.rows.iter().all(|r| r.checked);
                for r in &mut self.rows {
                    r.checked = !all;
                }
                None
            }
            Key::Confirm => Some(Outcome::Confirmed),
            Key::Cancel => Some(Outcome::Cancelled),
            Key::Other => None,
        }
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Agents currently checked, in row order.
    pub fn selected(&self) -> Vec<Agent> {
        self.rows
            .iter()
            .filter(|r| r.checked)
            .map(|r| r.agent)
            .collect()
    }
}

const BRONZE_BOLD: &str = "\x1b[1;38;5;178m";
const RESET: &str = "\x1b[0m";

impl SelectState {
    /// Render the full picker frame, every line newline-terminated. Plain
    /// text when `color` is false — callers gate color on TTY/NO_COLOR/TERM
    /// exactly like the welcome screen.
    pub fn render(&self, color: bool) -> String {
        let mut out = format!(
            "{} (space = toggle, enter = confirm, esc = cancel):\n\n",
            self.title
        );
        let width = self
            .rows
            .iter()
            .map(|r| r.label.chars().count())
            .max()
            .unwrap_or(0);
        for (i, row) in self.rows.iter().enumerate() {
            let pointer = if i == self.cursor { "❯" } else { " " };
            let mark = if row.checked { "x" } else { " " };
            let line = if row.hooked {
                format!(
                    "  {pointer} [{mark}] {:<width$}  (hook installed ✓)",
                    row.label
                )
            } else {
                format!("  {pointer} [{mark}] {}", row.label)
            };
            if color && i == self.cursor {
                out.push_str(BRONZE_BOLD);
                out.push_str(&line);
                out.push_str(RESET);
            } else {
                out.push_str(&line);
            }
            out.push('\n');
        }
        out.push_str(&format!("\n{} selected\n", self.selected().len()));
        out
    }
}

/// Decode one keypress from `input`. Because raw mode sets VMIN=0/VTIME=1,
/// a read can return 0 bytes after a 0.1 s timeout with no key pressed. On
/// the very first byte, that timeout surfaces as `Ok(None)` so the caller
/// polls again; after an ESC byte, the same timeout means no more bytes
/// followed, which is how a bare ESC press is distinguished from the start
/// of an arrow-key CSI (`ESC [ A`/`ESC [ B`) sequence.
pub fn read_key(input: &mut impl std::io::Read) -> std::io::Result<Option<Key>> {
    let mut b = [0u8; 1];
    if input.read(&mut b)? == 0 {
        return Ok(None);
    }
    Ok(Some(match b[0] {
        0x03 => Key::Cancel, // Ctrl-C arrives as a byte because ISIG is off
        b'\r' | b'\n' => Key::Confirm,
        b' ' => Key::Toggle,
        b'a' => Key::ToggleAll,
        b'q' => Key::Cancel,
        b'j' => Key::Down,
        b'k' => Key::Up,
        0x1b => {
            if input.read(&mut b)? == 0 {
                return Ok(Some(Key::Cancel)); // bare ESC
            }
            if b[0] != b'[' {
                return Ok(Some(Key::Other));
            }
            if input.read(&mut b)? == 0 {
                return Ok(Some(Key::Other));
            }
            match b[0] {
                b'A' => Key::Up,
                b'B' => Key::Down,
                _ => Key::Other,
            }
        }
        _ => Key::Other,
    }))
}

use std::io::Write;

/// Match the welcome screen's color policy: interactive stdout, NO_COLOR
/// unset, TERM != dumb.
fn color_enabled() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM")
            .map(|t| t != "dumb")
            .unwrap_or(true)
}

/// Restores the original termios and re-shows the terminal cursor on drop,
/// covering confirm, cancel, error, and panic paths alike.
struct RawMode {
    original: libc::termios,
}

impl RawMode {
    fn enable() -> Result<Self, String> {
        // SAFETY: FFI on stdin's fd; termios is a plain-old-data out-param.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut t) != 0 {
                return Err("terminal does not support raw mode (tcgetattr failed)".to_string());
            }
            let original = t;
            t.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
            t.c_cc[libc::VMIN] = 0; // reads may return 0 bytes…
            t.c_cc[libc::VTIME] = 1; // …after a 0.1 s timeout (ESC telling)
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) != 0 {
                return Err("terminal does not support raw mode (tcsetattr failed)".to_string());
            }
            Ok(RawMode { original })
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: restores the termios captured in enable().
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
        let _ = write!(std::io::stdout(), "\x1b[?25h"); // re-show the cursor
        let _ = std::io::stdout().flush();
    }
}

fn flush() -> Result<(), String> {
    std::io::stdout()
        .flush()
        .map_err(|e| format!("flush stdout: {e}"))
}

/// Run the picker on the current TTY. `Ok(Some(agents))` = confirmed
/// (possibly empty) selection; `Ok(None)` = cancelled; `Err` = raw mode
/// could not be established (caller should suggest --agent).
pub fn run_picker(mut state: SelectState) -> Result<Option<Vec<Agent>>, String> {
    let _raw = RawMode::enable()?;
    let color = color_enabled();
    let frame = state.render(color);
    // Row count is fixed, so the frame's line count never changes.
    let lines = frame.lines().count();
    print!("\x1b[?25l{frame}"); // hide cursor + first frame
    flush()?;
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    loop {
        let Some(key) = read_key(&mut stdin).map_err(|e| format!("read stdin: {e}"))? else {
            continue; // VTIME timeout — poll again
        };
        match state.handle_key(key) {
            None => {
                let frame = state.render(color);
                print!("\x1b[{lines}A\r\x1b[J{frame}"); // repaint in place
                flush()?;
            }
            Some(outcome) => {
                print!("\x1b[{lines}A\r\x1b[J"); // remove the picker
                flush()?;
                return Ok(match outcome {
                    Outcome::Confirmed => Some(state.selected()),
                    Outcome::Cancelled => None,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(agent: Agent, label: &'static str) -> Row {
        Row {
            agent,
            label,
            hooked: false,
            checked: false,
        }
    }

    fn state() -> SelectState {
        SelectState::new(
            "Select agents to hook",
            vec![
                row(Agent::Claude, "Claude Code"),
                row(Agent::Codex, "Codex CLI"),
                row(Agent::Cursor, "Cursor"),
                row(Agent::Gemini, "Gemini CLI"),
            ],
        )
    }

    #[test]
    fn cursor_wraps_both_directions() {
        let mut s = state();
        assert!(s.handle_key(Key::Up).is_none());
        assert_eq!(s.cursor(), 3, "Up from row 0 wraps to last row");
        s.handle_key(Key::Down);
        assert_eq!(s.cursor(), 0, "Down from last row wraps to 0");
        s.handle_key(Key::Down);
        assert_eq!(s.cursor(), 1);
    }

    #[test]
    fn space_toggles_cursor_row() {
        let mut s = state();
        s.handle_key(Key::Toggle);
        assert_eq!(s.selected(), vec![Agent::Claude]);
        s.handle_key(Key::Toggle);
        assert!(s.selected().is_empty());
    }

    #[test]
    fn toggle_all_checks_then_unchecks() {
        let mut s = state();
        s.handle_key(Key::ToggleAll);
        assert_eq!(
            s.selected(),
            vec![Agent::Claude, Agent::Codex, Agent::Cursor, Agent::Gemini]
        );
        s.handle_key(Key::ToggleAll);
        assert!(s.selected().is_empty());
    }

    #[test]
    fn toggle_all_from_partial_checks_all() {
        let mut s = state();
        s.handle_key(Key::Toggle); // claude on
        s.handle_key(Key::ToggleAll);
        assert_eq!(s.selected().len(), 4);
    }

    #[test]
    fn confirm_cancel_and_other() {
        let mut s = state();
        assert_eq!(s.handle_key(Key::Other), None);
        assert_eq!(s.handle_key(Key::Confirm), Some(Outcome::Confirmed));
        assert_eq!(s.handle_key(Key::Cancel), Some(Outcome::Cancelled));
    }

    #[test]
    fn selected_preserves_row_order() {
        let mut s = state();
        s.handle_key(Key::Down);
        s.handle_key(Key::Down); // cursor → Cursor row
        s.handle_key(Key::Toggle);
        s.handle_key(Key::Up);
        s.handle_key(Key::Up); // cursor → Claude row
        s.handle_key(Key::Toggle);
        assert_eq!(s.selected(), vec![Agent::Claude, Agent::Cursor]);
    }

    #[test]
    fn plain_render_matches_layout_exactly() {
        let mut s = state();
        s.rows[0].hooked = true;
        s.rows[0].checked = true;
        s.handle_key(Key::Down); // cursor on Codex
        let out = s.render(false);
        let expected = "Select agents to hook (space = toggle, enter = confirm, esc = cancel):\n\n    [x] Claude Code  (hook installed ✓)\n  ❯ [ ] Codex CLI\n    [ ] Cursor\n    [ ] Gemini CLI\n\n1 selected\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn plain_render_has_no_escape_codes() {
        assert!(!state().render(false).contains('\x1b'));
    }

    #[test]
    fn color_render_highlights_cursor_row_only() {
        let out = state().render(true);
        assert!(
            out.contains("\x1b[1;38;5;178m  ❯ [ ] Claude Code\x1b[0m"),
            "cursor row painted bronze; got: {out}"
        );
        assert_eq!(
            out.matches("\x1b[1;38;5;178m").count(),
            1,
            "exactly one painted row"
        );
    }

    #[test]
    fn render_pads_labels_so_hook_markers_align() {
        let mut s = SelectState::new(
            "Select agents to unhook",
            vec![
                {
                    let mut r = row(Agent::Cursor, "Cursor");
                    r.hooked = true;
                    r
                },
                {
                    let mut r = row(Agent::Claude, "Claude Code");
                    r.hooked = true;
                    r
                },
            ],
        );
        s.handle_key(Key::Other); // no-op; cursor stays on row 0
        let out = s.render(false);
        assert!(out.contains("  ❯ [ ] Cursor       (hook installed ✓)\n"));
        assert!(out.contains("    [ ] Claude Code  (hook installed ✓)\n"));
    }

    fn key(bytes: &[u8]) -> Option<Key> {
        let mut input = bytes;
        read_key(&mut input).unwrap()
    }

    #[test]
    fn decodes_plain_keys() {
        assert_eq!(key(b" "), Some(Key::Toggle));
        assert_eq!(key(b"\r"), Some(Key::Confirm));
        assert_eq!(key(b"\n"), Some(Key::Confirm));
        assert_eq!(key(b"a"), Some(Key::ToggleAll));
        assert_eq!(key(b"q"), Some(Key::Cancel));
        assert_eq!(key(b"j"), Some(Key::Down));
        assert_eq!(key(b"k"), Some(Key::Up));
        assert_eq!(key(&[0x03]), Some(Key::Cancel), "Ctrl-C byte with ISIG off");
        assert_eq!(key(b"z"), Some(Key::Other));
    }

    #[test]
    fn decodes_arrow_sequences() {
        assert_eq!(key(b"\x1b[A"), Some(Key::Up));
        assert_eq!(key(b"\x1b[B"), Some(Key::Down));
        assert_eq!(key(b"\x1b[C"), Some(Key::Other), "right arrow ignored");
    }

    #[test]
    fn bare_esc_cancels_and_esc_junk_is_ignored() {
        assert_eq!(key(b"\x1b"), Some(Key::Cancel), "bare ESC (timeout after)");
        assert_eq!(key(b"\x1bx"), Some(Key::Other));
        assert_eq!(key(b"\x1b["), Some(Key::Other), "truncated CSI");
    }

    #[test]
    fn zero_byte_read_is_none() {
        assert_eq!(key(b""), None, "VTIME timeout surfaces as None");
    }

    fn st(detected: bool, hooked: bool) -> crate::install_hook::AgentStatus {
        crate::install_hook::AgentStatus { detected, hooked }
    }

    #[test]
    fn install_rows_preselect_detected_unhooked() {
        let rows = Row::install_rows(&[
            (Agent::Claude, st(true, true)),   // hooked → unchecked
            (Agent::Codex, st(true, false)),   // detected, unhooked → checked
            (Agent::Cursor, st(false, false)), // absent → unchecked
            (Agent::Gemini, st(true, false)),  // detected, unhooked → checked
        ]);
        assert_eq!(rows.len(), 4, "install lists every agent");
        let checked: Vec<Agent> = rows.iter().filter(|r| r.checked).map(|r| r.agent).collect();
        assert_eq!(checked, vec![Agent::Codex, Agent::Gemini]);
        assert!(rows[0].hooked, "hooked marker carried through");
        assert_eq!(rows[0].label, "Claude Code");
    }

    #[test]
    fn uninstall_rows_list_only_hooked_none_checked() {
        let rows = Row::uninstall_rows(&[
            (Agent::Claude, st(true, true)),
            (Agent::Codex, st(true, false)),
            (Agent::Cursor, st(true, true)),
            (Agent::Gemini, st(false, false)),
        ]);
        let agents: Vec<Agent> = rows.iter().map(|r| r.agent).collect();
        assert_eq!(agents, vec![Agent::Claude, Agent::Cursor]);
        assert!(rows.iter().all(|r| !r.checked));
        assert!(rows.iter().all(|r| r.hooked));
    }
}
