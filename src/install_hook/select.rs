//! Interactive multi-select picker for `install-hook`/`uninstall-hook`.
//! Pure selection state machine + rendering live here, separated from the
//! termios/ANSI layer so they are unit-testable without a TTY.

use super::Agent;

/// One selectable row.
#[derive(Debug, Clone)]
pub struct Row {
    pub agent: Agent,
    pub label: &'static str,
    pub hooked: bool,
    pub checked: bool,
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
}
