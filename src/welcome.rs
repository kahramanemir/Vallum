//! The bare-`vallum` welcome screen: a branded status + quick-start banner.
//!
//! `render` is pure (fully testable); color is decided by the caller so tests
//! and piped output stay deterministic.

/// Hook install state for one agent, as shown on the welcome screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookState {
    /// Agent detected and the Vallum hook entry is present.
    Installed,
    /// Agent detected but no Vallum hook entry.
    NotInstalled,
    /// Agent config dir not present on this machine.
    AgentAbsent,
    /// Hook/settings file exists but could not be read or parsed.
    Unknown,
}

/// Guardrail summary for the welcome screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardrailState {
    On { active_rules: usize },
    Off,
    Unknown,
}

pub struct WelcomeStatus {
    pub guardrail: GuardrailState,
    pub claude: HookState,
    pub codex: HookState,
    pub gemini: HookState,
    pub cursor: HookState,
}

// Welcome-screen-only SGR codes (spec palette). `run`'s output pipeline is
// untouched; these never appear when `use_color` is false.
const BRONZE: &str = "\x1b[1;38;5;178m";
const BRONZE_DARK: &str = "\x1b[38;5;136m";
const GRAY: &str = "\x1b[38;5;245m";
const GREEN: &str = "\x1b[38;5;114m";
const RED: &str = "\x1b[38;5;167m";
const RESET: &str = "\x1b[0m";

const LOGO_TOP: &str = "█▀▀▀█▀▀▀█▀▀▀█";
const LOGO_BOTTOM: &str = "█▄▄▄█▄▄▄█▄▄▄█";
const TAGLINE: &str = "The wall between AI agents and your shell";

fn paint(s: &str, color: &str, use_color: bool) -> String {
    if use_color {
        format!("{color}{s}{RESET}")
    } else {
        s.to_string()
    }
}

fn guardrail_detail(g: &GuardrailState, use_color: bool) -> String {
    match g {
        GuardrailState::On { active_rules } => format!(
            "{} — {} rules active",
            paint("on", GREEN, use_color),
            active_rules
        ),
        GuardrailState::Off => format!(
            "{} — commands run ungated (security.guardrail = false)",
            paint("off", RED, use_color)
        ),
        GuardrailState::Unknown => format!(
            "{} — config error, run vallum doctor",
            paint("unknown", GRAY, use_color)
        ),
    }
}

/// One `name <marker>` cell for the Hooks line. Codex additionally reminds
/// about its one-time hook trust when installed (Codex silently skips
/// untrusted hooks — see SECURITY.md).
fn hook_token(name: &str, state: HookState, trust_note: bool, use_color: bool) -> String {
    let mark = match state {
        HookState::Installed => paint("✓", GREEN, use_color),
        HookState::NotInstalled => paint("✗", RED, use_color),
        HookState::AgentAbsent => paint("—", GRAY, use_color),
        HookState::Unknown => paint("?", GRAY, use_color),
    };
    let mut cell = format!("{name} {mark}");
    if trust_note && state == HookState::Installed {
        cell.push(' ');
        cell.push_str(&paint("(trust!)", GRAY, use_color));
    }
    cell
}

pub fn render(status: &WelcomeStatus, use_color: bool) -> String {
    let title = format!("VALLUM v{}", env!("CARGO_PKG_VERSION"));
    let hooks = [
        hook_token("claude", status.claude, false, use_color),
        hook_token("codex", status.codex, true, use_color),
        hook_token("gemini", status.gemini, false, use_color),
        hook_token("cursor", status.cursor, false, use_color),
    ]
    .join("  ");

    format!(
        "{logo_top}   {title}\n\
         {logo_bottom}   {tagline}\n\
         \n\
         \x20 {guardrail_label}   {guardrail}\n\
         \x20 {hooks_label}       {hooks}\n\
         \n\
         \x20 {get_started}\n\
         \x20   vallum install-hook --agent claude    {hint_hook}\n\
         \x20   vallum run -- <cmd>                   {hint_run}\n\
         \x20   vallum doctor                         {hint_doctor}\n\
         \n\
         \x20 {help_line}\n",
        logo_top = paint(LOGO_TOP, BRONZE, use_color),
        logo_bottom = paint(LOGO_BOTTOM, BRONZE_DARK, use_color),
        title = paint(&title, BRONZE, use_color),
        tagline = TAGLINE,
        guardrail_label = paint("Guardrail", BRONZE, use_color),
        guardrail = guardrail_detail(&status.guardrail, use_color),
        hooks_label = paint("Hooks", BRONZE, use_color),
        hooks = hooks,
        get_started = paint("Get started:", BRONZE, use_color),
        hint_hook = paint("hook your agent", GRAY, use_color),
        hint_run = paint("gate a single command", GRAY, use_color),
        hint_doctor = paint("full health check", GRAY, use_color),
        help_line = paint("vallum --help for all commands", GRAY, use_color),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_status() -> WelcomeStatus {
        WelcomeStatus {
            guardrail: GuardrailState::On { active_rules: 10 },
            claude: HookState::Installed,
            codex: HookState::Installed,
            gemini: HookState::NotInstalled,
            cursor: HookState::AgentAbsent,
        }
    }

    #[test]
    fn plain_render_matches_spec_layout_exactly() {
        let out = render(&sample_status(), false);
        let expected = format!(
            "█▀▀▀█▀▀▀█▀▀▀█   VALLUM v{}\n\
             █▄▄▄█▄▄▄█▄▄▄█   The wall between AI agents and your shell\n\
             \n\
             \x20 Guardrail   on — 10 rules active\n\
             \x20 Hooks       claude ✓  codex ✓ (trust!)  gemini ✗  cursor —\n\
             \n\
             \x20 Get started:\n\
             \x20   vallum install-hook --agent claude    hook your agent\n\
             \x20   vallum run -- <cmd>                   gate a single command\n\
             \x20   vallum doctor                         full health check\n\
             \n\
             \x20 vallum --help for all commands\n",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn plain_render_contains_no_escape_codes() {
        assert!(!render(&sample_status(), false).contains('\x1b'));
    }

    #[test]
    fn color_render_paints_title_and_markers() {
        let out = render(&sample_status(), true);
        assert!(
            out.contains("\x1b[1;38;5;178mVALLUM v"),
            "bronze bold title"
        );
        assert!(out.contains("\x1b[38;5;114m✓\x1b[0m"), "green check");
        assert!(out.contains("\x1b[38;5;167m✗\x1b[0m"), "red cross");
        assert!(out.contains("\x1b[38;5;245m—\x1b[0m"), "gray dash");
        assert!(
            out.contains("\x1b[38;5;245m(trust!)\x1b[0m"),
            "gray trust note"
        );
    }

    #[test]
    fn guardrail_off_and_unknown_variants() {
        let mut s = sample_status();
        s.guardrail = GuardrailState::Off;
        assert!(
            render(&s, false).contains("off — commands run ungated (security.guardrail = false)")
        );
        s.guardrail = GuardrailState::Unknown;
        assert!(render(&s, false).contains("unknown — config error, run vallum doctor"));
    }

    #[test]
    fn unknown_hook_state_renders_question_mark() {
        let mut s = sample_status();
        s.gemini = HookState::Unknown;
        assert!(render(&s, false).contains("gemini ?"));
    }
}
