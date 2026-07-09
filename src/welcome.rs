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
        GuardrailState::On { active_rules } => {
            let noun = if *active_rules == 1 { "rule" } else { "rules" };
            format!(
                "{} — {active_rules} {noun} active",
                paint("on", GREEN, use_color)
            )
        }
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

use std::path::{Path, PathBuf};

/// Classify one agent's hook install state. Best-effort: every failure mode
/// maps to a `HookState`, never an error.
pub fn hook_state(
    agent_dir: &Path,
    hooks_path: &Path,
    has_hook: fn(&serde_json::Value) -> bool,
) -> HookState {
    if !agent_dir.exists() {
        return HookState::AgentAbsent;
    }
    match crate::install_hook::read_settings(hooks_path) {
        Ok(settings) => {
            if has_hook(&settings) {
                HookState::Installed
            } else {
                HookState::NotInstalled
            }
        }
        Err(_) => HookState::Unknown,
    }
}

/// `hook_state` driven by the installer's own `config_path()`; an Err (no
/// home directory) is Unknown — we cannot probe what we cannot locate.
fn hook_state_at(
    config_path: Result<PathBuf, String>,
    has_hook: fn(&serde_json::Value) -> bool,
) -> HookState {
    match config_path {
        Ok(path) => {
            let agent_dir = path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            hook_state(&agent_dir, &path, has_hook)
        }
        Err(_) => HookState::Unknown,
    }
}

/// Guardrail summary from a config-load result. Active = built-ins minus
/// disabled built-ins, plus user rules ([policy] disabled only filters
/// built-in names, so user rules always count).
pub fn guardrail_state(loaded: Result<crate::config::AppConfig, String>) -> GuardrailState {
    match loaded {
        Ok(cfg) if cfg.security.guardrail => {
            let builtin_active = crate::policy::builtin_names()
                .iter()
                .filter(|name| !cfg.policy.disabled.iter().any(|d| d == *name))
                .count();
            GuardrailState::On {
                active_rules: builtin_active + cfg.policy.rules.len(),
            }
        }
        Ok(_) => GuardrailState::Off,
        Err(_) => GuardrailState::Unknown,
    }
}

/// Gather live status from the real environment. Never panics; every probe
/// degrades to an "unknown"-ish state instead.
pub fn gather() -> WelcomeStatus {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));

    let claude_dir = home.join(".claude");
    let claude_settings = crate::install_hook::settings_path(crate::install_hook::Level::User)
        .unwrap_or_else(|_| claude_dir.join("settings.json"));

    let config_path = crate::config::config_path_from_env_or_default();

    WelcomeStatus {
        guardrail: guardrail_state(crate::config::AppConfig::from_path(&config_path)),
        claude: hook_state(
            &claude_dir,
            &claude_settings,
            crate::install_hook::has_vallum_hook,
        ),
        codex: hook_state_at(
            crate::install_hook::codex::config_path(),
            crate::install_hook::codex::has_hook,
        ),
        gemini: hook_state_at(
            crate::install_hook::gemini::config_path(),
            crate::install_hook::gemini::has_hook,
        ),
        cursor: hook_state_at(
            crate::install_hook::cursor::config_path(),
            crate::install_hook::cursor::has_hook,
        ),
    }
}

/// Print the welcome screen to stdout. Color only on an interactive stdout
/// with NO_COLOR unset and TERM != dumb.
pub fn print() {
    use std::io::IsTerminal;
    let use_color = std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var_os("TERM")
            .map(|t| t != "dumb")
            .unwrap_or(true);
    print!("{}", render(&gather(), use_color));
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
    fn guardrail_one_rule_is_singular() {
        let mut s = sample_status();
        s.guardrail = GuardrailState::On { active_rules: 1 };
        let out = render(&s, false);
        assert!(out.contains("on — 1 rule active"), "{out}");
        assert!(!out.contains("1 rules active"));
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

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vallum-welcome-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn hook_state_classifies_all_four_cases() {
        let dir = temp_dir("hookstate");
        let agent_dir = dir.join(".codex");
        let hooks = agent_dir.join("hooks.json");

        // Agent dir absent → AgentAbsent.
        assert_eq!(
            hook_state(&agent_dir, &hooks, crate::install_hook::codex::has_hook),
            HookState::AgentAbsent
        );

        // Agent dir present, hooks file missing → NotInstalled.
        std::fs::create_dir_all(&agent_dir).unwrap();
        assert_eq!(
            hook_state(&agent_dir, &hooks, crate::install_hook::codex::has_hook),
            HookState::NotInstalled
        );

        // Vallum entry present → Installed.
        std::fs::write(
            &hooks,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"vallum hook --agent codex"}]}]}}"#,
        )
        .unwrap();
        assert_eq!(
            hook_state(&agent_dir, &hooks, crate::install_hook::codex::has_hook),
            HookState::Installed
        );

        // Malformed JSON → Unknown.
        std::fs::write(&hooks, "{not json").unwrap();
        assert_eq!(
            hook_state(&agent_dir, &hooks, crate::install_hook::codex::has_hook),
            HookState::Unknown
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)] // building config variants is clearer this way
    fn guardrail_state_from_config_result() {
        // Defaults: guardrail on, all built-ins active, no user rules.
        let on = guardrail_state(Ok(crate::config::AppConfig::default()));
        assert_eq!(
            on,
            GuardrailState::On {
                active_rules: crate::policy::builtin_names().len()
            }
        );

        // guardrail = false → Off.
        let mut cfg = crate::config::AppConfig::default();
        cfg.security.guardrail = false;
        assert_eq!(guardrail_state(Ok(cfg)), GuardrailState::Off);

        // Disabled built-in reduces the count.
        let mut cfg = crate::config::AppConfig::default();
        cfg.policy.disabled = vec!["rm_rf_root".to_string()];
        assert_eq!(
            guardrail_state(Ok(cfg)),
            GuardrailState::On {
                active_rules: crate::policy::builtin_names().len() - 1
            }
        );

        // Broken config → Unknown.
        assert_eq!(
            guardrail_state(Err("boom".to_string())),
            GuardrailState::Unknown
        );
    }
}
