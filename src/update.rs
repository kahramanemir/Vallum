//! `vallum update`: report whether a newer release exists and how to get it.
//!
//! Detects how the running binary was installed (from its own path) and prints
//! the right upgrade command. The latest-version check is best-effort via
//! `curl` against the crates.io sparse index — no HTTP dependency, and the
//! method/command guidance still works if the network lookup fails. By default
//! it only PRINTS the upgrade command; `--run` executes it (package managers
//! only — a standalone `curl | sh` installer is never auto-run).

use std::path::Path;

/// How the running `vallum` binary was installed, inferred from its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMethod {
    Cargo,
    Homebrew,
    Npm,
    Standalone,
}

impl InstallMethod {
    /// Human-readable label for the report.
    pub fn label(self) -> &'static str {
        match self {
            InstallMethod::Cargo => "cargo",
            InstallMethod::Homebrew => "Homebrew",
            InstallMethod::Npm => "npm",
            InstallMethod::Standalone => "standalone",
        }
    }

    /// The upgrade command to display for this install method.
    pub fn upgrade_display(self) -> &'static str {
        match self {
            InstallMethod::Cargo => "cargo install vallum --force",
            InstallMethod::Homebrew => "brew upgrade vallum",
            InstallMethod::Npm => "npm install -g vallum",
            InstallMethod::Standalone => {
                "curl -LsSf https://github.com/kahramanemir/Vallum/releases/latest/download/vallum-installer.sh | sh"
            }
        }
    }

    /// argv for `--run`, or None when the upgrade can't be safely auto-run
    /// (standalone pipes `curl` into a shell — exactly what Vallum warns about,
    /// so we print it instead of executing it).
    pub fn upgrade_argv(self) -> Option<&'static [&'static str]> {
        match self {
            InstallMethod::Cargo => Some(&["cargo", "install", "vallum", "--force"]),
            InstallMethod::Homebrew => Some(&["brew", "upgrade", "vallum"]),
            InstallMethod::Npm => Some(&["npm", "install", "-g", "vallum"]),
            InstallMethod::Standalone => None,
        }
    }
}

/// Infer the install method from the running binary's path.
pub fn detect_install_method(exe: &Path) -> InstallMethod {
    let p = exe.to_string_lossy();
    if p.contains("/.cargo/") {
        InstallMethod::Cargo
    } else if p.contains("/Cellar/") || p.contains("/Caskroom/") || p.contains("/homebrew/") {
        InstallMethod::Homebrew
    } else if p.contains("/node_modules/") {
        InstallMethod::Npm
    } else {
        InstallMethod::Standalone
    }
}

/// The latest non-yanked version from a crates.io sparse-index body
/// (newline-delimited JSON, one object per published version in publish order).
pub fn parse_latest_from_index(body: &str) -> Option<String> {
    body.lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .find_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            if v.get("yanked").and_then(|y| y.as_bool()).unwrap_or(false) {
                return None;
            }
            v.get("vers")?.as_str().map(str::to_string)
        })
}

/// Parse `x.y.z`, ignoring any `-pre` / `+build` suffix.
fn semver_core(v: &str) -> (u64, u64, u64) {
    let core = v.split(['+', '-']).next().unwrap_or(v);
    let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// True if `latest` is a newer release than `current`.
pub fn is_outdated(current: &str, latest: &str) -> bool {
    semver_core(latest) > semver_core(current)
}

/// Best-effort latest-version lookup via `curl` against the crates.io sparse
/// index (all release channels publish the same version, so one source
/// suffices). No HTTP dependency; any failure degrades to method-only advice.
fn fetch_latest() -> Result<String, String> {
    let out = std::process::Command::new("curl")
        .args([
            "-sSf",
            "--max-time",
            "10",
            "https://index.crates.io/va/ll/vallum",
        ])
        .output()
        .map_err(|e| format!("could not run curl ({e})"))?;
    if !out.status.success() {
        return Err("network lookup failed".to_string());
    }
    let body = String::from_utf8(out.stdout).map_err(|_| "non-UTF-8 response".to_string())?;
    parse_latest_from_index(&body).ok_or_else(|| "could not parse the index".to_string())
}

/// Entry point for `vallum update`. Exit code: 0 = up to date or advice
/// printed; 10 = `--check` and a newer version exists; 1 = `--run` upgrade
/// failed.
pub fn run(check: bool, run_upgrade: bool) -> i32 {
    let current = env!("CARGO_PKG_VERSION");
    let method = std::env::current_exe()
        .ok()
        .map(|p| detect_install_method(&p))
        .unwrap_or(InstallMethod::Standalone);

    let latest = match fetch_latest() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vallum update: couldn't check for the latest version ({e}).");
            println!("vallum {current} (installed via {})", method.label());
            println!("to upgrade, run:\n    {}", method.upgrade_display());
            return 0;
        }
    };

    if !is_outdated(current, &latest) {
        println!("vallum {current} is up to date (latest {latest}).");
        return 0;
    }

    println!(
        "vallum {current} — {latest} is available (installed via {}).",
        method.label()
    );

    // `--check` is report-only: never run anything, exit 10 so scripts can gate.
    if check {
        println!("to upgrade, run:\n    {}", method.upgrade_display());
        return 10;
    }

    if run_upgrade {
        return match method.upgrade_argv() {
            Some(argv) => {
                println!("running: {}", method.upgrade_display());
                match std::process::Command::new(argv[0])
                    .args(&argv[1..])
                    .status()
                {
                    Ok(s) if s.success() => {
                        println!("upgraded.");
                        0
                    }
                    Ok(s) => {
                        eprintln!("upgrade command exited with {s}.");
                        1
                    }
                    Err(e) => {
                        eprintln!("could not run the upgrade command ({e}).");
                        1
                    }
                }
            }
            None => {
                // Standalone installs upgrade via `curl | sh` — exactly the
                // pattern Vallum warns about, so print it, don't execute it.
                println!(
                    "this install can't be auto-upgraded safely; run:\n    {}",
                    method.upgrade_display()
                );
                0
            }
        };
    }

    println!("to upgrade, run:\n    {}", method.upgrade_display());
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_install_method_from_path() {
        assert_eq!(
            detect_install_method(Path::new("/Users/x/.cargo/bin/vallum")),
            InstallMethod::Cargo
        );
        assert_eq!(
            detect_install_method(Path::new("/opt/homebrew/Cellar/vallum/0.8.4/bin/vallum")),
            InstallMethod::Homebrew
        );
        assert_eq!(
            detect_install_method(Path::new("/usr/local/lib/node_modules/vallum/vallum")),
            InstallMethod::Npm
        );
        assert_eq!(
            detect_install_method(Path::new("/Users/x/.local/bin/vallum")),
            InstallMethod::Standalone
        );
    }

    #[test]
    fn upgrade_command_per_method() {
        assert!(InstallMethod::Cargo
            .upgrade_display()
            .contains("cargo install vallum"));
        assert!(InstallMethod::Homebrew
            .upgrade_display()
            .contains("brew upgrade vallum"));
        assert!(InstallMethod::Npm
            .upgrade_display()
            .contains("npm install -g vallum"));
        // standalone can't be auto-run (curl | sh)
        assert!(InstallMethod::Standalone.upgrade_argv().is_none());
        assert!(InstallMethod::Cargo.upgrade_argv().is_some());
    }

    #[test]
    fn parses_latest_from_sparse_index() {
        let body = concat!(
            r#"{"name":"vallum","vers":"0.8.3","yanked":false}"#,
            "\n",
            r#"{"name":"vallum","vers":"0.8.4","yanked":false}"#,
            "\n",
            r#"{"name":"vallum","vers":"0.9.0","yanked":true}"#,
            "\n"
        );
        // 0.9.0 is yanked, so the latest live version is 0.8.4
        assert_eq!(parse_latest_from_index(body).as_deref(), Some("0.8.4"));
    }

    #[test]
    fn version_comparison() {
        assert!(is_outdated("0.8.4", "0.8.5"));
        assert!(is_outdated("0.8.4", "0.9.0"));
        assert!(is_outdated("0.8.4", "1.0.0"));
        assert!(!is_outdated("0.8.4", "0.8.4"));
        assert!(!is_outdated("0.8.5", "0.8.4"));
        assert!(!is_outdated("0.8.4", "0.8.4+abc123")); // build metadata ignored
    }
}
