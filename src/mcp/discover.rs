//! Well-known MCP config file locations. Static, platform-aware; absent files
//! are simply not returned by `existing_*`.

use std::path::PathBuf;

/// The full list of well-known MCP config locations on this machine
/// (whether or not they exist).
pub fn known_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".cursor").join("mcp.json"));
        paths.push(home.join(".claude.json"));
        paths.push(home.join(".codex").join("config.toml"));
        paths.push(home.join(".gemini").join("settings.json"));
        #[cfg(target_os = "macos")]
        paths.push(
            home.join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json"),
        );
        #[cfg(not(target_os = "macos"))]
        paths.push(
            home.join(".config")
                .join("Claude")
                .join("claude_desktop_config.json"),
        );
    }
    // Project-relative locations (resolved against the current working dir).
    paths.push(PathBuf::from(".mcp.json"));
    paths.push(PathBuf::from(".vscode").join("mcp.json"));
    paths
}

/// Keep only the candidates that currently exist on disk.
pub fn existing_from(candidates: &[PathBuf]) -> Vec<PathBuf> {
    candidates.iter().filter(|p| p.exists()).cloned().collect()
}

/// Well-known locations that exist on this machine.
pub fn existing_config_paths() -> Vec<PathBuf> {
    existing_from(&known_config_paths())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_paths_are_nonempty_and_include_cursor() {
        let paths = known_config_paths();
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.ends_with("mcp.json")));
    }

    #[test]
    fn existing_from_keeps_only_files_that_exist() {
        let dir = std::env::temp_dir().join(format!(
            "vallum_mcp_discover_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let present = dir.join("present.json");
        std::fs::write(&present, "{}").unwrap();
        let absent = dir.join("absent.json");

        let got = existing_from(&[present.clone(), absent.clone()]);
        assert_eq!(got, vec![present]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
