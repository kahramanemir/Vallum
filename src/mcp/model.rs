//! Parse the on-disk MCP config shapes (JSON `mcpServers`/`servers`, Codex TOML
//! `mcp_servers`) into a normalized `McpServer`, independent of file layout.

use std::path::{Path, PathBuf};

/// A normalized MCP server definition, independent of the on-disk file shape.
#[derive(Debug, Clone, PartialEq)]
pub struct McpServer {
    pub source: PathBuf,
    pub name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Free-text fields present in the config that may carry injection.
    pub text_fields: Vec<(&'static str, String)>,
}

const TEXT_FIELD_KEYS: [&str; 4] = ["description", "instructions", "prompt", "toolDescription"];

/// Parse a config file, dispatching on extension: `.toml` → Codex shape,
/// anything else → JSON.
pub fn parse_file(path: &Path, text: &str) -> Result<Vec<McpServer>, String> {
    if path.extension().and_then(|e| e.to_str()) == Some("toml") {
        parse_toml(path, text)
    } else {
        parse_json(path, text)
    }
}

/// Parse the JSON `{"mcpServers"|"servers": {name: {...}}}` shape. A file with
/// no server map yields zero servers (informational), not an error.
pub fn parse_json(source: &Path, text: &str) -> Result<Vec<McpServer>, String> {
    let root: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("parse error: {e}"))?;
    let map = root
        .get("mcpServers")
        .or_else(|| root.get("servers"))
        .and_then(|v| v.as_object());
    let Some(map) = map else {
        return Ok(Vec::new());
    };
    Ok(map
        .iter()
        .map(|(name, def)| json_server(source, name, def))
        .collect())
}

fn json_server(source: &Path, name: &str, def: &serde_json::Value) -> McpServer {
    let command = def
        .get("command")
        .and_then(|v| v.as_str())
        .map(String::from);
    let args = def
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let env = def
        .get("env")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let mut text_fields = Vec::new();
    for key in TEXT_FIELD_KEYS {
        if let Some(s) = def.get(key).and_then(|v| v.as_str()) {
            text_fields.push((key, s.to_string()));
        }
    }
    McpServer {
        source: source.to_path_buf(),
        name: name.to_string(),
        command,
        args,
        env,
        text_fields,
    }
}

/// Parse the Codex TOML `[mcp_servers.<name>]` shape.
pub fn parse_toml(source: &Path, text: &str) -> Result<Vec<McpServer>, String> {
    let root: toml::Value = toml::from_str(text).map_err(|e| format!("parse error: {e}"))?;
    let Some(tbl) = root.get("mcp_servers").and_then(|v| v.as_table()) else {
        return Ok(Vec::new());
    };
    Ok(tbl
        .iter()
        .map(|(name, def)| toml_server(source, name, def))
        .collect())
}

fn toml_server(source: &Path, name: &str, def: &toml::Value) -> McpServer {
    let command = def
        .get("command")
        .and_then(|v| v.as_str())
        .map(String::from);
    let args = def
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let env = def
        .get("env")
        .and_then(|v| v.as_table())
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let mut text_fields = Vec::new();
    for key in TEXT_FIELD_KEYS {
        if let Some(s) = def.get(key).and_then(|v| v.as_str()) {
            text_fields.push((key, s.to_string()));
        }
    }
    McpServer {
        source: source.to_path_buf(),
        name: name.to_string(),
        command,
        args,
        env,
        text_fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn json_mcpservers_key_parses_all_fields() {
        let text = r#"{
          "mcpServers": {
            "weather": {
              "command": "npx",
              "args": ["-y", "@acme/weather"],
              "env": {"API_KEY": "secret123"},
              "description": "gets weather"
            }
          }
        }"#;
        let servers = parse_json(Path::new("/x/mcp.json"), text).unwrap();
        assert_eq!(servers.len(), 1);
        let s = &servers[0];
        assert_eq!(s.name, "weather");
        assert_eq!(s.command.as_deref(), Some("npx"));
        assert_eq!(s.args, vec!["-y".to_string(), "@acme/weather".to_string()]);
        assert_eq!(
            s.env,
            vec![("API_KEY".to_string(), "secret123".to_string())]
        );
        assert_eq!(
            s.text_fields,
            vec![("description", "gets weather".to_string())]
        );
    }

    #[test]
    fn json_servers_key_is_accepted() {
        let text = r#"{"servers": {"a": {"command": "run"}}}"#;
        let servers = parse_json(Path::new("/x/mcp.json"), text).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "a");
    }

    #[test]
    fn json_without_server_map_is_zero_servers_not_error() {
        let text = r#"{"unrelated": true}"#;
        let servers = parse_json(Path::new("/x/mcp.json"), text).unwrap();
        assert!(servers.is_empty());
    }

    #[test]
    fn malformed_json_is_error_not_panic() {
        let err = parse_json(Path::new("/x/mcp.json"), "{not json");
        assert!(err.is_err());
    }

    #[test]
    fn toml_mcp_servers_table_parses() {
        let text = r#"
          [mcp_servers.db]
          command = "uvx"
          args = ["mcp-db"]
          [mcp_servers.db.env]
          TOKEN = "abc"
        "#;
        let servers = parse_toml(Path::new("/x/config.toml"), text).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "db");
        assert_eq!(servers[0].command.as_deref(), Some("uvx"));
        assert_eq!(
            servers[0].env,
            vec![("TOKEN".to_string(), "abc".to_string())]
        );
    }

    #[test]
    fn parse_file_dispatches_by_extension() {
        let json = parse_file(Path::new("/x/a.json"), r#"{"mcpServers":{"a":{}}}"#).unwrap();
        assert_eq!(json.len(), 1);
        let toml = parse_file(Path::new("/x/a.toml"), "[mcp_servers.a]\n").unwrap();
        assert_eq!(toml.len(), 1);
    }
}
