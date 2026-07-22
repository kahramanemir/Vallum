// tests/project_config_cli.rs — project-level .vallum.toml end-to-end.
use std::process::Command;

fn vallum_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vallum")
}

fn temp_repo(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("vallum_projcli_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    let cfg = dir.join("global-config.toml");
    std::fs::write(&cfg, format!("[audit]\nlog_dir = \"{}\"\n", dir.display())).unwrap();
    (dir, cfg)
}

#[test]
fn config_init_project_scaffolds_and_refuses_overwrite() {
    let (dir, cfg) = temp_repo("init");
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["config", "init", "--project"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let body = std::fs::read_to_string(dir.join(".vallum.toml")).unwrap();
    assert!(body.contains("[[policy.rules]]"), "{body}");
    assert!(body.contains("tighten-only"), "{body}");
    // Second run without --force refuses (still exit 0, message says exists).
    let out = Command::new(vallum_bin())
        .env("VALLUM_CONFIG", &cfg)
        .current_dir(&dir)
        .args(["config", "init", "--project"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("already exists"));
    let _ = std::fs::remove_dir_all(&dir);
}
