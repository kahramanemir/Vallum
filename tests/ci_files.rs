// tests/ci_files.rs — the committed CI integration files exist and carry the
// load-bearing strings (a plain smoke test; no YAML dependency just for tests).

fn read(name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

#[test]
fn action_yml_has_required_pieces() {
    let a = read("action.yml");
    for needle in [
        "using: \"composite\"",
        "vallum scan --sarif",
        "github/codeql-action/upload-sarif",
        "fail-on",
        "sha256",
        "x86_64-unknown-linux-musl",
        "aarch64-apple-darwin",
    ] {
        assert!(a.contains(needle), "action.yml must contain {needle:?}");
    }
    assert!(
        !a.lines()
            .any(|l| l.contains("curl") && (l.contains("| sh") || l.contains("| bash"))),
        "no pipe-to-shell installs in our own action"
    );
}

#[test]
fn pre_commit_hooks_yaml_has_required_pieces() {
    let p = read(".pre-commit-hooks.yaml");
    for needle in ["id: vallum-scan", "language: system", "entry: vallum scan"] {
        assert!(
            p.contains(needle),
            ".pre-commit-hooks.yaml must contain {needle:?}"
        );
    }
}
