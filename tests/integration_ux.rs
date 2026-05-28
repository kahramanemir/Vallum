// tests/integration_ux.rs — end-to-end tests for sub-project C.

#[test]
fn proxy_failure_exits_125() {
    let bin = env!("CARGO_BIN_EXE_vallum");
    let output = std::process::Command::new(bin)
        .args(["run", "/nonexistent-vallum-test-binary-zzz"])
        .env("VALLUM_CONFIG", "/nonexistent/vallum/config.toml")
        .output()
        .expect("run vallum");
    assert_eq!(output.status.code(), Some(125), "expected exit 125, got {:?}", output.status.code());
}
