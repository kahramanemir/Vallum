// tests/policy_precision.rs — the "never nags" gate: every common legitimate
// command in evals/corpus/policy_benign.txt must evaluate to Allow.
use vallum::config::PolicyConfig;
use vallum::policy::{Policy, PolicyAction};

#[test]
fn benign_commands_are_never_flagged() {
    let corpus = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/evals/corpus/policy_benign.txt"
    );
    let body = std::fs::read_to_string(corpus).expect("read policy_benign.txt");
    let policy = Policy::compile(&PolicyConfig::default()).unwrap();

    let mut flagged = Vec::new();
    for line in body.lines() {
        let cmd = line.trim();
        if cmd.is_empty() || cmd.starts_with('#') {
            continue;
        }
        let v = policy.evaluate(cmd);
        if v.action != PolicyAction::Allow {
            flagged.push(format!("{cmd}  ->  {:?} ({})", v.action, v.rule_name));
        }
    }
    assert!(
        flagged.is_empty(),
        "guardrail flagged benign commands:\n{}",
        flagged.join("\n")
    );
}
