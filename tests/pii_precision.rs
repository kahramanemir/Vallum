// tests/pii_precision.rs — the "never mangles normal output" gate. Every line
// in evals/corpus/pii_benign.jsonl must pass through privacy mode unchanged.
//
// This is the primary gate for the feature, the direct sibling of
// tests/policy_precision.rs. If it fails, tighten the gate in
// src/scrubber/pii/gate.rs — do not weaken the corpus.
use vallum::config::AppConfig;
use vallum::scrubber::{compile_rules, pii::PrivacyOptions, redact, ScrubOptions};

#[derive(serde::Deserialize)]
struct Record {
    text: String,
    kind: String,
}

#[test]
fn benign_developer_output_is_never_redacted() {
    let corpus = concat!(env!("CARGO_MANIFEST_DIR"), "/evals/corpus/pii_benign.jsonl");
    let body = std::fs::read_to_string(corpus).expect("read pii_benign.jsonl");

    let mut cfg = AppConfig::default();
    cfg.privacy.enabled = true;

    let extra = compile_rules(&[]);
    let privacy = PrivacyOptions::from_config(&cfg);
    let opts = ScrubOptions::from_config(&extra, &cfg).with_privacy(Some(&privacy));

    let mut mangled = Vec::new();
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let r: Record = serde_json::from_str(line).expect("valid corpus line");
        let out = redact(&r.text, &opts);
        if out != r.text {
            mangled.push(format!("[{}]\n  in:  {}\n  out: {}", r.kind, r.text, out));
        }
    }
    assert!(
        mangled.is_empty(),
        "privacy mode altered benign output:\n{}",
        mangled.join("\n")
    );
}
