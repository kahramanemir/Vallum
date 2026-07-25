// tests/pii_zero_impact.rs — privacy mode is opt-in, so with default config
// the scrubber must behave exactly as it did before the feature existed.
use vallum::config::AppConfig;
use vallum::scrubber::{compile_rules, redact, sanitize, ScrubOptions};

#[derive(serde::Deserialize)]
struct Benign {
    text: String,
}

#[test]
fn default_config_leaves_the_existing_benign_corpus_alone() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/evals/corpus/benign.jsonl");
    let body = std::fs::read_to_string(path).expect("read benign.jsonl");

    let cfg = AppConfig::default();
    assert!(!cfg.privacy.enabled, "privacy must default to off");
    let extra = compile_rules(&[]);
    let opts = ScrubOptions::from_config(&extra, &cfg);

    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let r: Benign = serde_json::from_str(line).expect("valid corpus line");
        assert_eq!(
            redact(&r.text, &opts),
            r.text,
            "default path altered: {}",
            r.text
        );
    }
}

#[test]
fn default_sanitize_still_wraps_and_defangs() {
    let cfg = AppConfig::default();
    let extra = compile_rules(&[]);
    let opts = ScrubOptions::from_config(&extra, &cfg);
    let out = sanitize("plain output", &opts);
    assert!(out.starts_with("[UNTRUSTED TERMINAL OUTPUT START]"));
    assert!(out.trim_end().ends_with("[UNTRUSTED TERMINAL OUTPUT END]"));
}

#[test]
fn privacy_off_leaves_the_positive_corpus_untouched_through_sanitize() {
    // The strongest form of the guarantee: even text that is entirely PII
    // passes through byte-identical when the mode is off.
    let cfg = AppConfig::default();
    let extra = compile_rules(&[]);
    let opts = ScrubOptions::from_config(&extra, &cfg);
    let sample = "kimlik 12345678950 iban GB82WEST12345698765432 ali@example.com";
    let out = sanitize(sample, &opts);
    assert!(out.contains(sample), "got {out}");
}
