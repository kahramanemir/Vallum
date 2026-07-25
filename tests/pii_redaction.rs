// tests/pii_redaction.rs — every positive in the corpus must be redacted when
// privacy mode is on, and untouched when it is off.
use vallum::config::AppConfig;
use vallum::scrubber::{compile_rules, pii::PrivacyOptions, redact, ScrubOptions};

#[derive(serde::Deserialize)]
struct Record {
    text: String,
    kind: String,
}

fn corpus() -> Vec<Record> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/evals/corpus/pii.jsonl");
    std::fs::read_to_string(path)
        .expect("read pii.jsonl")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid corpus line"))
        .collect()
}

fn enabled_config() -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.privacy.enabled = true;
    cfg
}

#[test]
fn positives_are_redacted_when_enabled() {
    let cfg = enabled_config();
    let extra = compile_rules(&[]);
    let privacy = PrivacyOptions::from_config(&cfg);
    let opts = ScrubOptions::from_config(&extra, &cfg).with_privacy(Some(&privacy));

    let mut missed = Vec::new();
    for r in corpus() {
        let out = redact(&r.text, &opts);
        if out == r.text {
            missed.push(format!("[{}] {}", r.kind, r.text));
        }
    }
    assert!(
        missed.is_empty(),
        "privacy mode missed:\n{}",
        missed.join("\n")
    );
}

#[test]
fn positives_are_untouched_when_disabled() {
    let cfg = AppConfig::default(); // enabled = false
    assert!(!cfg.privacy.enabled);
    let extra = compile_rules(&[]);
    let opts = ScrubOptions::from_config(&extra, &cfg);

    for r in corpus() {
        assert_eq!(
            redact(&r.text, &opts),
            r.text,
            "default path altered [{}]",
            r.kind
        );
    }
}

#[test]
fn aliases_are_stable_across_calls() {
    let cfg = enabled_config();
    let extra = compile_rules(&[]);
    let privacy = PrivacyOptions::from_config(&cfg);
    let opts = ScrubOptions::from_config(&extra, &cfg).with_privacy(Some(&privacy));

    let a = redact("kimlik 12345678950", &opts);
    let b = redact("kayit: kimlik 12345678950 bulundu", &opts);
    let alias_a = a
        .split_whitespace()
        .find(|t| t.starts_with("[TCKN_"))
        .expect("alias in a");
    assert!(b.contains(alias_a), "alias not stable: {a} vs {b}");
}

#[test]
fn narrowed_categories_disable_the_rest() {
    let mut cfg = enabled_config();
    cfg.privacy.categories = vec!["iban".to_string()];
    let extra = compile_rules(&[]);
    let privacy = PrivacyOptions::from_config(&cfg);
    let opts = ScrubOptions::from_config(&extra, &cfg).with_privacy(Some(&privacy));

    // IBAN still redacted...
    let iban = redact("iban GB82WEST12345698765432", &opts);
    assert!(iban.contains("[IBAN_"), "got {iban}");
    // ...but TCKN is no longer an active detector.
    assert_eq!(redact("kimlik 12345678950", &opts), "kimlik 12345678950");
}

#[test]
fn sanitize_applies_privacy_inside_the_untrusted_wrapper() {
    let cfg = enabled_config();
    let extra = compile_rules(&[]);
    let privacy = PrivacyOptions::from_config(&cfg);
    let opts = ScrubOptions::from_config(&extra, &cfg).with_privacy(Some(&privacy));

    let out = vallum::scrubber::sanitize("kimlik 12345678950", &opts);
    assert!(out.starts_with("[UNTRUSTED TERMINAL OUTPUT START]"));
    assert!(out.contains("[TCKN_"), "got {out}");
    assert!(!out.contains("12345678950"), "got {out}");
}
