// tests/security_corpus.rs — must-pass regression gate over the gate==true
// subset of the eval corpus (evals/corpus/*.jsonl). Honest, possibly-<100%
// metrics over the full corpus live in `cargo run --example eval`.
use vallum::eval::{
    load_jsonl, BenignRecord, EntropyBenignRecord, EntropySecretRecord, InjectionRecord,
    SecretRecord,
};
use vallum::scrubber;

#[test]
fn gate_injections_all_detected() {
    let rows: Vec<InjectionRecord> = load_jsonl("injections.jsonl");
    let mut missed = Vec::new();
    for r in rows.iter().filter(|r| r.gate) {
        if !scrubber::scrub_injections(&r.text, true).1 {
            missed.push(r.text.clone());
        }
    }
    assert!(missed.is_empty(), "gate injections missed: {missed:?}");
}

#[test]
fn gate_benign_none_flagged() {
    let rows: Vec<BenignRecord> = load_jsonl("benign.jsonl");
    let mut flagged = Vec::new();
    for r in rows.iter().filter(|r| r.gate) {
        if scrubber::scrub_injections(&r.text, true).1 {
            flagged.push(r.text.clone());
        }
    }
    assert!(flagged.is_empty(), "gate benign flagged: {flagged:?}");
}

#[test]
fn gate_secrets_all_redacted() {
    let rows: Vec<SecretRecord> = load_jsonl("secrets.jsonl");
    for r in rows.iter().filter(|r| r.gate) {
        let out = scrubber::redact(&r.text, &[], true, true);
        assert!(
            !out.contains(&r.secret),
            "secret leaked: {} -> {out}",
            r.text
        );
    }
}

#[test]
fn gate_entropy_secrets_all_redacted() {
    let rows: Vec<EntropySecretRecord> = load_jsonl("entropy_secrets.jsonl");
    for r in rows.iter().filter(|r| r.gate) {
        let out = scrubber::redact(&r.text, &[], true, true);
        assert!(
            !out.contains(&r.secret),
            "entropy secret leaked: {} -> {out}",
            r.text
        );
    }
}

#[test]
fn gate_entropy_benign_untouched() {
    let rows: Vec<EntropyBenignRecord> = load_jsonl("entropy_benign.jsonl");
    for r in rows.iter().filter(|r| r.gate) {
        let out = scrubber::redact(&r.text, &[], true, true);
        assert_eq!(out, r.text, "false positive on benign sample");
    }
}

#[test]
fn benign_unicode_survives_sanitize_verbatim() {
    let s = "Café ☕ — Türkçe ığüş";
    let out = scrubber::sanitize(s, &[], false, true, true);
    assert_eq!(
        out,
        format!("[UNTRUSTED TERMINAL OUTPUT START]\n{s}\n[UNTRUSTED TERMINAL OUTPUT END]\n")
    );
}

#[test]
fn entropy_redaction_fires_through_sanitize() {
    let input = "db_password=0123456789abcdef0123456789abcdef";
    let out = scrubber::sanitize(input, &[], false, true, true);
    assert!(
        !out.contains("0123456789abcdef0123456789abcdef"),
        "entropy secret must not survive sanitize: {out}"
    );
    assert!(out.contains("db_password=***"));
    assert!(out.starts_with("[UNTRUSTED TERMINAL OUTPUT START]"));
}
