## What does this PR do?

<!-- One or two sentences. Link the issue it closes, if any. -->

## Checklist

CI runs these on Linux and macOS — please run them locally first
(see [CONTRIBUTING.md](../CONTRIBUTING.md)):

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test --all`
- [ ] `cargo test --all --features bpe`
- [ ] User-facing changes noted in `CHANGELOG.md` under `[Unreleased]`
- [ ] Docs updated where behavior changed (README, SECURITY.md)

**If the PR touches detection** (scrubber, injection, guardrail rules,
optimizers):

- [ ] Corpus/regression entries added (`evals/corpus/`, `policy_bypass.txt`,
      or `policy_benign.txt` as appropriate) and the eval floors still pass
- [ ] Secret-shaped test fixtures are **de-contiguated** (`concat!(…)` splits
      or JSON `\u` escapes) — GitHub push protection rejects pushes containing
      contiguous scanner-matchable secrets, across all commits in the push

## Anything reviewers should focus on?

<!-- Precision risks, tricky edge cases, decisions you want a second opinion on. -->
