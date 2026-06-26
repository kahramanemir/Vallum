# Contributing to Vallum

Thanks for your interest in improving Vallum. This document covers the local
workflow and the bar a change needs to clear before it merges.

## Development setup

```bash
git clone https://github.com/kahramanemir/Vallum
cd Vallum
cargo build
```

The minimum supported Rust version is **1.82** (enforced by CI). Use a recent
stable toolchain for day-to-day work.

## Before you open a pull request

CI runs these on Linux and macOS; run them locally first so there are no
surprises:

```bash
cargo fmt --all -- --check        # formatting
cargo clippy --all-targets -- -D warnings   # lints (warnings are errors)
cargo test --all                  # unit + integration + property tests
cargo test --all --features bpe   # exact-tokenizer build
```

A change should keep all four green.

## Tests

- Unit tests live next to the code in `#[cfg(test)] mod tests`.
- Pure pipeline modules (scrubber, truncator, ansi, whitespace, optimizers)
  carry `proptest` invariants — at minimum a no-panic property. New
  transformation code should add one.
- Cross-cutting security behavior is exercised in `tests/security_corpus.rs`;
  end-to-end CLI behavior in `tests/cli_test.rs`.

## Adding an optimizer

Most optimizers are a small `impl CommandOptimizer` that delegates to the shared
`collapse_noise_runs` helper. To add one:

1. Create `src/optimizer/<name>.rs` with a struct implementing the trait
   (`name`, `matches`, `optimize`) plus unit tests and a no-panic proptest.
   See `src/optimizer/go_test.rs` or `kubectl.rs` for the pattern.
2. Register it in the `registry()` list in `src/optimizer/mod.rs`.
3. Document it in the README "Built-in Optimizers" list, the module table, and
   the `optimizer.disabled` valid-names list. `vallum doctor` validates those
   names, so keep them in sync.

## Adding a secret pattern

Add the regex to `secret_patterns()` in `src/scrubber/secrets.rs`. Order
matters: provider-specific rules must precede broad catch-alls (e.g. `sk-ant-`
before `sk-`). Prefer anchored, length-gated patterns to avoid eating prose,
add a positive test and — where the prefix is ambiguous — a negative one, and
update the secret list in both the README and `SECURITY.md`.

## Commit and PR conventions

- Use clear, conventional commit subjects (`feat(scrubber): …`, `fix(executor):
  …`, `docs(readme): …`).
- Keep each PR focused on one logical change.
- Note user-facing changes in `CHANGELOG.md` under `[Unreleased]`.

## Security

Please report vulnerabilities privately rather than in a public issue — see
[SECURITY.md](SECURITY.md) for the threat model and reporting guidance.

## License

By contributing you agree that your work is dual-licensed under MIT and
Apache-2.0, matching the project license.
