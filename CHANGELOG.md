# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Chinese (zh) injection detection across all four pattern families
  (ignore / reveal / roleplay / new-instructions), plus zh benign coverage so
  zh precision is measurable.
- Detection for noun-free "disregard everything above" phrasing, DAN/persona
  jailbreaks, French negative-imperative and adjective-free ignore, Spanish
  adjective-free ignore, and the Turkish `prompt` loanword reveal.
- Per-category recall breakdown in the detection eval report.

### Changed
- Grew the labeled eval corpus with curated, permissively-licensed samples
  from `deepset/prompt-injections` (Apache-2.0) plus hand-authored multilingual
  and mutation rows; provenance recorded in `evals/corpus/SOURCES.md`.
- Recalibrated `MIN_INJECTION_RECALL` to the grown-corpus measurement
  (calibrate-to-measurement policy); precision 1.000 and benign FP 0.000 hold.

## [0.3.1]

### Documentation
- Added a crate-level overview and one-line module-level rustdoc so docs.rs
  renders an intentional landing page (with a "this crate is a CLI" pointer and
  an "internal, not-semver-stable library surface" note) instead of a bare,
  description-less module list. Cleared all outstanding rustdoc warnings
  (private intra-doc links, an unclosed `<cwd>` HTML tag); `cargo doc` is clean.

## [0.3.0]

### Added
- `vallum doctor` — install/health self-check that validates the config file,
  flags unknown `[optimizer] disabled` names, reports whether the Claude Code
  hook is installed, checks that a `vallum` binary is on `PATH`, and probes the
  log directory for writability. Exits non-zero only on a hard failure.
- `kubectl get` optimizer — collapses runs of healthy (`Running`/`Completed`)
  resource rows while keeping the header and any pod in a problem state
  (`CrashLoopBackOff`, `Pending`, `Evicted`, …).
- `terraform plan|apply` optimizer — collapses state-refresh chatter and
  attribute-diff bodies while keeping per-resource action headers, the
  `Plan:`/`Apply complete!` summary, and errors.
- Expanded secret-format coverage: GitLab (`glpat-`), SendGrid (`SG.`),
  Twilio (`SK…`), npm (`npm_`), PyPI (`pypi-`), Hugging Face (`hf_`), OpenAI
  project keys (`sk-proj-`), and bare (non-`Bearer`) JWTs.

### Changed
- Documented a minimum supported Rust version (`rust-version = "1.85"`, raised
  from 1.82 to track the `clap` 4.6 edition-2024 floor) and enforce it with a
  dedicated, `--locked` CI job.

### Security
- New scheduled `cargo audit` GitHub Actions workflow that fails on known
  advisories in the dependency tree. Granted it `checks: write` so it can post
  results instead of erroring on the check-run API.
- Bumped the `anyhow` dev-dependency to 1.0.103, clearing RUSTSEC-2026-0190
  (unsoundness in `Error::downcast_mut`).

### Distribution
- Prebuilt binaries for macOS (Intel + ARM) and Linux (x86_64 + aarch64, musl
  static) published on tagged releases via `dist`, with shell, Homebrew,
  `cargo install`, and npm installers, SHA-256 checksums, and GitHub build
  provenance attestations.

## [0.2.0]

### Added
- ANSI stripping, whitespace collapse, token metrics, and `vallum stats`.
- Per-command optimizer framework with optimizers for `git status`/`diff`/`log`,
  `cargo`, `pytest`, `npm`, `docker`, `go test`, `make`, `rg`/`grep`, and
  `ls`/`find`/`fd`/`tree`.
- Concurrent bounded capture (byte cap, timeout, inherited stdin),
  context-preserving truncation, and an optional `--features bpe` token counter.
- Claude Code integration: `install-hook`/`uninstall-hook`, the `vallum hook`
  handler, `config show`/`config init`, shell completions, and `--tee` live log.
- Security pipeline: multilingual prompt-injection neutralization (with
  invisible/bidi stripping and homoglyph folding, plus `--strict` fail-closed
  mode), known-format secret redaction with context-gated entropy detection,
  untrusted-output wrapping with marker defang, and private-by-default logging.

## [0.1.0]

### Added
- MVP: execute a command through the proxy, truncate, scrub secrets, and audit.

[0.3.1]: https://github.com/kahramanemir/Vallum/releases/tag/v0.3.1
[0.3.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.3.0
[0.2.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.2.0
[0.1.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.1.0
