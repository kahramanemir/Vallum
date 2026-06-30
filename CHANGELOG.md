# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Documented a minimum supported Rust version (`rust-version = "1.82"`) and
  enforce it with a dedicated CI job.

### Security
- New scheduled `cargo audit` GitHub Actions workflow that fails on known
  advisories in the dependency tree.

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

[Unreleased]: https://github.com/kahramanemir/Vallum/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.2.0
[0.1.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.1.0
