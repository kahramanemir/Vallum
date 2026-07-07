# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0]

### Added
- **Multi-agent guardrail hooks.** `vallum hook --agent claude|cursor|gemini|codex`
  extends the pre-exec Allow/Ask/Deny guardrail to Cursor
  (`beforeShellExecution`, native ask), Gemini CLI (`BeforeTool`), and Codex
  CLI (`PreToolUse`). On agents without a native ask, Ask fails closed as a
  deny with instructions. `vallum install-hook --agent <x>` /
  `uninstall-hook --agent <x>` perform idempotent JSON merges into each
  agent's config; `vallum doctor` reports per-agent hook status; `policy.log`
  lines now record `agent=`. Bare `vallum hook` still means Claude Code, and
  Claude hook output is byte-identical to v0.5.1.

## [0.5.1]

### Fixed
- **Hook mode no longer degrades silently on a broken config.** A TOML or
  regex error in the config file used to drop the user's custom policy rules
  (and every other custom setting) without any diagnostic while the hook kept
  running with defaults. The hook now prints a warning to stderr (surfaced by
  Claude Code) and keeps gating with the built-in policy; direct `vallum run`
  still refuses to run (exit 125) on a broken config.
- **Trivial shell obfuscation no longer slips past the guardrail.** Command
  lines are lightly normalized before rule matching — empty quote pairs and
  identity backslash escapes are stripped — so `r''m -rf /` and `\rm -rf /`
  now trigger `rm_rf_root` just like the plain spelling. Raw matches are never
  lost, and the benign-command precision gate is unchanged.

### Changed
- A bare string in `[scrubber] extra_secret_patterns` now fails with an error
  that shows the expected `{ pattern = "…", replacement = "…" }` table form
  instead of a generic serde type error.
- `vallum run --help` now shows examples, including the `--` separator needed
  when the wrapped command has flags of its own.

### Documentation
- README: documented the guardrail's honest scope (text-pattern matching is a
  defense-in-depth speed bump, not a sandbox) and the broken-config fallback
  behavior in hook mode vs direct `vallum run`.

## [0.5.0]

### Added
- **Guardrail / policy layer** — Vallum now evaluates each command *before it
  runs* against a set of dangerous-command rules and returns Allow / Ask / Deny.
  Enforced through the Claude Code `PreToolUse` hook (native allow/ask/deny) and
  through direct `vallum run` (deny → exit 125; ask → terminal prompt or
  fail-closed when non-interactive). Ships with a narrow built-in rule set
  (`rm -rf` on root/home, `curl … | sh`, `dd` to a block device, fork bomb,
  recursive `chmod 777`, reading private keys/credentials, force-push, …),
  a benign-command precision gate, redacted `policy.log` auditing, and
  `vallum doctor` reporting. User rules and disables live under `[policy]`.

### Changed
- **Behavior change:** the guardrail is **enabled by default**
  (`security.guardrail = true`) with **all built-in rules set to `ask`** — a
  genuinely dangerous command now prompts for confirmation instead of running
  silently. Built-in patterns are deliberately narrow so ordinary commands are
  unaffected. Opt out with `security.guardrail = false`; auto-approve prompts in
  scripts with `security.assume_yes = true` or `VALLUM_ASSUME_YES=1`.

## [0.4.0]

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

### Documentation
- Enriched the README title/intro and crates.io metadata (keywords,
  categories, description) for discoverability.

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

[0.6.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.6.0
[0.5.1]: https://github.com/kahramanemir/Vallum/releases/tag/v0.5.1
[0.5.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.5.0
[0.4.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.4.0
[0.3.1]: https://github.com/kahramanemir/Vallum/releases/tag/v0.3.1
[0.3.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.3.0
[0.2.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.2.0
[0.1.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.1.0
