# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Secret redaction no longer leaks the tail of an over-length key.** The
  `AIza`, `npm_`, and `AKIA` patterns used exact-count quantifiers (`{35}`,
  `{36}`, `{16}`) sized to the canonical key length, so a longer look-alike was
  masked only up to that count and leaked the remaining characters past `***`
  (e.g. `AIza***ab`). Changed them to `{N,}` so the full credential-character run
  is consumed. `{N,}` can only extend a match that `{N}` already made — it never
  matches a string the old pattern did not — so canonical keys still redact to
  `AIza***`/`npm_***`/`AKIA***` and no new false positives are introduced.

## [0.8.2]

### Security
- **Guardrail now matches through common command wrappers.** `Policy::evaluate`
  reinterprets each command through a bounded set of precision-safe views: shell
  `-c` and `eval` arguments (verb-aware — `sh`/`bash`/`zsh`/`dash`/`ksh`, bare or
  bundled like `-xc`, behind wrapper prefixes like `sudo`/`env`/`timeout`, and
  nested), `base64 -d` payloads (decoded and re-checked), `$IFS` token-splitting,
  and word-internal quote / escaped-space obfuscation applied to both the payload
  and the interpreter verb (`\bash`, `b''ash`). Newlines are treated as command
  separators. Closes the confirmed bypasses where a dangerous command was wrapped
  or encoded past the built-in rules (e.g. `bash -c 'rm -rf /'`,
  `echo <base64> | base64 -d | sh`). Precision is unchanged (benign
  false-positive rate stays 0.000); all built-ins remain `Ask`; `guardrail =
  false` output is byte-identical. See SECURITY.md for the residual known
  limitations.

## [0.8.1]

### Added
- **Interactive agent picker for `install-hook`/`uninstall-hook`.** Bare
  `vallum install-hook` on a terminal now opens a multi-select (space =
  toggle, `a` = toggle all, enter = confirm, esc = cancel) listing Claude
  Code, Codex CLI, Cursor, and Gemini CLI with detected/installed status;
  detected-but-unhooked agents come preselected. `uninstall-hook` gets the
  same picker over currently hooked agents. Non-interactive invocations
  (pipes, CI) keep the silent Claude Code default, and explicit `--agent`
  never prompts. No new dependencies — hand-rolled termios raw mode.

## [0.8.0]

### Security
- **TUI-headed commands are now gated in hook mode on all four agents.**
  `less /etc/shadow` and friends were previously skipped before policy
  evaluation (a disclosed known gap); they are now evaluated like any
  command — Ask prompts natively on Claude Code/Cursor and fails closed on
  Gemini CLI/Codex CLI. A clean Allow still passes the command through
  unwrapped, and an approved Ask on Claude Code runs the original command
  directly, so interactive TTYs keep working.

### Added
- **`vallum policy test "<cmd>"`** — one-shot guardrail verdict without
  running an agent: prints `ALLOW` / `ASK [rule] (built-in|user rule)` /
  `DENY [rule] …` / `PASS-THROUGH (…)` and exits 0/10/20 (125 on config
  error) for scripting.

### Fixed
- `vallum install-hook` no longer panics when a hand-edited agent config
  has the right JSON syntax but the wrong shape (e.g. a `hooks` key that
  is a string) — it reports a clean error with the file path instead.
- Welcome screen says `1 rule active` instead of `1 rules active`.

### Changed
- `vallum doctor` and the welcome screen derive their per-agent probe
  paths from the installers' own path helpers, so the three can no longer
  drift apart.

## [0.7.0]

### Added
- **Welcome screen.** Bare `vallum` now prints a branded status banner —
  guardrail state (on/off + active rule count), per-agent hook install
  status (with the Codex one-time-trust reminder), and a three-command
  quick start — instead of clap's default help. Color only on an
  interactive stdout (`NO_COLOR` and `TERM=dumb` respected).

### Changed
- **Bare `vallum` now exits 0** (welcome screen on stdout). It previously
  exited 2 with the help text on stderr; scripts that invoked bare
  `vallum` expecting a usage error must call a real subcommand instead.
  The same shift applies to a hand-edited agent hook entry that mistakenly
  invokes bare `vallum` (missing the `hook` subcommand): it used to fail
  closed (exit 2 blocked every command); it now no-ops silently and commands
  run ungated. `vallum install-hook` never writes that shape, and `vallum
  doctor` reports it as not installed.
- `--help` restyled: tagline is now "The wall between AI agents and your
  shell" (was "AI CLI Proxy"), headers are colored, commands are listed
  task-first, and a "Quick start" block closes the help text.

## [0.6.1]

### Changed
- `vallum doctor`'s `hook (codex)` line now reminds, on a successful install,
  that Codex requires a one-time hook trust (and codex-cli ≥ 0.141) — Codex
  silently skips untrusted hooks, and that trust state is invisible to Vallum.

### Documentation
- README + SECURITY.md: documented two live-verified Codex CLI findings
  (2026-07-08, codex-cli 0.142.5): an installed-but-untrusted hook is skipped
  without warning (fail-open until the one-time trust step), and hook-trust
  handling in `codex exec` was only fixed in codex-cli 0.141.0
  (openai/codex#26434) — on 0.139 the hook never fired at all. Enforcement
  (Ask-rule deny, benign pass-through, `agent=codex` audit lines) verified
  live end-to-end on 0.142.5.

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

[0.8.2]: https://github.com/kahramanemir/Vallum/releases/tag/v0.8.2
[0.8.1]: https://github.com/kahramanemir/Vallum/releases/tag/v0.8.1
[0.8.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.8.0
[0.7.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.7.0
[0.6.1]: https://github.com/kahramanemir/Vallum/releases/tag/v0.6.1
[0.6.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.6.0
[0.5.1]: https://github.com/kahramanemir/Vallum/releases/tag/v0.5.1
[0.5.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.5.0
[0.4.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.4.0
[0.3.1]: https://github.com/kahramanemir/Vallum/releases/tag/v0.3.1
[0.3.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.3.0
[0.2.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.2.0
[0.1.0]: https://github.com/kahramanemir/Vallum/releases/tag/v0.1.0
