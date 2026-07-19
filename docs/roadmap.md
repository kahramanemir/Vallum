# Roadmap

> Part of the [Vallum](../README.md) documentation. Release history lives in
> [CHANGELOG.md](../CHANGELOG.md).

- [x] v0.1 — MVP: execute, truncate, scrub, audit
- [x] v0.2 — ANSI strip, whitespace collapse, token metrics, per-command optimizer framework, `vallum stats`
- [x] Post-v0.2 hardening — exit-code propagation, structured JSON output, configurable pipeline, cargo/pytest/npm optimizers
- [x] Security sweep — concurrent bounded capture (cap + timeout + stdin), context-preserving truncation, broadened injection neutralization, marker anti-spoofing, raw-logs-off-by-default with `0600` perms, small-output short-circuit, pluggable token estimator
- [x] Sub-project B — broader command coverage (git diff, git log, docker, go test, make), optimizer toggles (`[optimizer] disabled`), long-line truncation (`pipeline.max_line_length`), optional BPE token counting (`--features bpe`)
- [x] Sub-project C — integration/UX: `install-hook`/`uninstall-hook` (Claude Code PreToolUse), `vallum hook` handler, `config show`/`config init`, `vallum completions <shell>`, exit-125 convention
- [x] Sub-project D — live-tee (`vallum run --tee`, `~/.vallum/live.log`); PTY/streaming proper descoped because the hook skip-list (sub-project C) removed the urgency
- [x] Sub-project E — maturity: `proptest` invariants across scrubber/truncator/ansi/whitespace/optimizer modules; `criterion` benchmark harness with five versioned fixtures (`benches/fixtures/`); savings figures reproducible from a clean checkout
- [x] grep/file_list optimizers + hook-mode dispatch fix — `bash -c` unwrap so optimizers fire via the Claude Code hook; `rg`/`grep` match grouping; `ls`/`find`/`fd`/`tree` entry capping; two new bench fixtures (seven total)
- [x] Context-gated entropy secret detection — credential-ish assignment values with high Shannon entropy are masked; bare tokens (commit SHAs, UUIDs) structurally exempt; `[scrubber] entropy` flag (default on)
- [x] Injection precision tuning — reveal-family requires a possessive or system-directed object in all five languages; `System:`/`Assistant:` turn lines get a natural-language veto so log lines pass; entropy tokenizer captures separator runs (`key== "<value>"`); security corpus grown to 20 injections / 18 benign samples
- [x] Sub-project I — injection input normalization (strip invisible/bidi; NFKC + confusable-folded detection shadow; no-space ignore-family; `scrubber.normalize` flag)
- [x] Sub-project J — scrub-stage hardening: injection scan before secret masking (closes the secret-eats-trigger gap), reveal-family no-space detection in five languages, config extra-pattern compile-once (`CompiledRule`)
- [x] Sub-project K — broader infra/optimizer coverage: `kubectl get` (collapse healthy resource rows, keep problem-state pods) and `terraform plan|apply` (collapse refresh chatter + attribute diffs, keep action headers/summary/errors); expanded secret-format coverage (GitLab, SendGrid, Twilio, npm, PyPI, Hugging Face, OpenAI project keys, bare JWTs)
- [x] Sub-project L — `vallum doctor` install/health self-check: validates the config file, flags unknown `[optimizer] disabled` names, reports hook installation, checks the binary is on `PATH`, and probes log-dir writability (exit non-zero only on hard failures)
- [x] Sub-project M — distribution: `dist`-based tagged-release pipeline producing prebuilt binaries for macOS (Intel + ARM) and Linux (x86_64 + aarch64, musl static) with shell/Homebrew/`cargo install`/npm installers, SHA-256 checksums, and GitHub build-provenance attestations; crates.io publish on final tags; MSRV raised to 1.85 and the MSRV CI check pinned with `--locked`
- [x] Detection eval harness — externalized labeled corpus (`evals/corpus/*.jsonl`), confusion-matrix metrics with a committed `evals/report.md` (`cargo run --example eval`), and a CI recall-floor gate so detection claims stay tied to measured numbers
- [x] Detection corpus growth + Chinese-language injection — corpus grown to 85 injection / 54 benign samples (curated deepset imports with per-row provenance), full zh ignore/reveal/override family coverage, EN "disregard above" + DAN/persona patterns, FR/ES/TR gaps closed; per-category recall table in the eval report
- [x] Guardrail / policy layer — pre-exec Allow/Ask/Deny verdict on every command via the Claude Code hook and direct `vallum run` (deny → exit 125); ten narrow built-in rules for destructive commands, `[[policy.rules]]` config, redacted `policy.log` audit, benign-command precision gate, `vallum doctor` guardrail check
- [x] Multi-agent hook support — pre-exec guardrail via native hooks for Cursor, Gemini CLI, and Codex CLI
- [x] Guardrail bypass hardening — multi-view matching that unwraps shell `-c`/`eval` arguments, decodes `base64 -d` payloads, and normalizes `$IFS`/quote/escape and verb obfuscation, so wrapped dangerous commands are caught while benign-command precision stays at false-positive rate 0.000
- [x] Guardrail hardening rounds 2–3 — shell no-op normalization view (dequote/unescape/brace/path), ANSI-C `$'…'` quoting, path-qualified interpreters, `source`/process-substitution, and eight more destructive-command rules (`find -delete`, `shred`, `truncate`, `xargs rm`, reverse shells, `git clean -f`, recursive `chown`, agent-config writes)
- [x] Detection + coverage expansion — secret redaction to 30+ known formats, injection detection to 14 languages across eight family axes (recall 0.858 at precision 1.000), 23 output optimizers, `vallum update` self-update check
- [x] MCP static scanning + agent-config self-protection — `vallum mcp scan` (secrets / risky launch commands / embedded injection) and a doctor hook-audit that flags hooks Vallum did not install
- [x] Skill & context-file scanning — `vallum skills scan` (SKILL.md + CLAUDE.md/AGENTS.md/rules files: secrets / injection / risky fenced commands / invisible Unicode, ToxicSkills composite escalation)
- [x] Tamper-evident audit log — SHA-256 hash-chained `policy.log` with `vallum log verify [--expect-head]` and a doctor log-chain check
- [x] Blast-radius containment — rate-based circuit breaker (deny-all lockdown + `vallum unlock`) and a non-forgeable per-command HMAC approval token replacing the plain `--policy-approved` hook flag
- [x] Skill aux-file scanning + persistence guardrails — every UTF-8 file in a skill package scanned (cross-file PhantomSkill composite, anti-truncation read rules), six persistence-vector Ask rules (shell profiles, git hooks, crontab, SSH, LaunchAgents, systemd user), doctor audits all hook events and flags `ANTHROPIC_BASE_URL` overrides
- [ ] Deferred — `cargo-fuzz`/libFuzzer harness, performance regression gating, Windows support (the `0600`/timeout-backed guarantees need a Windows equivalent first)
