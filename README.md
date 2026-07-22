# Vallum

### The wall between AI coding agents and your shell.

Vallum is a single Rust CLI that sits between an AI coding agent and your
terminal. It **stops dangerous commands before they run**, **redacts secrets**
and **neutralizes prompt-injection** in command output before it reaches the
model, and audits everything — for Claude Code, Cursor, Codex, Gemini CLI, or
any agent that runs shell commands.

[![CI](https://github.com/kahramanemir/Vallum/actions/workflows/ci.yml/badge.svg)](https://github.com/kahramanemir/Vallum/actions/workflows/ci.yml)
[![Security audit](https://github.com/kahramanemir/Vallum/actions/workflows/audit.yml/badge.svg)](https://github.com/kahramanemir/Vallum/actions/workflows/audit.yml)
[![crates.io](https://img.shields.io/crates/v/vallum.svg)](https://crates.io/crates/vallum)
[![docs.rs](https://img.shields.io/docsrs/vallum)](https://docs.rs/vallum)
[![npm](https://img.shields.io/npm/v/vallum.svg)](https://www.npmjs.com/package/vallum)
[![MSRV](https://img.shields.io/crates/msrv/vallum?label=msrv)](https://github.com/kahramanemir/Vallum/blob/main/Cargo.toml)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

<p align="center">
  <img src="assets/vallum-demo.gif" alt="Terminal demo: a raw deploy log leaks an AWS key and a prompt-injection line; the same command through vallum run shows the key masked and the injection neutralized inside untrusted-output markers; a git push --force is then stopped by the pre-exec guardrail asking for confirmation" width="840">
</p>

## What it does

| Capability | What it does |
|---|---|
| **[Guardrail](docs/guardrail.md)** | Stops `rm -rf /`, `curl … \| sh`, force-push, and other dangerous commands *before they run* — prompts (`Ask`) or blocks (`Deny`), on by default. On Claude Code it also gates the native `Write`/`Edit`/`Read` tools against sensitive paths. |
| **Secret redaction** | Masks known key/token formats (OpenAI, AWS, GitHub, Stripe, and more) plus high-entropy credentials before output ever reaches the model. |
| **Injection defense** | Neutralizes "ignore previous instructions"-style text in fourteen languages, then wraps the output in untrusted-data markers so it can't hijack the agent. |
| **[Config scanning](docs/scanning.md)** | Statically scans MCP server configs, skill packages, and agent context files for embedded secrets, injection, and risky commands. |
| **[Token savings](docs/optimizers.md)** | Strips ANSI noise and compresses large build and test logs — a side benefit of routing output through the security pipeline. |

> **Measured, not claimed.** Over a committed, labeled corpus: injection recall
> **0.858** · precision **1.000** · benign false-positive rate **0.000**;
> known-format secret recall **1.000**. Numbers are evidence, not a guarantee —
> [full report](evals/report.md).

## Quick start

```bash
# 1. Install (macOS + Linux)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/kahramanemir/Vallum/releases/latest/download/vallum-installer.sh | sh

# 2. Try it on any command
vallum run cargo test

# 3. Gate your agent — pick Claude Code, Cursor, Gemini CLI, or Codex CLI
vallum install-hook
```

After installing the hook, dangerous commands are gated inside your agent's
own approval flow. Check the install anytime with `vallum doctor`.

## Install

| Channel | Command |
|---|---|
| Shell installer | `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/kahramanemir/Vallum/releases/latest/download/vallum-installer.sh \| sh` |
| Homebrew | `brew install kahramanemir/homebrew-tap/vallum` |
| Cargo | `cargo install vallum` |
| npm | `npm install -g vallum` |

Prebuilt binaries for macOS (Intel + ARM) and Linux (x86_64 + aarch64) — with
SHA-256 checksums and build-provenance attestations — are attached to every
[GitHub Release](https://github.com/kahramanemir/Vallum/releases). Attestation
verification, source builds, and the exact-BPE token-count feature:
[CLI reference → Install](docs/cli.md#install).

## Works with your agent

`vallum run` works with any agent that runs shell commands. The pre-exec
guardrail also hooks **natively** into **Claude Code**, **Cursor**,
**Gemini CLI**, and **Codex CLI** — one `vallum install-hook` and dangerous
commands are gated inside the agent's own approval flow. Output sanitization
and token optimization run on Claude Code (and any explicit `vallum run`); on
the other three agents Vallum gates commands without rewriting their output.
Full matrix, per-agent behavior, and honest limitations:
**[Agent integrations](docs/agents.md)**.

## Everyday commands

```bash
vallum run <command> [args...]   # run any command through the security pipeline
vallum install-hook              # hook your agent(s) — interactive picker
vallum policy test "<command>"   # what would the guardrail say? (exit 0/10/20)
vallum mcp scan                  # scan MCP server configs for risks
vallum skills scan               # scan skills + agent context files for poisoning
vallum stats                     # cumulative token savings
vallum doctor                    # health self-check
vallum update                    # check for a newer release
```

Every command, JSON output, and exit codes: **[CLI reference](docs/cli.md)**.

## How it works

Command output is **untrusted input**: it can leak secrets into the model's
context, carry adversarial "ignore previous instructions" text, and bury the
signal in noise. Vallum puts a controlled boundary in between — before a
command runs it is checked against the [guardrail policy](docs/guardrail.md),
and after it runs the output is scrubbed, wrapped in untrusted-data markers,
and audited. Pipeline stages, the security model, and the module map:
**[Architecture](docs/architecture.md)**.

> **Scope of the guarantees.** Secret redaction and injection neutralization
> are best-effort, pattern-based defenses — they raise the cost of an attack,
> they don't replace treating terminal output as untrusted. The full threat
> model, mechanism by mechanism, is in [SECURITY.md](SECURITY.md).

## Fewer asks over time

Repeated approvals stop being asked: an approved Ask is remembered (exact
command + directory, narrow rule set, 14-day TTL, HMAC-signed) and
`[[policy.allow]]` lets you carve a scoped exception for one rule without
disabling it. Every downgrade is audit-logged. See
[docs/guardrail.md](docs/guardrail.md).

## CI & automation

One command gates a repo: `vallum scan .` (exit 0 clean / 10 warnings /
20 high / 125 error). GitHub code scanning:

```yaml
- uses: kahramanemir/Vallum@v0.9.0   # pin to a release tag
  with:
    paths: "."
    fail-on: high
```

pre-commit:

```yaml
- repo: https://github.com/kahramanemir/Vallum
  rev: v0.9.0
  hooks:
    - id: vallum-scan   # requires an installed vallum
```

Optional session-start scanning for Claude Code:
`vallum install-hook --agent claude --session-scan` injects a one-line
warning into new sessions when a scan finds issues (never blocks startup).

## Documentation

| Doc | What's inside |
|---|---|
| [Guardrail & policy](docs/guardrail.md) | The 26 built-in rules, Claude Code file-tool gating, custom rules, circuit breaker, tamper-evident `policy.log` |
| [Agent integrations](docs/agents.md) | Claude Code, Cursor, Gemini CLI, Codex CLI — hook points, Ask behavior, limitations |
| [CLI reference](docs/cli.md) | Every command, examples, JSON output, exit codes, all install channels |
| [Configuration](docs/configuration.md) | `~/.vallum/config.toml` — every setting with its default |
| [Output optimizers](docs/optimizers.md) | The 23 built-in optimizers, measuring and reproducing token savings |
| [MCP & skill scanning](docs/scanning.md) | `vallum mcp scan` and `vallum skills scan` in depth |
| [Architecture](docs/architecture.md) | Why, pipeline stages, security model, measured detection, module map |
| [Roadmap](docs/roadmap.md) | What's built and what's next |
| [SECURITY.md](SECURITY.md) | Full threat model — protections, strengths, and explicit non-goals |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Local workflow, how to add an optimizer or secret pattern |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Name

**Vallum** — Latin for the defensive embankment along Roman frontier
fortifications. The thing that stands between what's inside and what's outside.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
