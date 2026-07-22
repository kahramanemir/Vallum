# CLI reference

> Part of the [Vallum](../README.md) documentation. See also:
> [Configuration](configuration.md) · [Guardrail & policy](guardrail.md) ·
> [Agent integrations](agents.md).

## Install

**Shell (macOS + Linux):**

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/kahramanemir/Vallum/releases/latest/download/vallum-installer.sh | sh
```

**Homebrew:**

```bash
brew install kahramanemir/homebrew-tap/vallum
```

**Cargo:**

```bash
cargo install vallum                  # heuristic token counts (default)
cargo install vallum --features bpe   # exact BPE token counts (adds tiktoken-rs)
```

**npm:**

```bash
npm install -g vallum
```

**Prebuilt binaries** for macOS (Intel + ARM) and Linux (x86_64 + aarch64) are
attached to every [GitHub Release](https://github.com/kahramanemir/Vallum/releases),
with SHA-256 checksums and build-provenance attestations. Verify a download with:

```bash
gh attestation verify ./vallum --repo kahramanemir/Vallum
```

**Build from source:**

```bash
cargo build --release                 # default: dependency-free heuristic token counts
cargo build --release --features bpe  # exact BPE token counts (adds tiktoken-rs)
```

The binary lands at `target/release/vallum`.

## Commands

```bash
vallum run <command> [args...]       # run a command through the proxy
vallum run --json <command> ...      # emit structured JSON
vallum run --strict <command> ...    # block output if a prompt injection is detected
vallum run --tee <command> ...       # also append raw output to ~/.vallum/live.log
vallum stats                         # show cumulative token savings
vallum stats --reset                 # delete collected stats

# Integration & UX
vallum install-hook                  # pick agents interactively (space = toggle, enter = confirm)
vallum install-hook --agent claude   # script one agent (also: cursor, gemini, codex)
vallum install-hook --project        # Claude Code only, <cwd>/.claude/settings.json
vallum uninstall-hook                # remove hooks (same picker; --agent to script)
vallum hook                          # internal: invoked by the agent's hook config (don't run directly)
vallum config show                   # print effective merged config as TOML
vallum config init [--force]         # scaffold ~/.vallum/config.toml
vallum policy test "<command>"       # one-shot guardrail verdict (exit 0/10/20)
vallum update                        # check for a newer release + upgrade command
vallum mcp scan                      # scan discovered MCP configs for risks
vallum mcp scan --json <path>...     # structured output / specific files
vallum skills scan                   # scan skills + agent context files for poisoning
vallum skills scan <dir>             # scan a downloaded skill before installing it
vallum scan [<path>...]              # unified scan: mcp + skills + config + log chain
vallum scan --sarif . > scan.sarif   # SARIF 2.1.0 for GitHub code scanning
vallum scan --json | --full          # aggregate JSON | also run the doctor env checks
vallum install-hook --agent claude --session-scan  # opt-in SessionStart quick scan
vallum log verify                    # verify the policy.log hash chain (tamper evidence)
vallum log verify --expect-head <hex>  # also compare against an externally stored head
vallum unlock                        # clear a tripped circuit-breaker lock
vallum doctor                        # self-check: config, hook, guardrail, hook-audit, base-url, log-chain, breaker, PATH, log dir
vallum completions <bash|zsh|fish|elvish|powershell> > completions/_vallum
```

## Examples

```bash
vallum run ls -la
vallum run cargo test
vallum run git status
vallum run pytest
vallum run npm test
vallum run sh -- -c 'exit 7'      # preserves the child exit code
vallum run --json printf "hello\n"
```

Example JSON output:

```json
{
  "command": "printf",
  "args": ["hello\\n"],
  "exit_code": 0,
  "optimizer": null,
  "tokens_before": 1,
  "tokens_after": 18,
  "sanitized_output": "[UNTRUSTED TERMINAL OUTPUT START]\nhello\n[UNTRUSTED TERMINAL OUTPUT END]\n"
}
```

Note how a tiny output ends up *larger* after wrapping: the security wrapper
has a fixed cost, and on short commands that cost dominates. Token savings
show up on the large, noisy outputs (builds, test runs, big diffs) — see
[Measuring savings](optimizers.md#measuring-savings).

## Exit codes

- The child's own exit code is propagated as Vallum's exit code on success.
- Vallum-level failures (bad config, executor spawn error, JSON serialization
  error) exit **`125`** — the `env(1)` "command not invoked" convention — so
  they are distinguishable from the child's real exit 1.
- A guardrail **`Deny`** (or an `Ask` that is declined / fails closed in a
  non-interactive session) also exits **`125`** — the command is never run. An
  `Ask` prompts on `/dev/tty`; set `security.assume_yes` /
  `VALLUM_ASSUME_YES=1` to auto-approve in scripts.
- `vallum policy test`: 0 allow, 10 ask, 20 deny, 125 config error.
- `vallum mcp scan` / `vallum skills scan` / `vallum scan`: 0 clean, 10
  findings, 20 high-severity, 125 usage error (125 wins over findings).
