# MCP & skill scanning

> Part of the [Vallum](../README.md) documentation. See also:
> [Guardrail & policy](guardrail.md) · [CLI reference](cli.md).

Beyond gating live commands, Vallum can statically scan the *configuration
surface* your agents trust: MCP server configs, skill packages, and agent
context files. Both scanners are read-only — they connect to nothing, launch
nothing, and modify nothing — and their exit codes (`0` clean, `10` findings,
`20` high-severity, `125` usage error) make them CI-usable.

## MCP scanning

`vallum mcp scan` statically inspects the MCP server configuration on your
machine — the same files your agents read — and reuses Vallum's existing
engines to flag three things without connecting to any server:

- **Embedded secrets** in a server's `env` block (the secret scrubber).
- **Risky launch commands** — a server started via `curl … | sh` and friends
  (the guardrail policy engine).
- **Prompt injection** in tool descriptions written into the config (the
  injection detector).

With the built-in ruleset a risky launch command surfaces as a warning (exit
`10`); the high-severity code (`20`) is reached only when you add a `deny`
policy rule.

**Honest limitation:** static scanning only sees descriptions written in the
config file; most servers supply tool descriptions at runtime via
`tools/list`, which a future live-introspection mode will cover.

```bash
vallum mcp scan                  # scan discovered MCP configs
vallum mcp scan --json <path>... # structured output / specific files
```

## Skill & context-file scanning

`vallum skills scan` statically checks agent **skill files** (`SKILL.md`) and
agent **context files** (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`,
`*.mdc`, `copilot-instructions.md`) for the supply-chain poisoning patterns
catalogued in 2026 research (Snyk's ToxicSkills audit, CSA's SKILL.md
context-poisoning briefing): embedded secrets, prompt injection in the prose,
risky shell commands in fenced or inline code (`curl … | sh`, base64-decode
pipes), and invisible-Unicode smuggling. It reuses the same secret, injection,
and guardrail engines as the rest of Vallum.

Scanning a skill goes past its `SKILL.md`: **every UTF-8 file bundled in the
skill package** (the directory that holds the `SKILL.md`) is scanned, because a
poisoned payload hides just as easily in a helper script or a `README` as in the
entry file (the PhantomSkill class). The walk is depth-bounded (6 levels from
the skill root) and never follows symlinks; a nested `SKILL.md` owns its own
package (a symlinked one never creates a nested root). Markdown-named aux files
keep the fence-aware parsing; every other aux file is scanned line-by-line as
commands plus a full-text injection/secret/invisible-character check. Files with
a known binary extension are skipped by extension and **counted**
(`(n binary file(s) skipped)`), never content-scanned; an aux file larger than
5 MiB, or one that is unreadable / non-UTF-8, is reported as a **Warning** —
never silently dropped, and never truncated-then-scanned (a partial read is
exactly how a payload past the cutoff would slip by).

```bash
vallum skills scan                  # discovered skills + context files
vallum skills scan ./downloaded/    # a directory, before you install it
vallum skills scan --json           # CI / pre-commit (findings carry doc_kind)
```

A document that carries **both** prompt injection **and** a risky shell
command — the measured ToxicSkills signature (91% of confirmed-malicious
skills combine the two) — is escalated to a high-severity finding, and the same
escalation fires **across files of one skill**: an injection in one bundled file
plus a risky command in another surfaces as a single high-severity
`combined_signature` at the skill's `SKILL.md` (the cross-file PhantomSkill
pattern).

## Unified scan (`vallum scan`)

`vallum scan` runs both scanners in one pass and adds two repo-health checks
(unknown names in `[policy]`/`[optimizer] disabled`, and `policy.log` hash-chain
integrity), collapsing everything into a single exit code:
**0** clean / **10** warnings / **20** high-severity / **125** usage or config
error (125 wins).

```bash
vallum scan                          # everything discoverable (user + repo)
vallum scan .                        # the current repo — the CI form
vallum scan --json .                 # aggregate JSON (carries exit_code)
vallum scan --sarif . > scan.sarif   # SARIF 2.1.0 for GitHub code scanning
vallum scan --full                   # also runs the doctor environment checks
```

`--sarif` cannot be combined with `--json` or `--full` (that is a usage error,
exit 125). SARIF locations are **file-level only** in v1 — the finding models
carry no line spans — and paths outside the working directory stay absolute, so
they will not map to repo alerts.

### GitHub Action and pre-commit

The repo ships a composite action (`action.yml`) that installs the release
binary for the runner platform, verifies it against the published `sha256`
asset (no pipe-to-shell), runs the scan, uploads the SARIF, and applies a
`fail-on: high | warning | never` policy:

```yaml
- uses: kahramanemir/Vallum@v0.9.0   # pin to a release tag
  with:
    paths: "."
    fail-on: high
```

`.pre-commit-hooks.yaml` exposes the same scan as `id: vallum-scan`
(`language: system` — it uses an already-installed `vallum`).

### SessionStart quick scan (Claude Code, opt-in)

`vallum install-hook --agent claude --session-scan` adds a `SessionStart` entry
running `vallum scan --hook-context`. It is advisory only: silent when clean,
otherwise one line of `additionalContext` summarising the finding count, and it
**always exits 0** — it never blocks session start and never executes scanned
content. `vallum uninstall-hook --agent claude` removes it along with the
`PreToolUse` entry; `vallum doctor` reports whether it is on.
