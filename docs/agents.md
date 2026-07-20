# Agent integrations

> Part of the [Vallum](../README.md) documentation. See also:
> [Guardrail & policy](guardrail.md) · [CLI reference](cli.md) ·
> [SECURITY.md](../SECURITY.md) for the full threat model.

`vallum run` works with any agent that runs shell commands. The pre-exec
guardrail also hooks **natively** into Claude Code, Cursor, Gemini CLI, and
Codex CLI — one `vallum install-hook` and dangerous commands are gated inside
the agent's own approval flow. Automatic output sanitization and token
optimization run on Claude Code (and any explicit `vallum run`); on the other
three agents Vallum gates commands without rewriting their output.

## Support matrix

| Agent | Hook point | Ask behavior | Install |
|---|---|---|---|
| Claude Code | `PreToolUse` (allow/ask/deny + rewrite through `vallum run`) | native ask | `vallum install-hook` |
| Cursor | `beforeShellExecution` (verdicts only) | native ask | `vallum install-hook --agent cursor` |
| Gemini CLI | `BeforeTool` (verdicts only) | fail-closed deny with instructions | `vallum install-hook --agent gemini` |
| Codex CLI | `PreToolUse` (verdicts only) | fail-closed deny with instructions | `vallum install-hook --agent codex` |

All four installers write to a user-level config
(`~/.claude/settings.json`, `~/.cursor/hooks.json`, `~/.gemini/settings.json`,
`~/.codex/hooks.json`) — new agents are **user-level installs only**;
`--project` remains Claude Code-specific. `uninstall-hook --agent <x>`
removes exactly the entry the installer added. Every Ask/Deny verdict, on any
agent, is recorded to `policy.log` with
`agent=<claude|cursor|gemini|codex|direct>`.

## Doctor checks

`vallum doctor` reports per-agent status (`hook (claude)`, `hook (cursor)`,
`hook (gemini)`, `hook (codex)`), showing "agent not detected — skipped" for
agents that aren't installed on the machine. It also audits the hook commands
installed under **every** hook event of each agent's config — not just
`PreToolUse`, so an injected `SessionStart` hook (CVE-2026-25725 class) is
caught too — and flags any command it did not install (a foreign hook is a
review prompt, labeled `agent (Event)`; one matching a dangerous guardrail
pattern fails the check). Separately, doctor **warns** when
`ANTHROPIC_BASE_URL` is overridden to a non-`*.anthropic.com` host — in the
process environment or a project/user `settings.json` `env` block
(`settings.local.json` included) — because that silently reroutes every API
call and your key to another endpoint (CVE-2026-21852 class); it only warns,
never fails, since proxy gateways (LiteLLM, corporate) are legitimate and only
you can confirm intent.

## Limitations, stated plainly

- **Ask degrades to deny on Gemini CLI and Codex CLI.** Neither exposes a
  native "ask the user" decision, and emitting no decision would silently
  become *allow* under auto-approve modes. Vallum fails closed instead: the
  deny reason tells you how to run the command yourself
  (`vallum run -- bash -c '<cmd>'` — the same `bash -c` wrapping the Claude
  hook uses, so a piped/compound command stays gated as one unit) or turn the
  rule off — `[policy] disabled = ["<rule>"]` for a built-in, or edit the
  matching `[[policy.rules]]` entry in your config for a user-defined one.
- **TUI-headed commands are gated but never rewritten.** `vim`, `less`,
  `top` and friends are policy-evaluated like any command (`less
  /etc/shadow` asks/denies); on a clean Allow they pass through
  unwrapped, and an approved Ask on Claude Code runs the original command
  directly, so their interactive TTY keeps working — but their *output* is
  not sanitized (it never was for passed-through commands). Direct
  `vallum run` is unaffected.
- **Codex CLI does not intercept every shell call.** Codex's own hooks
  documentation says it plainly: *"This doesn't intercept all shell calls
  yet, only the simple ones. The newer `unified_exec` mechanism allows richer
  streaming stdin/stdout handling of shell, but interception is incomplete.
  Similarly, this doesn't intercept `WebSearch` or other non-shell, non-MCP
  tool calls."* (source: <https://developers.openai.com/codex/hooks>,
  verified live 2026-07-06). A command that Codex doesn't route through the
  hook never reaches Vallum at all — there is no verdict, logged or
  otherwise, for it.
- **Codex CLI silently skips the hook until you trust it — and needs a
  recent CLI.** Installing the hook is not enforcement on Codex: Codex
  requires a one-time review of each hook definition ("Hooks need review →
  Trust all and continue" in the Codex TUI; `--dangerously-bypass-hook-trust`
  for automation), and until that happens the hook is *skipped without any
  warning* while gated commands run unguarded. Version matters too: hook
  trust handling in `codex exec` was fixed in codex-cli 0.141.0
  (openai/codex#26434), and on 0.139 the installed hook never fired at all in
  our tests. Verified live end-to-end on codex-cli 0.142.5 (2026-07-08): an
  Ask-rule command was blocked with Vallum's deny message, a benign command
  passed untouched, and both verdicts appeared in `policy.log` with
  `agent=codex`. `vallum doctor` reminds you of the trust step on its
  `hook (codex)` line — it cannot see Codex's trust state.
- **Verify enforcement after installing:** run a known-Ask command like
  `git push --force` in the agent and expect a prompt (Claude Code, Cursor) or
  a deny with instructions (Gemini CLI, Codex CLI). On Codex, complete the
  hook-trust step first or the test will silently pass through. `vallum
  doctor` reports per-agent install status.
- **These hook protocols are young.** Every field name above was confirmed
  live against each agent's current documentation on 2026-07-06 (see
  `docs/superpowers/research/2026-07-06-agent-hook-protocols.md`), and that
  pass already caught real drift from what was originally assumed —
  Cursor's stdout fields renamed camelCase to snake_case at some point after a
  ~Oct 2025 walkthrough, and Codex's shell tool name turned out to be `Bash`,
  not `shell` or `local_shell`. None of the three agents' docs carries an
  explicit CLI version stamp to pin, so treat this as validated against each
  agent's live documentation as of that date, not against a fixed release
  number — if a future agent update renames its hook event, the hook simply
  never fires again silently, so re-run the verification command above after
  upgrading any of these agents.

## Claude Code integration in depth

`vallum install-hook` writes a `PreToolUse` entry into
`~/.claude/settings.json` (default, user-level) or
`<cwd>/.claude/settings.json` (`--project`). A timestamped `.bak-<unix_ts>`
backup of the settings file is written before any modification. The command is
idempotent — re-running it without `--force` is a no-op if the entry already
exists; `--force` replaces an existing entry. Run bare on a terminal,
`vallum install-hook` opens an interactive picker (space = toggle, enter =
confirm) listing all four agents with their detected/installed status; in
non-interactive contexts (pipes, CI) it defaults to Claude Code.

Once installed, Claude Code invokes `vallum hook` before every Bash tool call.
The hook rewrites the command to
`vallum run --approval-token <token> -- bash -c '<original>'` so the full
Vallum pipeline (capture, ANSI strip, optimize, scrub, wrap) runs on every
shell invocation without any change to how you or the agent writes commands.
The approval token is an HMAC over that exact command, keyed by a
machine-local secret — it tells the inner `vallum run` the hook already gated
this command, so an approved Ask is not re-prompted, while a forged or
replayed-onto-a-different-command token is simply re-gated (see
[SECURITY.md](../SECURITY.md) for the trust boundary).

Approved Asks for four workflow rules (`git_push_force`, `git_clean_force`,
`write_crontab`, `write_git_hooks`) are remembered: the exact command +
working directory is recorded (HMAC-signed with the same machine secret,
14-day TTL anchored at your approval — re-use never extends it), and the hook
allows the identical command silently next time, logging
`ALLOW [approval_cache:<rule>]` to policy.log. Inspect with `vallum approvals
list`, wipe with `vallum approvals clear`, disable with `[security]
approval_cache = false`. Destructive rules, credential reads, agent-config
writes, and `curl | sh`-class rules are never remembered — see
[docs/guardrail.md](guardrail.md#approval-cache).

Because the hook wraps commands as `bash -c '<original>'`, Vallum unwraps
simple scripts (no pipes, redirects, quoting, or other shell metacharacters)
before optimizer matching, so `bash -c 'git status'` still hits the
`git_status` optimizer; complex scripts fall back to generic compression.
Known TUI programs (`vim`, `vi`, `nano`, `less`, `more`, `top`, `htop`,
`tmux`, `screen`) are still policy-evaluated, but never rewritten through
`vallum run` — capturing their stdout would break the TTY they need, so a
clean Allow passes them through untouched and an approved Ask runs the
original command directly. Commands already starting with `vallum` are
skipped for idempotency.

To remove the hook, run `vallum uninstall-hook` — it removes only the Vallum
entry, leaving the rest of your settings file untouched. Run bare on a
terminal, it opens the same picker over the agents that currently have a
Vallum hook installed.

**Live progress.** `vallum run --tee` appends the child's raw stdout/stderr to
`~/.vallum/live.log` as lines arrive. Watch it from a side terminal with
`tail -f ~/.vallum/live.log`. The tee target is a private file (`0600`), not a
stream the agent ever reads — the agent's input is still the wrapped, scrubbed
pipeline output on stdout. Tee is best-effort: if the file can't be opened or
written, the command runs normally without it.
