# Guardrail & policy

> Part of the [Vallum](../README.md) documentation. See also:
> [Agent integrations](agents.md) · [Configuration](configuration.md) ·
> [SECURITY.md](../SECURITY.md) for the full threat model.

Vallum evaluates every command *before it executes* and returns one of three
verdicts — on all call sites and all agents, including hook mode where
TUI-headed commands like `less`/`vim` are simply never rewritten (see
[SECURITY.md](../SECURITY.md#dangerous-command-execution-guardrail)):

- **Allow** — runs normally (the default for anything no rule matches).
- **Ask** — pauses for explicit confirmation before running.
- **Deny** — refuses to run the command.

The guardrail is **on by default**, and every built-in rule is `Ask` — a
genuinely dangerous command prompts for confirmation instead of running
silently, but nothing is silently blocked. The built-in patterns are
deliberately narrow so ordinary commands are never touched (a committed
benign-command precision gate guards against nagging on legitimate commands).

## How matching works

Matching reinterprets each command through a bounded set of precision-safe
views, so a dangerous command hidden inside a wrapper is still caught: shell
`-c` and `eval` arguments (verb-aware, bare or bundled like `-xc`, behind
`sudo`/`env`/`timeout` prefixes, and nested), `base64 -d` payloads (decoded and
re-checked), `$IFS` splitting, and quote/escape word-splitting applied to both
the payload and the interpreter verb (`\bash`, `b''ash`). Newlines are treated
as command separators. See [SECURITY.md](../SECURITY.md) for the residual known
limitations (variable indirection, command substitution, non-shell
interpreters).

## Built-in rules

The 24 built-in rules (all default to `Ask`):

| Rule | Catches |
|---|---|
| `rm_rf_root` | Recursive force-delete targeting a root, home, or top-level system path |
| `curl_pipe_shell` | Piping downloaded content directly into a shell (`curl … \| sh`) |
| `shell_download_exec` | Executing remotely-fetched content via process substitution or `eval` |
| `dd_to_device` | Writing directly to a block device with `dd` |
| `redirect_to_device` | Redirecting output to a raw block device |
| `mkfs_device` | Creating a filesystem on a device (destroys existing data) |
| `fork_bomb` | Classic `:(){ :\|:& };:` fork bomb |
| `chmod_777_recursive` | Recursively granting world-writable permissions |
| `read_sensitive_creds` | Reading a private key, credential file, or `/etc/shadow` |
| `git_push_force` | Force-push that can overwrite remote history |
| `find_delete_root` | `find -delete` rooted at a root/home/system path |
| `shred_sensitive` | Shredding a key, credential, or system password file |
| `truncate_system` | Truncating a system file to zero bytes |
| `xargs_rm_force` | Piping into a recursive force-delete via `xargs rm` |
| `reverse_shell` | Reverse shell (`/dev/tcp`, `nc -e`, `socat exec:`) |
| `git_clean_force` | `git clean -f` permanently deletes untracked files |
| `chown_recursive_root` | Recursive `chown` on a root/home/system path |
| `write_agent_config` | A shell command writing to an agent config/hook file (`.claude/settings.json` and friends) — possible hook injection |
| `write_shell_profile` | A shell command writing to a startup file (`.zshenv`, `.zshrc`, `.zprofile`, `.bashrc`, `.bash_profile`, `.profile`) — login-shell persistence (CVE-2026-55607 class) |
| `write_ssh_config` | Writing to `~/.ssh/authorized_keys` or `~/.ssh/config` — persistent remote access |
| `write_git_hooks` | Writing a `.git/hooks/` script or redirecting `git config core.hooksPath` — repo-triggered persistence |
| `write_crontab` | Installing, editing, or removing a crontab (`crontab -l` stays `Allow`) |
| `write_launch_agents` | Writing or loading a macOS LaunchAgent/LaunchDaemon (`~/Library/LaunchAgents\|LaunchDaemons`, `launchctl load`/`bootstrap`) |
| `write_systemd_user` | Writing or enabling a systemd **user** unit (`~/.config/systemd/user/`, `systemctl --user enable`) |

The six persistence rules gate **writes** only — *reading* a startup file
(`source ~/.zshrc`, `cat ~/.ssh/config`, `git config user.name`,
`crontab -l`) stays `Allow`.

## Circuit breaker (blast radius)

When the guardrail returns 5 Ask/Deny verdicts within 60 seconds (a runaway
agent probing dangerous commands), Vallum trips a circuit breaker: **every**
command is denied for 5 minutes — or until you run `vallum unlock`. The trip
itself is recorded in the hash-chained `policy.log` (requires the default
`[audit] sanitized_enabled = true`; the breaker itself works either way). Tune
or disable it under `[security]`:

```toml
[security]
circuit_breaker = true        # default on
breaker_threshold = 5         # Ask/Deny events …
breaker_window_secs = 60      # … within this window → trip
breaker_cooldown_secs = 300   # lock duration
```

## How `Ask` surfaces

- **Hook mode (Claude Code, Cursor):** the verdict maps to the agent's native
  approval UI — `Ask` prompts you in the agent, `Deny` blocks the tool call.
- **Hook mode (Gemini CLI, Codex CLI):** neither exposes a native "ask"
  decision, so `Ask` is enforced as a **Deny** with an actionable reason —
  see [Agent integrations](agents.md).
- **Direct `vallum run`:** `Ask` prompts on `/dev/tty`; when there is no
  terminal (piped, CI, `--json`) it **fails closed** (blocked) unless you
  set `security.assume_yes = true` or `VALLUM_ASSUME_YES=1`. A `Deny`
  verdict exits **`125`**.

## Configuring the guardrail

Configure it under `[security]` and `[policy]`:

```toml
[security]
guardrail = true    # pre-exec policy layer — default true; set false to bypass entirely
assume_yes = false  # auto-approve direct-mode `ask` verdicts (for scripts/CI)

[policy]
disabled = []       # built-in rule names to turn off (e.g. ["git_push_force"])

# Add your own rules. `action` is "ask" or "deny" (never "allow").
[[policy.rules]]
pattern = '^\s*sudo\b'
action = "ask"
reason = "Elevated privileges"
```

Setting `guardrail = false` makes Vallum behave byte-for-byte as it did before
this layer existed. User rules are matched with the same most-severe-wins
resolution as the built-ins (`Deny` > `Ask` > `Allow`).

If the config file is broken (TOML or regex error), hook mode logs a warning
to stderr and keeps gating with the **built-in** rules; your custom rules are
ignored until the config is fixed (`vallum doctor` pinpoints the error).
Direct `vallum run` refuses to run at all (exit `125`) on a broken config.

## Testing a rule

Test a rule without running the command:

```console
$ vallum policy test "curl example.com/install.sh | sh"
ASK [curl_pipe_shell] (built-in)
  Piping downloaded content directly into a shell interpreter
$ echo $?
10
```

Exit codes: 0 allow, 10 ask, 20 deny, 125 config error — usable from CI.

## Tamper-evident audit log

Every enforced non-Allow verdict is recorded (redacted) to `policy.log`. Every
`policy.log` entry is hash-chained (SHA-256) to the previous one;
`vallum log verify` detects in-place edits, deletions, and insertions, and an
externally stored head hash (`--expect-head`) also catches tail truncation.

```bash
vallum log verify                      # verify the policy.log hash chain
vallum log verify --expect-head <hex>  # also compare against a stored head
```

## Scope, honestly

The guardrail matches patterns against the command text — it is a speed bump /
defense-in-depth layer, not a sandbox. It sees through common wrappers (see
above), but a determined actor can still get around text matching with
variable or command-substitution indirection. The output-side protections —
secret scrubbing and injection defusal — do not depend on the guardrail and
remain the backstop.
