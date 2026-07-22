# Configuration

> Part of the [Vallum](../README.md) documentation. See also:
> [Guardrail & policy](guardrail.md) · [Output optimizers](optimizers.md) ·
> [CLI reference](cli.md).

Vallum looks for `~/.vallum/config.toml` by default. For testing or
per-project overrides, point `VALLUM_CONFIG` at a different file. Scaffold a
commented default with `vallum config init`; print the effective merged config
with `vallum config show`.

A repo may also commit a **tighten-only** `.vallum.toml` at its git root, which
adds `ask`/`deny` rules on top of this file and nothing else — see
[Project-level rules](guardrail.md#project-level-rules-vallumtoml). It is never
part of `config show` output (the global file is the only thing that config
surface describes).

## Full example

```toml
[audit]
log_dir = "/tmp/vallum-logs"
raw_enabled = false          # raw, unredacted logging is opt-in
sanitized_enabled = true

[pipeline]
head_lines = 20
tail_lines = 20
min_optimize_tokens = 50     # skip optimize/truncate below this token estimate
max_output_bytes = 10485760  # 10 MiB capture cap; excess is dropped with a marker
timeout_secs = 300           # kill the child after N seconds (0 = disabled)
max_line_length = 2000       # truncate single lines longer than this (0 disables)

[optimizer]
disabled = []            # optimizer names to turn off; all on by default

[scrubber]
entropy = true   # context-gated entropy redaction of credential-ish values
normalize = true # strip invisible/bidi chars; fold homoglyphs for injection matching
extra_secret_patterns = [
  { pattern = "token-[0-9]+", replacement = "token-***" }
]

[security]
strict = false      # block the entire output when a prompt injection is detected
guardrail = true    # pre-exec policy layer (Allow/Ask/Deny) — default true
assume_yes = false  # auto-approve direct-mode `ask` verdicts (scripts/CI)
approval_cache = true          # remember approved Asks (exact command+cwd; narrow rule set)
approval_cache_ttl_days = 14   # days a cached approval stays valid (1-90)

[policy]
disabled = []       # built-in rule names to disable; all on by default
# [[policy.rules]]   # optional user rules; action = "ask" | "deny"
# pattern = '^\s*sudo\b'
# action = "ask"
# reason = "Elevated privileges"
# [[policy.allow]]   # scoped exception: suppress ONE built-in for matching commands
# pattern = '^git push --force origin main-backup$'
# suppresses = "git_push_force"
# reason = "release flow"
```

## Every setting

- `audit.log_dir`: audit log directory override
- `audit.raw_enabled`: enable raw (unredacted) terminal logs — **default `false`**
- `audit.sanitized_enabled`: enable or disable sanitized logs
- `pipeline.head_lines` / `pipeline.tail_lines`: truncation window
- `pipeline.min_optimize_tokens`: outputs below this estimate skip optimize/truncate
- `pipeline.max_output_bytes`: maximum bytes captured from a command (default 10 MiB)
- `pipeline.timeout_secs`: command timeout in seconds; `0` disables it (default 300)
- `pipeline.max_line_length`: cap individual line length; longer lines are truncated mid-line with an elision marker — default 2000, `0` disables
- `optimizer.disabled`: list of optimizer names to disable (git_status, git_diff, git_log, cargo, pytest, pip, apt, maven, gradle, dotnet, go_build, npm, docker, go_test, make, kubectl, terraform, grep, file_list) — default none
- `scrubber.extra_secret_patterns`: extra regex-based redaction rules
- `scrubber.entropy`: context-gated entropy redaction of credential-ish assignment values — **default `true`**
- `scrubber.normalize`: strip invisible/bidi characters and fold homoglyphs for injection matching — **default `true`**
- `security.strict`: when `true` (or `--strict`), the output is replaced with `[OUTPUT BLOCKED: prompt injection detected]` if any injection is detected — **default `false`**
- `security.guardrail`: enable the pre-exec policy layer that gates dangerous commands (Allow/Ask/Deny) — **default `true`**; set `false` to bypass entirely
- `security.assume_yes`: auto-approve direct-mode `ask` verdicts (also via `VALLUM_ASSUME_YES=1`) — **default `false`**
- `security.circuit_breaker` / `security.breaker_threshold` / `security.breaker_window_secs` / `security.breaker_cooldown_secs`: blast-radius circuit breaker — see [Guardrail & policy](guardrail.md#circuit-breaker-blast-radius)
- `security.approval_cache`: remember human-approved Asks (exact command + cwd; hard-coded eligible rules `git_push_force`, `git_clean_force`, `write_crontab`, `write_git_hooks`; TTL anchored at the approval, uses never renew it) — **default `true`**
- `security.approval_cache_ttl_days`: days a cached approval stays valid (1–90) — **default `14`**
- `policy.rules`: user policy rules — each has `pattern`, `action` (`ask` or `deny`; `allow` is rejected), and `reason`
- `policy.allow`: scoped allow exceptions — each has `pattern`, `suppresses` (exactly one built-in rule name), `reason`; applies to the raw command line only; global config only — see [Guardrail & policy](guardrail.md#scoped-allow-exceptions)
- `policy.disabled`: built-in rule names to disable (rm_rf_root, curl_pipe_shell, shell_download_exec, dd_to_device, redirect_to_device, mkfs_device, fork_bomb, chmod_777_recursive, read_sensitive_creds, git_push_force, find_delete_root, shred_sensitive, truncate_system, xargs_rm_force, reverse_shell, git_clean_force, chown_recursive_root, write_agent_config, vallum_self_disable, write_vallum_config, write_shell_profile, write_ssh_config, write_git_hooks, write_crontab, write_launch_agents, write_systemd_user; file-tool rules: file_write_shell_profile, file_write_ssh_config, file_write_git_hooks, file_write_crontab_dir, file_write_launch_agents, file_write_systemd_user, file_write_agent_config, file_write_vallum, file_read_sensitive) — default none
