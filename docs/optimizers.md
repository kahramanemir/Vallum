# Output optimizers & token savings

> Part of the [Vallum](../README.md) documentation. See also:
> [Architecture](architecture.md) · [Configuration](configuration.md).

Vallum's security pipeline has a useful side effect: routing output through it
strips ANSI noise and compresses large build/test logs. Optimizers are
per-command summarizers; anything without a matching optimizer still gets
whitespace collapse and context-preserving truncation.

Disable any of them with `[optimizer] disabled = [...]` — see
[Configuration](configuration.md).

## Built-in optimizers

- `git status`: summarizes large working-tree sections while keeping branch state and representative file entries
- `git diff` / `git log`: collapse large unchanged-context runs / long commit bodies while keeping headers, hunks, and changed lines
- `cargo build|test|check|clippy|run`: collapses compile/download noise and preserves summaries, failures, and diagnostics
- `pytest` and `python -m pytest`: hides progress-dot spam while keeping collection, failure, and summary sections
- `pip install` (also `pip3` / `python -m pip install`): collapses `Requirement already satisfied` / `Collecting` / `Downloading` / `Using cached` chatter while keeping the `Installing collected packages` / `Successfully installed` outcome, errors, and warnings
- `apt`/`apt-get install` (with or without `sudo`): collapses package-list reads, `Get:` downloads, `Unpacking`/`Setting up`/`Processing triggers` progress while keeping the NEW-packages plan, the `N upgraded, N newly installed …` summary, and `E:`/`W:` diagnostics
- `mvn` / `mvnw`: collapses Maven's `Downloading from` / `Downloaded from` / `Progress` artifact chatter while keeping build phases, `[WARNING]`/`[ERROR]` lines, and the `BUILD SUCCESS`/`BUILD FAILURE` summary
- `gradle` / `gradlew`: collapses `Download https://…` dependency chatter while keeping task output and the `BUILD SUCCESSFUL`/`BUILD FAILED` result
- `dotnet build|restore|test|publish|run`: collapses NuGet `Restored …` / `Determining projects to restore` chatter while keeping build results and `CS####` diagnostics
- `go build|mod|get|install`: collapses `go: downloading <mod> <ver>` chatter while keeping compiler errors (`go test` is handled separately)
- `cmake`: collapses compiler/feature-probe chatter (`-- Detecting …`, `-- Looking for …`, `-- Performing Test …`, `-- Found …`) while keeping errors, warnings, and the `-- Configuring done` / `-- Build files …` lines
- `ninja`: collapses `[N/M] …` build-progress lines while keeping compiler warnings and errors
- `poetry`: collapses per-package `• Installing`/`Updating`/`Removing` operations while keeping the `Package operations` summary and errors
- `brew`: collapses `==> Downloading` chatter and `####…%` progress bars while keeping `==> Pouring`/`Caveats`/`Summary`, warnings, and errors
- `npm test|install|ci|run`: collapses repeated `PASS` and warning lines while preserving result summaries
- `docker build|compose`: collapse layer/step progress while keeping step headers, errors, and the final result
- `go test`: hide `=== RUN`/`--- PASS` spam while keeping failures and the summary
- `make`: surface errors/warnings while collapsing ordinary build noise
- `kubectl get`: collapse runs of healthy (`Running`/`Completed`) resources while keeping the header and any pod in a problem state (`CrashLoopBackOff`, `Pending`, `Evicted`, …)
- `terraform plan|apply`: collapse state-refresh chatter and attribute-diff bodies while keeping resource action headers, the `Plan:`/`Apply complete!` summary, and errors
- `rg` / `grep` (also `egrep`/`fgrep`): group matches by file, keep the first few per file, and summarize the rest with per-file and total counts
- `ls` / `find` / `fd` / `tree`: keep the leading entries and summarize the rest (with a top-directories breakdown for path lists); error lines are always preserved

## Measuring savings

Every `vallum run` appends one JSON record to `~/.vallum/stats.jsonl` with raw
and sanitized token estimates. Counting goes through a pluggable
`TokenEstimator`; the default is a dependency-free heuristic (word runs +
symbols) that tracks BPE better than a flat chars/4 ratio. `vallum stats`
aggregates the file. Build with `--features bpe` to count tokens with an exact
`tiktoken` (o200k_base) tokenizer instead of the default dependency-free
heuristic; it is an OpenAI-family approximation of Claude's tokenizer.

```
Vallum — Token savings report
─────────────────────────────────────────
Commands run:        142
Tokens (raw):        58,420
Tokens (sanitized):  11,205
Saved:               47,215  (80.8%)

Top savings by command
─────────────────────────────────────────
cargo build           18,940 saved   (94%)
git status            12,103 saved   (88%)
npm install            8,442 saved   (76%)
```

Note that a tiny output ends up *larger* after wrapping: the security wrapper
has a fixed cost, and on short commands that cost dominates. Savings show up
on the large, noisy outputs (builds, test runs, big diffs).

## Reproducing the savings

Run `cargo bench` to time the full pipeline against seven committed fixtures
(`git status`, `cargo build`, `pytest`, `npm install`, a minified blob, an
`rg` match list, a `find` file list) and print a raw-vs-sanitized token table.
Fixtures live in `benches/fixtures/` and are versioned with the repo, so the
savings figures are reproducible from a clean checkout. The bench also prints
a summary table to stderr after all criterion measurements complete, showing
each fixture's before/after token counts.
