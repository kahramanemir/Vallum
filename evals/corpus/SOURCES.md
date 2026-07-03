# Corpus sources

Provenance and license for imported corpus rows. Hand-authored rows carry no
`source` field. Only permissively-licensed datasets are imported; samples are
hand-picked for plausibility as terminal output (log lines, error messages,
scraped/README content) and may be lightly unchanged from the original.

| source (`source` field value) | dataset | license | accessed | used for |
| --- | --- | --- | --- | --- |
| `deepset/prompt-injections (Apache-2.0)` | https://huggingface.co/datasets/deepset/prompt-injections | Apache-2.0 | 2026-07-03 | injection + benign samples (en/de/fr/es) |

## Selection notes

- deepset rows longer than ~160 chars, or shaped as multi-turn chat, were
  excluded — they do not resemble command output.
- License verified via the HuggingFace dataset API (`cardData.license`).
