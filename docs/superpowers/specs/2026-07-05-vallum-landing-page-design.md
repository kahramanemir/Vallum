# Vallum Landing Page — Design Spec

**Date:** 2026-07-05
**Status:** Approved by user ("uygun geçelim")

## Goal

A single-page marketing/landing site for [Vallum](https://github.com/kahramanemir/Vallum) — a Rust CLI proxy that sits between AI coding agents (Claude Code, Cursor, Codex, Gemini CLI) and the shell as a security boundary: secret redaction, prompt-injection neutralization, untrusted-output wrapping, token optimization, and pre-execution guardrails.

## Decisions (user-approved)

- **Language:** English
- **Stack:** Static HTML/CSS/JS. No framework, no build step. Deployable as-is to GitHub Pages / Cloudflare Pages / Netlify.
- **Design direction:** Dark tech + subtle Roman identity. Basalt/obsidian dark background, single bronze/antique-gold accent, monumental wide-tracked display type (Trajan feel) for headings, modern sans for body, monospace for terminal content. Recurring horizontal "boundary line" motif with a subtle crenellation (rampart) pattern at section transitions.

## Concept

"The wall between your shell and the model." The Roman frontier embankment (vallum) metaphor maps directly onto the product: the boundary between inside (your system) and outside (untrusted output the model sees).

## Page structure

1. **Hero** — Monumental "VALLVM"-style title, tagline *"The security boundary between AI agents and your shell."*, one-line install command with copy button, GitHub link. Below: animated terminal demo — `vallum run cargo test` shows raw output containing an API key and an injection payload, then the sanitized version: secret redacted, output wrapped in `[UNTRUSTED TERMINAL OUTPUT]` markers, "94% tokens saved" badge.
2. **Threat trio** — Three cards: Secret Leakage / Prompt Injection / Token Waste, each with a short concrete example.
3. **How it works** — Pipeline diagram: Agent → VALLUM (ANSI strip → truncate → optimize → redact → neutralize → wrap) → Shell. The boundary metaphor made visual.
4. **Guardrail** — Pre-execution policy layer: Allow / Ask / Deny verdicts, illustrated with a dangerous command example (recursive force-delete, pipe-to-shell).
5. **Proof / metrics** — Big numbers: injection precision 1.000, recall 0.812, secret detection recall 1.000, ~80% average token savings; corpus note (85 injection payloads, 54 benign negatives).
6. **Install** — Tabbed code block: Shell installer / Homebrew (`brew install kahramanemir/homebrew-tap/vallum`) / Cargo (`cargo install vallum`) / npm (`npm install -g vallum`), plus Claude Code `install-hook` zero-config callout.
7. **Footer** — GitHub link, Apache-2.0/MIT dual license, brief "vallum" etymology note.

## Non-goals

- No docs pages, blog, or multi-page navigation.
- No external JS dependencies; terminal animation in vanilla JS.
- No backend, forms, or analytics.

## Files

- `index.html`, `style.css`, `script.js` at repo root (GitHub Pages friendly).

## Success criteria

- Renders correctly on desktop and mobile widths; no horizontal scroll.
- Terminal demo animates on load and respects `prefers-reduced-motion`.
- All install commands copy-paste correct (verbatim from README).
- Lighthouse-friendly: system/self-hosted or Google Fonts only, no heavy assets.
