# Vallum Landing Page Redesign: "Night Patrol"

Date: 2026-07-09
Status: approved by user

## Problem

The current page reads as boxed and templated: the threats section is a
three-card grid (the exact anti-pattern PRODUCT.md forbids), the pipeline is
six bordered chips, the guardrail and install sections are panels inside
panels. The user wants the page cooler, cinematic, and explicitly free of
card-heavy layout.

## Direction (user-approved decisions)

1. **Identity stays, structure changes.** Basalt + bronze palette, Cinzel /
   Geist / JetBrains Mono, Roman wall motif, all copy and content are kept.
2. **Character: cinematic/immersive.** Scroll-driven scenes, large
   typography, depth and atmosphere; controlled, not gimmicky.
3. **Tech: GSAP + ScrollTrigger allowed**, vendored locally (no CDN).
4. **Concept: "Night Patrol"** — the whole page is one continuous patrol
   along the wall at night.

## Design

### Structural spine: the patrol line

A thin bronze SVG line runs down the left edge of the entire page. It is
drawn progressively as the user scrolls (stroke-dashoffset scrubbed by
ScrollTrigger). It carries crenellation ticks and waypoint markers labeled
with Roman numerals (I, II, III…) marking each zone. This line replaces
boxes as the structural device: content hangs off the patrol line. On
mobile the line thins and hugs the edge.

### Box inventory (hard rule)

The only bordered/chromed surfaces on the entire page:

1. Terminal windows (they are literal windows).
2. The install command plinth.

Everything else is expressed with hairline rules, whitespace, typography,
and the patrol line. No card grids, no panel backgrounds, no chip rows.

### Page flow

1. **Hero — The Gate.** Carved outlined VALLVM inscription, headline,
   subline, single install chip + GitHub link. The demo moves OUT of the
   hero; the hero is full-height with one focus. Load choreography kept but
   tightened (inscription settles, copy rises staggered).

2. **Scene I — The Demonstration (pinned).** A single full-width terminal
   pins. It shows the raw `cargo test` output (secret leak, injection line,
   2,801 lines of noise). As the user scrolls, a crenellated wall sweep
   passes across the terminal and the content transforms in place into the
   sanitized version; a token counter falls 3,210 → 612. Replaces the two
   stacked hero terminals.

3. **Threats — Three Indictments (no cards).** Each threat is a full-width
   typographic statement: Roman-numeral waypoint + edge-to-edge Cinzel
   heading, a narrow measured body column, and monospace evidence lines set
   directly on the page background (no box; a bronze left tick only).
   Alternating asymmetry: I text-left/evidence-right, II mirrored, III
   centered around the giant "3,210 → 612" figure. Evidence lines stamp in
   on enter.

4. **Scene II — The Six Gates (centerpiece, pinned scrub).** Full-viewport
   pinned scene. A real output block travels through six gates; at each
   gate the lines visibly mutate: ANSI codes vanish, noise collapses, the
   secret takes a REDACTED stamp, the injection is neutralized, the
   untrusted wrapper closes around the result. Gate names are set as carved
   small-caps station inscriptions. Replaces the six-chip row.
   Mobile / reduced-motion fallback: a static vertical step list with a
   before/after per gate.

5. **Guardrail — The Verdict Ledger.** No box: three commands sit directly
   on the page like ledger entries; on enter, allow / ask / deny seals
   stamp in (scale + slight rotation settle, like wax seals). Explanatory
   copy sits beside the ledger.

6. **Metrics + Motto — Carved.** Giant JetBrains Mono numerals with an
   engraved (inset) treatment in one full-width row, hairlines above and
   below, count-up on enter. Immediately after, SI VIS PACEM, PARA VALLVM
   reveals full-bleed with letter-spacing expansion.

7. **Install — Raise the Wall.** The tabbed box dies. One command under
   stage light on an inscription plinth; a plain-text switcher
   (`shell · brew · cargo · npm`) swaps the command. The "download it, read
   it, then run it" honesty note stays. The Claude Code hook callout
   becomes a plain two-column passage, no box.

8. **Footer.** Etymology passage and links kept, recomposed to match the
   new width; closing giant inscription stays.

### Layout system

- Content max-width 1160px → 1320px, with full-bleed moments (scenes,
  motto, optimizer marquee).
- The optimizer marquee (git · cargo · pytest · …) is kept as a full-bleed
  band directly after Scene II; it is a band, not a card, so it passes the
  box rule.
- Type scale increases: h2 to clamp(3.5rem…5.5rem); threat numerals and
  metric figures at display sizes.
- Section rhythm grows to match the cinematic pacing (~9-10rem desktop).

### Motion system

- GSAP core + ScrollTrigger vendored at `vendor/gsap.min.js` and
  `vendor/ScrollTrigger.min.js`, loaded before `script.js`. No CDN.
- Pinned scrubbed scenes: Scene I (demo sweep), Scene II (six gates).
- Scrubbed: patrol line draw, hero inscription parallax.
- Enter animations: verdict seals, metric count-ups, evidence stamps,
  section reveals.
- `prefers-reduced-motion: reduce`: all pins and scrubs disabled; every
  scene renders as its static, fully readable fallback layout. Content is
  never gated behind animation.
- Short viewports / mobile: pins disabled or heavily simplified; Scene II
  uses the vertical fallback.
- The ember canvas atmosphere layer is kept, subtle.

### What is explicitly kept

All copy, colors (`--bg0…--accent`), fonts, favicon, single-page
structure, WCAG AA contrast, keyboard reachability of the install switcher
and copy buttons, honest install messaging, audit-log/metrics claims.

### Files

- `index.html` — restructured to the new flow.
- `style.css` — rewritten layout/typography; palette variables unchanged.
- `script.js` — rewritten around GSAP/ScrollTrigger with reduced-motion
  guards.
- `vendor/gsap.min.js`, `vendor/ScrollTrigger.min.js` — new, vendored.
- `DESIGN.md` — updated to describe the new layout and motion systems.

### Error handling / robustness

- If GSAP fails to load, the page must render complete and readable:
  scenes fall back to their static layouts (same mechanism as
  reduced-motion). No content may exist only inside a JS-driven state.
- Copy buttons keep their clipboard fallback behavior.

### Testing

- Visual pass at 1440, 1024, 768, 390 widths (agent-browser screenshots).
- Reduced-motion pass: emulate `prefers-reduced-motion` and verify every
  section is readable and complete.
- No-JS pass: disable JS, verify all copy is visible.
- Keyboard pass: install switcher and copy buttons operable by keyboard.
