# DESIGN.md

## Theme
Dark-locked. Basalt near-black surfaces lit from above by a faint warm bronze
light. No light mode.

## Color
- `--bg0` #0c0b09 page basalt
- `--bg1` #14110c raised panel
- `--bg2` #1a160f terminal chrome / tab strip
- `--line` #262117, `--line-strong` #383021 hairlines
- `--text` #ece7dc, `--text2` #b5aea0, `--text3` #837c6f
- `--accent` #c9a24d bronze (sole accent), `--accent-bright` #ddb968
- Semantic verdicts only: `--green` #8fb573 allow, `--red` #c9705f deny/error

## Typography
- Display: Cinzel (Roman square capitals), weights 600-700. Wordmark,
  h1/h2 headings, the inscription, the motto.
- Body/UI: Geist 400-600.
- Code/terminal/numbers: JetBrains Mono 400-600.

## Motifs
- Crenellated (merlon) line: repeating-linear-gradient bronze blocks. Used at
  the hero boundary, the pipeline wall's top edge, the footer transition,
  and as marquee separators. It is the brand mark.
- The giant carved "VALLVM" inscription: outlined Cinzel letterforms behind
  the hero, opacity <= 0.35 stroke, no fill.

## Radius
Panels/terminals 10px; buttons/chips/tabs 8px. Nothing else.

## Layout
Max width 1160px. Section rhythm ~7-8rem desktop. Layout families in use:
asymmetric split (hero, guardrail), 3-cell bento (threats), full-width band
(pipeline wall, marquee), plain stat row (metrics), centered manifesto
(motto), tabbed panel (install).

## Motion
- One orchestrated page-load: inscription settles, headline/sub/CTAs rise
  staggered, terminal demo types and the wall sweep reveals the sanitized pane.
- Scroll: sections fade-rise once (IntersectionObserver); metrics count up;
  verdict tags stamp in sequence.
- Hover: bronze spotlight follows cursor on threat cards and gates; sheen on
  the install chip.
- Marquee: single slow optimizer marquee after the pipeline. Max one on page.
- Everything collapses to static under `prefers-reduced-motion: reduce`.
- No scroll listeners; IntersectionObserver + CSS only. Animate transform and
  opacity only.

## Voice
Short declaratives. Latin only where it lands (wordmark, motto
"SI VIS PACEM, PARA VALLVM", footer etymology). Zero em-dashes, zero
eyebrows, zero decorative dots.
