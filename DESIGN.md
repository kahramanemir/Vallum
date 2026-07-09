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
Max width 1320px with full-bleed scenes. No card grids. The only
bordered surfaces on the page: terminal windows and the install plinth.
Everything else is hairline rules, whitespace, typography, and the
patrol rail (fixed left spine, scroll-drawn, Roman-numeral waypoints).
Section flow: hero gate, pinned demonstration sweep, three typographic
indictments, pinned six-gate mutation scrub, marquee band, verdict
ledger, carved metrics, motto, install plinth.

## Motion
GSAP 3.12.5 + ScrollTrigger, vendored in /vendor (no CDN). html.gsap
gates every scene: without it (reduced motion, no JS, load failure) the
page is a complete static document — markup always ships the end state.
Pinned scrub scenes (>=900px only): demonstration sweep, six gates.
Scrubbed: patrol fill, hero inscription parallax. Enter-once: seals,
count-ups, evidence stamps, motto tracking. prefers-reduced-motion
collapses everything to static.

The nav is `position: fixed` (out of document flow), so the 100svh hero
fills the entire first viewport underneath it. Breakpoint arming for all
scroll-driven behavior uses `gsap.matchMedia` throughout: the two pinned
scenes arm/disarm at 900px, the patrol rail arms/disarms at 1100px.

## Voice
Short declaratives. Latin only where it lands (wordmark, motto
"SI VIS PACEM, PARA VALLVM", footer etymology). Zero em-dashes, zero
eyebrows, zero decorative dots.
