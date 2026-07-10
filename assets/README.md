# assets

- `og.png` — 1200×630 Open Graph / Twitter card image (referenced from `index.html`).
- `og@2x.png` — 2400×1260 master of the same frame.
- `hero.gif` — 960×434, 12s animated hero (drifting embers), for README / posts / Discord. NOT for og:image — X/Facebook/LinkedIn only show a GIF's first frame in link cards.
- `hero.mp4` — same clip as H.264 (much smaller); prefer this for native uploads to X/Reddit.

## Regenerating the OG image

The image is a styled capture of the live hero (inscription + embers intact):

```bash
# from the repo root
python3 -m http.server 8734 --bind 127.0.0.1 &
agent-browser set viewport 1200 630 2
agent-browser open http://127.0.0.1:8734/
agent-browser eval "
const s = document.createElement('style');
s.textContent = \`
  .patrol, .descend, .nav-links, .nav-gh, .skip-link { display: none !important; }
  .nav { background: transparent !important; border-bottom: none !important; box-shadow: none !important; }
  .chip-copy { display: none !important; }
  .hero-actions .btn-ghost { display: none !important; }
  .inscription { -webkit-text-stroke: 1.3px rgba(201, 162, 77, 0.34) !important; }
  .hero-copy { transform: translateY(34px); }
\`;
document.head.appendChild(s);"
agent-browser wait 4000   # let the embers drift into frame
agent-browser screenshot assets/og@2x.png
agent-browser close
sips -z 630 1200 assets/og@2x.png --out assets/og.png
```

## Regenerating the animated hero (hero.gif / hero.mp4)

Recorder gotchas: `record start` reloads the page (re-inject the style AFTER it),
resolves relative output paths against the daemon's cwd, and captures at its own
fixed size (1280×578 @ 10fps) regardless of viewport.

```bash
agent-browser open http://127.0.0.1:8734/
agent-browser record start ./hero.webm      # lands in the daemon's cwd
# re-inject the same og-mode style block as above, then:
agent-browser wait 16000
agent-browser record stop
agent-browser close
# trim the un-styled head, encode:
ffmpeg -ss 3.5 -t 12 -i hero.webm -c:v libx264 -crf 20 -pix_fmt yuv420p -movflags +faststart assets/hero.mp4
ffmpeg -ss 3.5 -t 12 -i hero.webm -vf "fps=10,scale=960:-2:flags=lanczos,palettegen" /tmp/palette.png
ffmpeg -ss 3.5 -t 12 -i hero.webm -i /tmp/palette.png -lavfi "fps=10,scale=960:-2:flags=lanczos[x];[x][1:v]paletteuse" assets/hero.gif
```
