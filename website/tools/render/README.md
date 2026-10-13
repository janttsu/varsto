# Website illustrations: 3D renders

The pictures on the project, features, use-case and how-it-works pages are rendered in Blender
from the scene descriptions in this directory, then the labels are composed on top
with Pillow. The old hand-drawn SVGs (`website/tools/gen_svgs.py`) stay in
`website/public/assets/img/` as a fallback generator; no page references them.

```
scene_kit.py   builders (laptop, phone, NAS, disks, cloud, bucket, key, padlock, ...),
               shared palette, orthographic studio camera, light rig, backdrop,
               screen-space placement, dashed links, text queue
scenes.py      the 29 compositions, one function per picture (rendered light and dark)
compose.py     Pillow text layer (Inter), writes .webp (quality 88) and .png
render_all.py  renders every scene and composes the text in one go
fonts/         Inter Regular / Medium / SemiBold (OFL, see fonts/OFL.txt)
```

## Requirements

- Blender 4.5 LTS (portable Linux build), e.g. unpacked to `~/.local/opt/blender`.
  Download `blender-4.5.x-linux-x64.tar.xz` from
  <https://download.blender.org/release/Blender4.5/>, verify it against the
  `blender-4.5.x.sha256` file next to it, unpack with `--strip-components=1`.
- `python3` with Pillow (WebP support) for `compose.py`.
- Optional: an NVIDIA GPU for Cycles (OptiX). `render_all.py` uses it when at
  least 2.5 GB of VRAM is free, otherwise it renders on the CPU and says so.

## Render everything

```bash
cd <repository root>
~/.local/opt/blender/blender -b --python website/tools/render/render_all.py
```

Options after `--`:

```
--only features/ledger,hero     render a subset
--samples 160                   Cycles samples (default 160; the hero uses at least 192)
--device AUTO|OPTIX|CUDA|CPU    AUTO picks the GPU when enough VRAM is free
--work DIR                      scratch directory (default: $TMPDIR/varsto-render)
--out DIR                       write the pictures under DIR (drafts) instead of website/public/assets/img
--theme light|dark|both         variants to render (default both)
--no-compose                    skip the text layer
--layout-only                   build every scene and run the overlap check, no render (20 s)
```

## Overlap check

Every element registers its projected screen box and silhouette
(`scene_kit.register_box`: the convex hull of the projected mesh bounds) with a
kind: `object`, `card`, `ui` for a piece on a card, `badge` for a padlock, check
or cross attached to a corner of a parent. Every dashed or solid link registers
its path and arrow heads. `compose.py` adds the text boxes measured with the real
font and checks (clearances in grid px, 1 grid px = 2 output px):

- elements stay inside the picture; texts keep 6 px from its edge;
- elements keep 4 px from each other (hull to hull), except a UI piece on its own
  card and an element registered `free=True` (a cross placed on a dashed line);
- a UI piece (or nested card) lies inside its card with a 6 px inset;
- a badge may sit on its parent's silhouette edge but cover at most 2 % of an
  object or 30 % of a card corner (`badge_at`, `lock_at`, `attached`; move it with
  `dx`/`dy` to a free corner);
- a text keeps 6 px from every object, UI piece, badge and link, and 4 px from
  every other text; a text on a card lies inside it with a 6 px inset; a text
  marked `free` (letters on the shelf disks, seal initials) may lie on its element;
- a link keeps 4 px from the edge of a card it does not run on and 3 px from
  badges and UI pieces (links start and end at objects by design, so objects are
  not checked against links).

`render_all.py --layout-only` runs the check for all scenes without rendering;
the same check runs after every compose, and a non-empty report means the
composition must be fixed (nudge the badge, the link ends or the labels, widen
the spacing). Rows of nodes share a title baseline with `node(..., label_y=...)`.

## Light and dark

Every picture is rendered twice: `<name>.webp|png` with the light palette and
`<name>-dark.webp|png` with the dark one (`scene_kit.DARK`, `DARK_HEX` and
`compose.DARK_TEXT`, based on the site's dark tokens: page #0d0f12, surface
#14171c, text #eceef2, muted #9aa3b2, accent #8aa9ff). Neutral surfaces become
slate tones, card faces the dark surface; blues, gold, green and red stay. The
pages show one of the pair with `<picture class="theme-light">` and
`<picture class="theme-dark">` (site.css follows the theme toggle and, in auto,
the system setting). The social card (`website/tools/og/make-card.py`) uses the
light hero.

Outputs go next to the SVGs: `website/public/assets/img/features/*.webp|png`,
`website/public/assets/img/usecases/*.webp|png`,
`website/public/assets/img/encryption/*.webp|png` (the how-it-works page; the
directory keeps the name of the page it started on) and
`website/public/assets/img/hero.webp|png` (1280 x 640 px for the 640 x 320
illustrations, 2400 x 1200 px for the hero; both are 2x for Retina displays),
each with its `-dark` twin.
The scratch directory keeps the raw render (`<scene>.png`), the text layout
(`<scene>.json`) and `report.txt` with the per-scene timings.

To recompose the text without re-rendering (e.g. after editing a label style):

```bash
python3 website/tools/render/compose.py work/features_ledger.png work/features_ledger.json \
    website/public/assets/img/features/ledger
```

## Design system

- Grid: the same coordinates as the SVGs (640 x 320, hero 1200 x 600), 1 px = 1 cm
  in the scene. `place()` and `billboard()` put objects by grid point, so a layout
  is read directly from the scene functions.
- Camera: orthographic, 33 degrees elevation, 32 degrees azimuth, the same in every
  scene; objects keep the same world size everywhere, so the scale is consistent
  across pictures.
- Light: an overhead softbox plus three sun lamps (key, fill, cool rim) with
  angular size for soft shadows; the suns give every object the same shadow
  regardless of its position. The backdrop is a matte floor with the page
  gradient (#f8faff to #eef2ff; dark #181c23 to #12151b) so the picture sits in the page.
- Materials: one Principled palette, roughness about 0.5 with a little sheen
  (clay with a soft gloss); blues #1b3a9a #2b57d6 #8aa9ff #dbe4ff, gold #f0a53a for
  keys only, green #2bb673, red #e0535a, light neutral surfaces.
- Text: Inter, node titles 28 px semi-bold, sub-labels 24 px regular muted and
  one centred caption at the bottom (sizes at 2x). `node()` puts the labels in a
  band under the projected bounding box of the object; `compose.py` warns if any
  text would overlap an object.

Render time on the development machine (12-core CPU, Cycles 160 samples with
denoising): about 50 s per 1280 x 640 picture and about 10 min for the hero, in
all roughly 50 min for the 58 files (29 scenes, light and dark). With a free
RTX 2060 (OptiX) it is about 8 minutes.
