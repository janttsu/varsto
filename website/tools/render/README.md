# Website illustrations: 3D renders

The pictures on the project, features and use-case pages are rendered in Blender
from the scene descriptions in this directory, then the labels are composed on top
with Pillow. The old hand-drawn SVGs (`website/tools/gen_svgs.py`) stay in
`website/public/assets/img/` as a fallback generator; no page references them.

```
scene_kit.py   builders (laptop, phone, NAS, disks, cloud, bucket, key, padlock, ...),
               shared palette, orthographic studio camera, light rig, backdrop,
               screen-space placement, dashed links, text queue
scenes.py      the 20 compositions, one function per output file
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
--no-compose                    skip the text layer
--layout-only                   build every scene and run the overlap check, no render (20 s)
```

## Overlap check

Every element registers its projected screen box (`scene_kit.register_box`:
kind `object`, `card`, `ui` for a piece on a card, `badge` for a padlock, check
or cross attached to a corner of a parent). `compose.py` adds the text boxes
measured with the real font and reports every pair that intersects, with these
exceptions only: a badge may touch its own parent on the silhouette edge (its
centre must be on or outside the parent box, never over the face); a UI piece
may lie on its card; a text may lie on a card when it is fully inside it; a text
marked `free` (letters on the shelf disks, seal initials) may lie on its element.
`render_all.py --layout-only` runs the check for all scenes without rendering;
the same check runs after every compose, and a non-empty report means the
composition must be fixed (move the badge to a free corner with `badge_at`,
`lock_at` or `attached`, nudge labels, widen the spacing).

Outputs go next to the SVGs: `website/public/assets/img/features/*.webp|png`,
`website/public/assets/img/usecases/*.webp|png` and
`website/public/assets/img/hero.webp|png` (1280 x 640 px for the 640 x 320
illustrations, 2400 x 1200 px for the hero; both are 2x for Retina displays).
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
  gradient (#f8faff to #eef2ff) so the picture sits in the light boxes.
- Materials: one Principled palette, roughness about 0.5 with a little sheen
  (clay with a soft gloss); blues #1b3a9a #2b57d6 #8aa9ff #dbe4ff, gold #f0a53a for
  keys only, green #2bb673, red #e0535a, light neutral surfaces.
- Text: Inter, node titles 28 px semi-bold, sub-labels 24 px regular muted and
  one centred caption at the bottom (sizes at 2x). `node()` puts the labels in a
  band under the projected bounding box of the object; `compose.py` warns if any
  text would overlap an object.

Render time on the development machine (12-core CPU, Cycles 160 samples with
denoising): about 50 s per 1280 x 640 picture and about 10 min for the hero, in
all roughly 25 min for the 20 files. With a free RTX 2060 (OptiX) it is a few
times faster.
