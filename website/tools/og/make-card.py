#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Render the social sharing card (1200x630) from the hero picture and logo:
    python3 website/tools/og/make-card.py
writes website/public/assets/img/og-card.png. Needs Pillow and rsvg-convert."""
import io
import pathlib
import subprocess

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[2]
IMG = ROOT / "public/assets/img"
FONTS = ROOT / "tools/render/fonts"
W, H, BAR = 1200, 630, 96

hero = Image.open(IMG / "hero.png").convert("RGB")
hero = hero.resize((round(hero.width * (H - BAR) / hero.height), H - BAR), Image.LANCZOS)
# The sides take the colour of the picture's edges, top to bottom.
card = Image.new("RGB", (W, H))
left = hero.crop((0, 0, 1, hero.height)).resize(((W - hero.width) // 2 + 1, hero.height))
right = hero.crop((hero.width - 1, 0, hero.width, hero.height)).resize(((W - hero.width) // 2 + 1, hero.height))
card.paste(left, (0, BAR))
card.paste(right, (W - right.width, BAR))
card.paste(hero, ((W - hero.width) // 2, BAR))
draw = ImageDraw.Draw(card)
draw.rectangle((0, 0, W, BAR), fill="#16181d")
logo = subprocess.run(["rsvg-convert", "-w", "56", "-h", "56", str(IMG / "logo.svg")], capture_output=True, check=True).stdout
logo = Image.open(io.BytesIO(logo)).convert("RGBA")
card.paste(logo, (40, (BAR - 56) // 2), logo)
name = ImageFont.truetype(str(FONTS / "Inter-SemiBold.ttf"), 44)
tag = ImageFont.truetype(str(FONTS / "Inter-Regular.ttf"), 28)
draw.text((112, BAR // 2), "Varsto", font=name, fill="#ffffff", anchor="lm")
x = 112 + draw.textlength("Varsto", font=name) + 24
draw.text((x, BAR // 2 + 2), "end-to-end encrypted sync and backup on your own storage", font=tag, fill="#b8c4ff", anchor="lm")
card.save(IMG / "og-card.png", optimize=True)
print(IMG / "og-card.png")
