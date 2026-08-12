#!/usr/bin/env python3
"""Prepare a supplied logo for use on the dark UI.

Run after dropping the artwork in:

    python scripts/prep-logo.py frontend/images/logo-lockup.png

It reports what the asset actually is — transparency, trim box, whether the
wordmark is dark — and writes the variants the UI needs:

    logo-lockup.png       trimmed, transparent, LIGHT text (topbar + login)
    logo-lockup-dark.png  trimmed, transparent, original colours (light surfaces)
    logo-icon.png         square shield-only crop (favicon, narrow layouts)

Why this exists: an exported logo is usually a wide frame with large empty
margins and dark text intended for white backgrounds. Dropped straight onto a
dark topbar it renders small (the margins get fitted, not the artwork) and the
wordmark is dark-on-dark. Doing the trim and the recolour here means the app can
just use the file, instead of the CSS compensating with a white panel.
"""
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    sys.exit("Pillow required:  python -m pip install pillow")

LIGHT = (238, 246, 255)      # near-white for the wordmark on dark surfaces
DARK_MAX = 120               # a pixel this dark is treated as "dark text"


def describe(im: Image.Image) -> dict:
    im = im.convert("RGBA")
    alpha = im.getchannel("A")
    lo, hi = alpha.getextrema()
    bbox = alpha.getbbox() if lo < 255 else None
    return {
        "size": im.size,
        "has_alpha": lo < 255,
        "alpha_range": (lo, hi),
        "content_bbox": bbox,
    }


def trim(im: Image.Image) -> Image.Image:
    """Drop empty margin — transparent if present, otherwise near-white."""
    im = im.convert("RGBA")
    box = im.getchannel("A").getbbox()
    if box is None:                       # fully opaque: treat white as margin
        rgb = im.convert("RGB")
        bg = Image.new("RGB", rgb.size, (255, 255, 255))
        from PIL import ImageChops
        box = ImageChops.difference(rgb, bg).convert("L").point(lambda v: 255 if v > 12 else 0).getbbox()
    return im.crop(box) if box else im


def whiten_dark(im: Image.Image) -> tuple:
    """Recolour dark pixels to near-white, leave the blues alone.

    Only near-neutral dark pixels are touched, so the shield's blues and the
    'Gate' highlight survive — a blanket invert would destroy the artwork.
    """
    im = im.convert("RGBA")
    px = im.load()
    w, h = im.size
    changed = 0
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if a < 24:
                continue
            if max(r, g, b) <= DARK_MAX and (max(r, g, b) - min(r, g, b)) <= 70:
                px[x, y] = (LIGHT[0], LIGHT[1], LIGHT[2], a)
                changed += 1
    return im, changed


def make_transparent(im: Image.Image) -> tuple:
    """Knock out a solid white background if the image has no alpha."""
    im = im.convert("RGBA")
    px = im.load()
    w, h = im.size
    cleared = 0
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if r > 244 and g > 244 and b > 244:
                px[x, y] = (r, g, b, 0)
                cleared += 1
    return im, cleared


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    src = Path(sys.argv[1])
    if not src.exists():
        sys.exit(f"not found: {src}\nSave the artwork there first.")

    im = Image.open(src)
    info = describe(im)
    print(f"source        : {src}")
    print(f"  size        : {info['size'][0]}x{info['size'][1]}")
    print(f"  transparency: {'yes' if info['has_alpha'] else 'NO — flat background'}")

    work = im.convert("RGBA")
    if not info["has_alpha"]:
        work, cleared = make_transparent(work)
        print(f"  knocked out : {cleared:,} white pixels -> transparent")

    work = trim(work)
    print(f"  trimmed to  : {work.size[0]}x{work.size[1]}  "
          f"(ratio {work.size[0] / work.size[1]:.2f}:1)")

    out_dir = src.parent
    dark_variant = out_dir / "logo-lockup-dark.png"
    work.save(dark_variant)
    print(f"  wrote       : {dark_variant.name}  (original colours, for light surfaces)")

    light, changed = whiten_dark(work.copy())
    light.save(out_dir / "logo-lockup.png")
    print(f"  wrote       : logo-lockup.png    ({changed:,} dark px -> light, for the dark UI)")

    # Square icon from the left of the lockup, where the shield sits
    w, h = work.size
    icon = work.crop((0, 0, min(h, w), h)).resize((256, 256), Image.LANCZOS)
    icon.save(out_dir / "logo-icon.png")
    print(f"  wrote       : logo-icon.png      (256x256 shield, for favicon/narrow)")

    print("\nNext: hard-reload the dashboard. If the wordmark still looks dark, "
          "raise DARK_MAX at the top of this script and re-run.")


if __name__ == "__main__":
    main()
