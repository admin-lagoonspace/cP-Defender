#!/usr/bin/env python3
"""
Render the marketing site's raster icons from website/assets/img/mark.svg.

The PNGs and the ICO are build output. Editing one by hand is how a site ends
up with a favicon that no longer matches its logo, so this is the only thing
that writes them:

    python/python.exe scripts/render-site-icons.py

How: headless Chrome (or Edge) screenshots the SVG once at 512x512 with a
transparent background, and Pillow downsamples that master to each size.
One rasterisation, many sizes, so every icon is the same drawing.

    favicon.png   32x32    transparent corners
    mark-64.png   64x64    transparent corners
    icon-180.png  180x180  opaque -- iOS ignores transparency and fills black
    favicon.ico   16 + 32  at the docroot (website/favicon.ico)

Not shipped, not run on the server. Needs Pillow (present in the
project-local python/ build) and a Chromium browser on this machine.
"""

import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "website", "assets", "img")
SRC = os.path.join(IMG, "mark.svg")
MASTER = 512
# The tile colour in mark.svg; icon-180 is flattened onto it.
INK = (0x1B, 0x24, 0x30, 255)

BROWSERS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "google-chrome", "chromium", "chromium-browser",
]


def browser():
    for b in BROWSERS:
        if os.path.isfile(b) or shutil.which(b):
            return b
    sys.exit("no Chromium browser found to rasterise the SVG")


def render_master(tmp):
    page = os.path.join(tmp, "m.html")
    with open(page, "w", encoding="utf-8") as fh:
        fh.write('<!doctype html><html><body style="margin:0;background:transparent">'
                 '<img src="file:///%s" width="%d" height="%d" style="display:block">'
                 '</body></html>' % (SRC.replace("\\", "/"), MASTER, MASTER))
    out = os.path.join(tmp, "master.png")
    subprocess.run([
        browser(), "--headless=new", "--disable-gpu", "--hide-scrollbars",
        "--allow-file-access-from-files", "--force-device-scale-factor=1",
        "--default-background-color=00000000",
        "--window-size=%d,%d" % (MASTER, MASTER),
        "--user-data-dir=" + os.path.join(tmp, "profile"),
        "--screenshot=" + out, "file:///" + page.replace("\\", "/"),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    im = Image.open(out).convert("RGBA")
    if im.size != (MASTER, MASTER):
        im = im.crop((0, 0, MASTER, MASTER))
    # A blank screenshot means the SVG never loaded; refuse to write icons from it.
    if im.getextrema()[3][1] == 0:
        sys.exit("the browser produced an empty image -- mark.svg did not render")
    return im


def main():
    tmp = tempfile.mkdtemp(prefix="ss-icons-")
    try:
        master = render_master(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    def size(n):
        return master.resize((n, n), Image.LANCZOS)

    size(32).save(os.path.join(IMG, "favicon.png"), optimize=True)
    size(64).save(os.path.join(IMG, "mark-64.png"), optimize=True)

    flat = Image.new("RGBA", (180, 180), INK)
    flat.alpha_composite(size(180))
    flat.convert("RGB").save(os.path.join(IMG, "icon-180.png"), optimize=True)

    size(32).save(os.path.join(ROOT, "website", "favicon.ico"),
                  sizes=[(16, 16), (32, 32)])

    for p in ("assets/img/favicon.png", "assets/img/mark-64.png",
              "assets/img/icon-180.png", "favicon.ico"):
        full = os.path.join(ROOT, "website", p)
        print("%-24s %6d bytes" % (p, os.path.getsize(full)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
