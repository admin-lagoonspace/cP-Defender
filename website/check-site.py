#!/usr/bin/env python3
"""
Validate the marketing site before it is uploaded.

Four static pages with no build step means nothing else checks them. A broken
tag or a link to a page that does not exist costs nothing to find here and is
embarrassing once it is live, so this runs over every page and refuses to be
quiet about anything it cannot resolve.
"""

import os
import re
import sys
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.abspath(__file__))

# Tags that never close, HTML and SVG alike. An SVG <path> inside an HTML
# parser looks like an unclosed element otherwise, so the self-closing SVG
# shapes are listed too.
VOID = {
    "meta", "link", "img", "br", "hr", "input", "source", "area", "base",
    "col", "embed", "param", "track", "wbr",
    "path", "rect", "circle", "line", "polyline", "polygon", "ellipse",
    "stop", "use", "feDropShadow",
}


class Checker(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.problems = []
        self.links = []
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
        if tag in ("img", "link", "script") and (d.get("src") or d.get("href")):
            self.srcs.append(d.get("src") or d.get("href"))
        if tag == "img" and not d.get("alt") and d.get("alt") != "":
            self.problems.append("img without alt: %s" % d.get("src"))
        if tag not in VOID:
            self.stack.append((tag, self.getpos()[0]))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack:
            self.problems.append("line %d: stray </%s>" % (self.getpos()[0], tag))
            return
        if self.stack[-1][0] != tag:
            self.problems.append(
                "line %d: </%s> closes <%s> opened on line %d"
                % (self.getpos()[0], tag, self.stack[-1][0], self.stack[-1][1]))
        else:
            self.stack.pop()


def main():
    pages = sorted(f for f in os.listdir(ROOT) if f.endswith(".html"))
    if not pages:
        print("no pages found in %s" % ROOT)
        return 1

    failures = 0
    for page in pages:
        path = os.path.join(ROOT, page)
        with open(path, encoding="utf-8") as fh:
            src = fh.read()

        c = Checker()
        c.feed(src)
        probs = list(c.problems)

        for tag, line in c.stack:
            probs.append("<%s> opened on line %d is never closed" % (tag, line))

        # Every internal link has to resolve to a file we are shipping.
        for href in c.links:
            if href.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = href.split("#")[0].split("?")[0]
            if target in ("", "/"):
                target = "/index.html"
            local = os.path.join(ROOT, target.lstrip("/"))
            if not os.path.isfile(local):
                probs.append("link to a file that does not exist: %s" % href)

        # Same for stylesheets, images and scripts.
        for src_url in c.srcs:
            if src_url.startswith(("http://", "https://", "data:")):
                continue
            local = os.path.join(ROOT, src_url.lstrip("/").split("?")[0])
            if not os.path.isfile(local):
                probs.append("asset that does not exist: %s" % src_url)

        # The order button is the point of the site. A page that mentions
        # ordering without the real cart URL is a dead end.
        if "Order" in src and "cart.php?a=add&amp;pid=29" not in src:
            probs.append("an order control does not point at the cart URL")

        # Raw ampersands in a URL are a validity error and break the query.
        for bad in re.findall(r'href="[^"]*?&(?!amp;|#|lt;|gt;|quot;)[^"]*"', src):
            probs.append("unescaped & in href: %s" % bad[:70])

        status = "ok " if not probs else "FAIL"
        print("%s %-18s %d link(s), %d asset(s)" % (status, page, len(c.links), len(c.srcs)))
        for p in probs:
            print("       - %s" % p)
            failures += 1

    print()
    if failures:
        print("%d problem(s). Not ready to upload." % failures)
        return 1
    print("all pages valid, every link and asset resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
