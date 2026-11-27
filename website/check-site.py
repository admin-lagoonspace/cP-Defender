#!/usr/bin/env python3
"""
Validate the marketing site before it is uploaded.

Five static pages with no build step means nothing else checks them. A broken
tag or a link to a page that does not exist costs nothing to find here and is
embarrassing once it is live, so this runs over every page and refuses to be
quiet about anything it cannot resolve.

It also holds the site to the 2026-11-23 redesign rules, each of which is a
way the old site went wrong or could:

  - every page names its canonical https://www.serverscrub.com/ URL, and
    og:url agrees with it;
  - nothing is loaded from another host (a security vendor's page should not
    hand its visitors to a font CDN, and the deploy cannot verify it);
  - no logo.png, and no /serverscrub/code/ -- that install URL is aliased
    away on the CDN host and 404s, and the old site told customers to run it;
  - one <h1>, no skipped heading levels, no style="" and no page <style>;
  - hex colours only inside the :root token block of site.css;
  - every local file a page references is in deploy-site.sh's PAGES/ASSETS,
    or the deploy would publish a page whose images never arrive;
  - htaccess.site keeps its markers, and every redirect in it exempts
    /releases, because installed servers read updates there and treat a 301
    as "unreadable".

SS_DEPLOY_SCRIPT overrides where deploy-site.sh is read from (tests use it).
"""

import os
import re
import sys
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.abspath(__file__))
DEPLOY = os.environ.get("SS_DEPLOY_SCRIPT") or os.path.join(
    os.path.dirname(ROOT), "scripts", "deploy-site.sh")
CANON_BASE = "https://www.serverscrub.com/"
HT_BEGIN = "# BEGIN ServerScrub site"
HT_END = "# END ServerScrub site"

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
        self.headings = []
        self.canonical = []
        self.og_url = None
        self.external = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        rel = (d.get("rel") or "").split()
        if re.match(r"^h[1-6]$", tag):
            self.headings.append((int(tag[1]), self.getpos()[0]))
        if tag == "link" and "canonical" in rel:
            # The canonical names this site's own public URL; it is not a
            # resource, so it is neither an asset nor an external load.
            self.canonical.append(d.get("href") or "")
        elif tag in ("img", "link", "script"):
            v = d.get("src") or d.get("href")
            if v:
                self.srcs.append(v)
                if re.match(r"^(https?:)?//", v, re.I):
                    self.external.append("<%s> %s" % (tag, v))
        if tag == "meta" and d.get("property") == "og:url":
            self.og_url = d.get("content")
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
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


def bash_array(src, name):
    """The words of NAME=( ... ) in a bash script, comments dropped."""
    m = re.search(r"^%s=\((.*?)\)" % name, src, re.S | re.M)
    if not m:
        return None
    words = []
    for line in m.group(1).splitlines():
        words.extend(line.split("#", 1)[0].split())
    return words


def read_manifest():
    """(docroot-relative paths deploy-site.sh publishes, problems)."""
    try:
        with open(DEPLOY, encoding="utf-8") as fh:
            src = fh.read()
    except OSError as e:
        return set(), ["cannot read the deploy manifest %s: %s" % (DEPLOY, e)]
    pages, assets = bash_array(src, "PAGES"), bash_array(src, "ASSETS")
    probs = []
    if pages is None or assets is None:
        probs.append("deploy-site.sh has no PAGES/ASSETS array to check against")
    listed = set((pages or []) + (assets or []))
    for f in sorted(listed):
        if not os.path.isfile(os.path.join(ROOT, f)):
            probs.append("deploy-site.sh publishes %s, which does not exist" % f)
    return listed, probs


def local_path(url):
    """Docroot-relative path for a local URL, or None if it is not local."""
    if re.match(r"^([a-z][a-z0-9+.-]*:|//|#)", url, re.I):
        return None
    t = url.split("#")[0].split("?")[0]
    if t in ("", "/"):
        t = "/index.html"
    return t.lstrip("/")


def redesign_checks(page, src, c, manifest):
    probs = []

    want = CANON_BASE + ("" if page == "index.html" else page)
    if len(c.canonical) != 1:
        probs.append("expected one rel=canonical, found %d" % len(c.canonical))
    elif c.canonical[0] != want:
        probs.append("canonical is %s, expected %s" % (c.canonical[0], want))
    if c.og_url != want:
        probs.append("og:url is %s, expected %s" % (c.og_url, want))

    for e in c.external:
        probs.append("resource loaded from another host: %s" % e)

    for bad in ("logo.png", "/serverscrub/code/"):
        if bad in src:
            probs.append("references %s" % bad)

    if re.search(r"\sstyle\s*=", src, re.I):
        probs.append("has a style= attribute; use the stylesheet tokens")
    if re.search(r"<style[\s>]", src, re.I):
        probs.append("has a page-local <style> block")

    levels = [lv for lv, _ in c.headings]
    if levels.count(1) != 1:
        probs.append("expected exactly one <h1>, found %d" % levels.count(1))
    prev = 0
    for lv, line in c.headings:
        if lv > prev + 1:
            probs.append("line %d: <h%d> skips a level after <h%d>" % (line, lv, prev))
        prev = lv

    for url in c.links + c.srcs:
        lp = local_path(url)
        if lp is not None and lp not in manifest:
            probs.append("%s is referenced but not in deploy-site.sh PAGES/ASSETS" % lp)
    return probs


def site_wide_checks():
    probs = []
    with open(os.path.join(ROOT, "assets", "css", "site.css"), encoding="utf-8") as fh:
        css = re.sub(r"/\*.*?\*/", "", fh.read(), flags=re.S)
    root = re.search(r":root\s*\{[^}]*\}", css)
    outside = css.replace(root.group(0), "") if root else css
    for hx in sorted(set(re.findall(r"#[0-9a-fA-F]{3,8}\b", outside))):
        probs.append("site.css: hex colour %s outside the :root tokens" % hx)
    if re.search(r"@import|url\(\s*['\"]?(https?:)?//", css, re.I):
        probs.append("site.css loads something from another host")

    try:
        with open(os.path.join(ROOT, "htaccess.site"), encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return probs + ["htaccess.site is missing"]
    if not lines or lines[0] != HT_BEGIN or lines[-1] != HT_END:
        probs.append("htaccess.site must start with '%s' and end with '%s'" % (HT_BEGIN, HT_END))
    if sum(1 for l in lines if l in (HT_BEGIN, HT_END)) != 2:
        probs.append("htaccess.site must contain each marker exactly once")
    conds, rules = [], 0
    for l in lines:
        s = l.strip()
        if s.startswith("RewriteCond"):
            conds.append(s)
        elif s.startswith("RewriteRule"):
            rules += 1
            if not any(re.match(r"RewriteCond\s+%\{REQUEST_URI\}\s+!\^/\(releases\b", x) for x in conds):
                probs.append("htaccess.site: a RewriteRule without the /releases exemption: %s" % s)
            conds = []
    if rules == 0:
        probs.append("htaccess.site has no RewriteRule at all")
    return probs


def main():
    manifest, mprobs = read_manifest()
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
            if src_url.startswith(("http://", "https://", "//", "data:")):
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

        probs.extend(redesign_checks(page, src, c, manifest))

        status = "ok " if not probs else "FAIL"
        print("%s %-18s %d link(s), %d asset(s)" % (status, page, len(c.links), len(c.srcs)))
        for p in probs:
            print("       - %s" % p)
            failures += 1

    site_probs = mprobs + site_wide_checks()
    print("%s %-18s manifest, stylesheet, htaccess.site"
          % ("ok " if not site_probs else "FAIL", "(site)"))
    for p in site_probs:
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
