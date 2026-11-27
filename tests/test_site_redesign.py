#!/usr/bin/env python3
"""The marketing site: one canonical https://www host, never at the CDN's expense.

What was wrong (2026-11-23):

  * The install command on index.html and install.html was
    bash <(curl -fsSL https://serverscrub.com/serverscrub/code/get.sh). On the
    CDN host /serverscrub/ is shadowed by the plugin's own global Alias, so
    that URL 404s: the site told every prospective customer to run a command
    that fails. The live bootstrap is /releases/get.sh.
  * deploy-site.sh chowned four pages by name and missed status.html, so the
    release dashboard stayed root-owned after every deploy.
  * features.html said "Fifteen modules" over sixteen cards, the index said
    "15+", and the WAF copy said "see what was blocked" about a WAF that can
    run in DetectionOnly -- the same false claim that once wrote
    action = 'block' on 148,551 events that were never blocked.
  * Nothing sent visitors to one canonical address. Adding that is the risky
    part: the same docroot is the update CDN, and UpdateChecker.php takes the
    status from the FIRST response line and accepts only 200. A 301 in front
    of /releases/latest.json makes every installed panel report the manifest
    unreadable and silently stop seeing updates.

So the redirect rules live in a marked .htaccess block that exempts /releases/
on both schemes and hosts, and the merge that installs it must never clobber
cPanel's own rules. The merge is executed for real here against temporary
files; the Apache behaviour of the rules themselves needs a real httpd and is
Shakaal's docker check, not something this file can claim.

Run by tests/run.php alongside the PHP suite.
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SITE = os.path.join(REPO, 'website')
DEPLOY = os.path.join(REPO, 'scripts', 'deploy-site.sh')
CHECK = os.path.join(SITE, 'check-site.py')
PAGES = ['index.html', 'features.html', 'pricing.html', 'install.html', 'status.html']

_passed = 0
_failed = 0


def ok(cond, what):
    global _passed, _failed
    if cond:
        _passed += 1
        print('PASS ' + what)
    else:
        _failed += 1
        print('FAIL ' + what)


def eq(expected, actual, what):
    ok(expected == actual, what + ('' if expected == actual
                                   else '  (expected %r, got %r)' % (expected, actual)))


def read(path, mode='r'):
    if 'b' in mode:
        with open(path, 'rb') as fh:
            return fh.read()
    with open(path, encoding='utf-8') as fh:
        return fh.read()


HTML = {p: read(os.path.join(SITE, p)) for p in PAGES}
DEP = read(DEPLOY)
HT = read(os.path.join(SITE, 'htaccess.site'))

# ── 1. The validator passes the real site ─────────────────────────────────────
r = subprocess.run([sys.executable, CHECK], stdout=subprocess.PIPE,
                   stderr=subprocess.STDOUT, universal_newlines=True)
eq(0, r.returncode, 'check-site.py passes the site as shipped')
if r.returncode:
    print(r.stdout)

# ── 2. ...and fails on each seeded defect, one at a time ──────────────────────
#
# A validator that passes everything proves nothing. Each defect below is one
# the redesign rules exist to stop, applied to a throwaway copy.


def seeded(label, page, mutate, target='page'):
    d = tempfile.mkdtemp(prefix='ss-site-')
    try:
        w = os.path.join(d, 'website')
        shutil.copytree(SITE, w)
        dep = os.path.join(d, 'deploy-site.sh')
        shutil.copy(DEPLOY, dep)
        path = {'page': os.path.join(w, page or ''), 'deploy': dep,
                'css': os.path.join(w, 'assets', 'css', 'site.css'),
                'ht': os.path.join(w, 'htaccess.site')}[target]
        src = read(path)
        new = mutate(src)
        assert new != src, 'seed for "%s" did not change anything' % label
        with open(path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(new)
        env = dict(os.environ, SS_DEPLOY_SCRIPT=dep)
        rr = subprocess.run([sys.executable, os.path.join(w, 'check-site.py')],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            universal_newlines=True, env=env)
        ok(rr.returncode != 0, 'check-site.py FAILS on: ' + label)
    finally:
        shutil.rmtree(d, ignore_errors=True)


seeded('a page with its canonical link removed', 'pricing.html',
       lambda s: re.sub(r'<link rel="canonical"[^>]*>\n', '', s))
seeded('a canonical on the apex instead of www', 'install.html',
       lambda s: s.replace('href="https://www.serverscrub.com/install.html"',
                           'href="https://serverscrub.com/install.html"', 1))
seeded('a style="x" attribute', 'index.html',
       lambda s: s.replace('<main id="main">', '<main id="main" style="x">'))
seeded('a Google Fonts stylesheet', 'features.html',
       lambda s: s.replace('</head>', '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">\n</head>'))
seeded('a reference to logo.png', 'index.html',
       lambda s: s.replace('/assets/img/logo.svg', '/assets/img/logo.png', 1))
seeded('the dead /serverscrub/code/ install URL', 'install.html',
       lambda s: s.replace('https://serverscrub.com/releases/get.sh',
                           'https://serverscrub.com/serverscrub/code/get.sh', 1))
seeded('a second <h1>', 'pricing.html',
       lambda s: s.replace('<h2>Included</h2>', '<h1>Included</h1>'))
seeded('a skipped heading level (h1 -> h3)', 'install.html',
       lambda s: s.replace('<h2>Before you start</h2>', '<h3>Before you start</h3>'))
seeded('an asset removed from the deploy ASSETS array', None,
       lambda s: s.replace('  assets/img/logo.svg\n', ''), target='deploy')
seeded('a hex colour outside the :root tokens', None,
       lambda s: s + '\n.x { color: #ff0000; }\n', target='css')
seeded('a redirect rule without the /releases exemption', None,
       lambda s: s.replace('RewriteCond %{REQUEST_URI} !^/(releases|serverscrub)(/|$) [NC]\n'
                           'RewriteCond %{REQUEST_URI} !^/\\.well-known/ [NC]\n'
                           'RewriteCond %{HTTP_HOST} ^serverscrub', 'RewriteCond %{HTTP_HOST} ^serverscrub', 1),
       target='ht')
seeded('htaccess.site without its END marker', None,
       lambda s: s.replace('# END ServerScrub site\n', ''), target='ht')

# ── 3. The copy tells customers the truth ─────────────────────────────────────
allsite = ''.join(HTML.values())
ok('/serverscrub/code/' not in allsite,
   'THE LIVE DEFECT: no page tells a customer to run the 404ing /serverscrub/code/ installer')
for p in ('index.html', 'install.html'):
    ok('bash &lt;(curl -fsSL https://serverscrub.com/releases/get.sh)' in HTML[p],
       p + ' gives the live bootstrap URL, on the apex CDN host')
ok('bash &lt;(wget -qO- https://serverscrub.com/releases/get.sh)' in HTML['install.html'],
   'install.html also gives the wget form for servers without curl')
ok('see what was blocked' not in HTML['features.html'],
   'the WAF copy no longer claims blocks a DetectionOnly WAF never made')
ok('whether it is blocking or only detecting' in HTML['features.html'],
   'it says what the WAF matched and which mode it is in')
for claim in ('Fifteen', '15+', 'Sixteen', 'about a minute'):
    ok(claim not in allsite,
       'no "%s": a module count that disagreed with the cards, or an unbacked timing' % claim)
for p in PAGES:
    ok('cart.php?a=add&amp;pid=29' in HTML[p], p + ' keeps the real order link')

# ── 4. One header, one footer, one canonical per page ─────────────────────────


def chrome(src, a, b):
    i, j = src.index(a), src.index(b)
    return re.sub(r' aria-current="page"', '', src[i:j])


hdr = {p: chrome(HTML[p], '<header class="masthead">', '</header>') for p in PAGES}
ftr = {p: chrome(HTML[p], '<footer class="foot">', '</footer>') for p in PAGES}
eq(1, len(set(hdr.values())), 'every page carries the same header')
eq(1, len(set(ftr.values())), 'and the same footer')
for p in PAGES:
    want = 'https://www.serverscrub.com/' + ('' if p == 'index.html' else p)
    ok('<link rel="canonical" href="%s">' % want in HTML[p], p + ' names ' + want + ' as canonical')
    ok('<meta property="og:url" content="%s">' % want in HTML[p], 'and og:url agrees')
    ok('<link rel="icon" href="/assets/img/favicon.svg" type="image/svg+xml">' in HTML[p]
       and 'href="/assets/img/icon-180.png"' in HTML[p], p + ' has the SVG icon and the touch icon')
    ok('class="skip" href="#main"' in HTML[p] and 'id="main"' in HTML[p],
       p + ' has a working skip link')
ok('<meta name="robots" content="noindex">' in HTML['status.html'], 'status.html stays noindex')
ok('status.html' not in read(os.path.join(SITE, 'sitemap.xml')), 'and stays out of the sitemap')

# ── 5. status.html reads what the servers read ────────────────────────────────
st = HTML['status.html']
ok("var CDN  = 'https://serverscrub.com/releases';" in st,
   'status.html reads the CDN at the APEX url the servers use, not a relative '
   '/releases that would resolve on www and hit a different proxy-cache key')
ok('.style.' not in st, 'the verdict colour comes from stylesheet tokens, not inline styles')
ok('Could not tell.' in st and 'if (!cdnBusted && !cdnPlain)' in st,
   'an unreadable CDN is "could not tell" -- it used to fall through to "the '
   'manifest is current but the archive is missing", a verdict made from no reading')
ok(st.index('if (!cdnBusted && !cdnPlain)') < st.index('if (cdnBusted && cdnPlain && cdnBusted !== cdnPlain)'),
   'and that check runs before any verdict that assumes a reading exists')
for i in ('v-published', 'v-cdn', 'v-zip', 'n-zip', 'v-mirror', 'readings', 'cmd', 'checked', 'verdict'):
    ok('id="%s"' % i in st, 'element #%s the script writes to still exists' % i)
ok("tree || 'not published'" not in st,
   'latest/VERSION is not "not published" when it could not be read -- with the '
   'CDN read CORS-blocked (status 0) it claimed something it never saw (Shakaal, finding 2)')
ok("treeR.status === 404 ? 'not published' : unread(treeR)" in st,
   'only a real 404 says "not published"; a failed read says "could not tell" like the other rows')

# ── 5b. Mobile hero command (Shakaal, finding 4) ──────────────────────────────
CSS = read(os.path.join(SITE, 'assets', 'css', 'site.css'))
ls = re.search(r'\.label-strip code \{([^}]*)\}', CSS)
ok(ls and 'overflow-wrap: anywhere' not in ls.group(1) and 'overflow-x: auto' in ls.group(1)
   and 'white-space: pre' in ls.group(1),
   'the hero install command scrolls sideways instead of breaking mid-URL at 375px '
   '("https://serverscrub.com/releases/ge" / "t.sh" read like a typo)')
ok('<code tabindex="0">bash &lt;(curl' in HTML['index.html'],
   'and the scrollable command can be reached with the keyboard')

# ── 6. The logo and icons ─────────────────────────────────────────────────────
IMG = os.path.join(SITE, 'assets', 'img')
ok(not os.path.exists(os.path.join(IMG, 'logo.png')), 'logo.png is no longer shipped from the repo')
ok(os.path.getsize(os.path.join(IMG, 'logo.svg')) <= 8192, 'logo.svg is within 8 KB')
ok('<text' not in read(os.path.join(IMG, 'logo.svg')),
   'the wordmark is paths, so it renders the same without any font installed')
ok('viewBox="0 0 32 32"' in read(os.path.join(IMG, 'mark.svg')), 'mark.svg is square')
LOGO = read(os.path.join(IMG, 'logo.svg'))
vb = re.search(r'viewBox="0 0 ([\d.]+) 32"', LOGO)
ok(vb is not None, 'logo.svg is 32 units tall')
sw = [float(x) for x in re.findall(r'stroke="#1b2430" stroke-width="([\d.]+)"', LOGO)]
ok(sw and min(sw) >= 4.5,
   'the wordmark stroke is heavy enough to sit beside the bold condensed headings '
   '(the 3.6-unit monoline read as thinner than the type around it)')
if vb:
    w = float(vb.group(1))
    for p in PAGES:
        for m in re.finditer(r'<img src="/assets/img/logo\.svg"[^>]*width="(\d+)" height="(\d+)"', HTML[p]):
            ok(abs(int(m.group(1)) / int(m.group(2)) - w / 32) < 0.05,
               '%s: the logo is shown at its own aspect ratio (%sx%s), not squeezed' % (p, m.group(1), m.group(2)))


def png_info(path):
    b = read(path, 'rb')
    assert b[:8] == b'\x89PNG\r\n\x1a\n', path + ' is not a PNG'
    w, h, depth, ctype = struct.unpack('>IIBB', b[16:26])
    return w, h, ctype, len(b)


for name, size, opaque in (('favicon.png', 32, False), ('mark-64.png', 64, False), ('icon-180.png', 180, True)):
    w, h, ctype, n = png_info(os.path.join(IMG, name))
    eq((size, size), (w, h), name + ' is %dx%d' % (size, size))
    ok(n <= 20480, name + ' is within 20 KB (%d bytes)' % n)
    if opaque:
        ok(ctype in (0, 2), 'icon-180.png has no alpha channel: iOS fills transparency with black')
ico = read(os.path.join(SITE, 'favicon.ico'), 'rb')
count = struct.unpack('<HHH', ico[:6])[2]
sizes = sorted((ico[6 + 16 * i] or 256) for i in range(count))
eq([16, 32], sizes, 'favicon.ico at the docroot carries 16 and 32, ending the default-request 404s')

# ── 7. htaccess.site: what the rules say ─────────────────────────────────────
ok(HT.startswith('# BEGIN ServerScrub site\n') and HT.endswith('# END ServerScrub site\n'),
   'the block opens and closes with its markers')
rules = re.findall(r'((?:^RewriteCond[^\n]*\n)+)^RewriteRule ([^\n]*)$', HT, re.M)
ok(len(rules) == 2, 'two redirect rules: http->https and apex->www')
for conds, rule in rules:
    ok('RewriteCond %{REQUEST_URI} !^/(releases|serverscrub)(/|$) [NC]' in conds
       and 'RewriteCond %{REQUEST_URI} !^/\\.well-known/ [NC]' in conds,
       'EVERY redirect exempts /releases, /serverscrub and /.well-known: ' + rule)
    ok('^(www\\.)?serverscrub\\.com' in conds or '^serverscrub\\.com' in conds,
       'and only fires for our own hosts, never a cPanel proxy subdomain or the IP')
    ok('[R=301,L]' in rule, 'and is a 301')
http_conds = rules[0][0]
ok('%{HTTPS} !=on' in http_conds and '%{HTTP:X-Forwarded-Proto} !=https' in http_conds,
   'HTTPS is %{HTTPS} OR X-Forwarded-Proto, so it cannot loop behind ea-nginx')
ok(HT.index('<IfModule mod_rewrite.c>') < HT.index('RewriteEngine On') < HT.index('</IfModule>'),
   'the rewrite rules degrade to "no redirect" without mod_rewrite, not a 500')
hsts = [l for l in HT.splitlines() if 'Strict-Transport-Security' in l and l.startswith('Header')]
eq(1, len(hsts), 'one HSTS header line')
ok('max-age=31536000' in hsts[0] and 'includeSubDomains' not in hsts[0] and 'preload' not in hsts[0],
   'HSTS is a year, without includeSubDomains (cPanel owns those certificates) or preload')
ok("%{HTTPS} == 'on'" in hsts[0], 'and is sent only on HTTPS responses')
ok(re.search(r'Header always set Access-Control-Allow-Origin "\*" "expr=%\{REQUEST_URI\} =~ m#\^/releases', HT),
   'CORS is opened on /releases/ only, so status.html on www can read the apex CDN')
ok(HT.index('<IfModule mod_headers.c>') < HT.index('Header always set'), 'headers are wrapped in IfModule too')

# ── 8. deploy-site.sh: manifest and ownership ─────────────────────────────────
for f in ('assets/img/logo.svg', 'assets/img/mark.svg', 'assets/img/favicon.svg', 'favicon.ico',
          'robots.txt', 'sitemap.xml'):
    ok(re.search(r'^  %s$' % re.escape(f), DEP, re.M), 'deploy-site.sh publishes ' + f)
ok(re.search(r'^  assets/img/(logo\.png|hero\.svg)$', DEP, re.M) is None,
   'and no longer lists logo.png or hero.svg')
ok('STAGE_ONLY=(htaccess.site)' in DEP, 'htaccess.site is staged but kept out of the publish loop')
ok('for f in "${PAGES[@]}" "${ASSETS[@]}"; do\n  chown "${CP_USER}:${CP_USER}" "${DOCROOT}/${f}"' in DEP,
   'THE OWNERSHIP FIX: chown walks the manifest itself, so status.html (missed by '
   'the old hand-written list) and the docroot files are owned by the account')
ok('--max-redirs 0' in DEP and 'releases/latest.json' in DEP,
   'the post-deploy check reads /releases/latest.json without following redirects')
i_broken = DEP.index('if [[ $BROKEN -ne 0 ]]; then')
ok('rollback' in DEP[i_broken:i_broken + 80], 'and a failed check restores the backup')
ok('https://www.${DOMAIN}/robots.txt' in DEP and '--max-time 15' in DEP,
   'www is probed, with certificate verification, before the apex is pointed at it')

# ── 9. The merge, executed ────────────────────────────────────────────────────
sys.path.insert(0, HERE)
from _bash import find_bash  # skips WSL's stub; see tests/_bash.py


BASH, why = find_bash()
if BASH is None:
    print('SKIP the .htaccess merge and the exempt-path probes were NOT exercised: ' + why)
else:
    CPANEL = ('# php -- BEGIN cPanel-generated handler, do not edit\n'
              '# Set the "ea-php81" package as the default "PHP" programming language.\n'
              '<IfModule mime_module>\n'
              '  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml\n'
              '</IfModule>\n'
              '# php -- END cPanel-generated handler, do not edit')   # no final newline, as cPanel writes it

    def sh(*args):
        return subprocess.run([BASH, DEPLOY] + list(args), stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)

    def files(d):
        return sorted(os.listdir(d))

    d = tempfile.mkdtemp(prefix='ss-ht-')
    try:
        site = os.path.join(SITE, 'htaccess.site')
        b1, b0 = os.path.join(d, 'block1'), os.path.join(d, 'block0')
        with open(b1, 'wb') as fh:
            fh.write(sh('render-block', '1', site).stdout)
        with open(b0, 'wb') as fh:
            fh.write(sh('render-block', '0', site).stdout)
        eq(read(site, 'rb'), read(b1, 'rb'), 'www enabled: the block is htaccess.site verbatim')
        blk0 = read(b0)
        ok('ss:www-begin' not in blk0 and 'https://www.serverscrub.com%{REQUEST_URI}' not in blk0,
           'www disabled: the apex->www rule is gone and nothing targets www')
        ok('RewriteRule ^ https://serverscrub.com%{REQUEST_URI} [R=301,L]' in blk0,
           'and plain HTTP still goes to HTTPS, on the apex')

        hd = os.path.join(d, 'docroot')
        os.makedirs(hd)
        ht = os.path.join(hd, '.htaccess')
        with open(ht, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(CPANEL)

        r1 = sh('merge-htaccess', ht, b1)
        eq(0, r1.returncode, 'merge into a cPanel-generated .htaccess succeeds')
        got = read(ht, 'rb')
        ok(got.startswith(read(b1, 'rb')), 'the block is PREPENDED, so the redirects run first')
        eq(CPANEL.encode(), got[len(read(b1, 'rb')) + 1:],
           "cPanel's section is byte-identical afterwards, missing final newline and all")
        baks = [f for f in files(hd) if f.startswith('.htaccess.ss-bak-')]
        eq(1, len(baks), 'one backup was written')
        eq(CPANEL.encode(), read(os.path.join(hd, baks[0]), 'rb'), 'and it holds the original bytes')

        r2 = sh('merge-htaccess', ht, b1)
        eq(0, r2.returncode, 'a second run succeeds')
        eq(got, read(ht, 'rb'), 'IDEMPOTENT: the second run leaves a byte-identical file')
        eq(baks, [f for f in files(hd) if f.startswith('.htaccess.ss-bak-')],
           'and writes no backup when nothing changed')

        r3 = sh('merge-htaccess', ht, b0)
        eq(0, r3.returncode, 'switching www off rewrites the block')
        now = read(ht, 'rb')
        eq(read(b0, 'rb') + b'\n' + CPANEL.encode(), now,
           'only the text between the markers changed')
        ok(not any(f.startswith('.htaccess.ss-tmp') for f in files(hd)), 'no temp file is left behind')

        # Backups are capped at five, and only our own files are touched.
        for n in range(6):
            with open(os.path.join(hd, '.htaccess.ss-bak-10%d' % n), 'w') as fh:
                fh.write('old')
        with open(os.path.join(hd, 'unrelated.bak'), 'w') as fh:
            fh.write('mine')
        sh('merge-htaccess', ht, b1)
        baks = [f for f in files(hd) if f.startswith('.htaccess.ss-bak-')]
        eq(5, len(baks), 'only the newest five backups are kept')
        ok('.htaccess.ss-bak-100' not in baks, 'the oldest are the ones removed')
        ok(os.path.exists(os.path.join(hd, 'unrelated.bak')), 'and nothing else in the docroot is touched')

        # Malformed markers: refuse, change nothing.
        for label, body in (
            ('BEGIN without END', 'a\n# BEGIN ServerScrub site\nb\n'),
            ('two BEGINs', '# BEGIN ServerScrub site\nx\n# BEGIN ServerScrub site\ny\n# END ServerScrub site\n'),
            ('END before BEGIN', '# END ServerScrub site\nx\n# BEGIN ServerScrub site\n'),
        ):
            bad = os.path.join(hd, 'bad.htaccess')
            with open(bad, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(body)
            rb = sh('merge-htaccess', bad, b1)
            ok(rb.returncode != 0, 'MALFORMED (%s): the merge refuses' % label)
            eq(body.encode(), read(bad, 'rb'), 'and the file is unchanged')
            ok(b'line(s)' in rb.stdout, 'and the message names the marker line numbers')
            for f in files(hd):
                if f.startswith('bad.htaccess.ss-'):
                    os.remove(os.path.join(hd, f))

        # A CRLF file keeps its markers recognised rather than gaining a second block.
        crlf = os.path.join(hd, 'crlf.htaccess')
        with open(crlf, 'wb') as fh:
            fh.write(b'x\r\n# BEGIN ServerScrub site\r\nold\r\n# END ServerScrub site\r\ny\r\n')
        eq(0, sh('merge-htaccess', crlf, b1).returncode, 'a CRLF .htaccess with markers merges')
        c = read(crlf, 'rb')
        ok(c.startswith(b'x\r\n') and c.endswith(b'y\r\n') and b'old' not in c and c.count(b'# BEGIN ServerScrub site') == 1,
           'replacing its block, not adding a second one, and keeping its own line endings')

        # No .htaccess at all: created with the block alone.
        fresh = os.path.join(hd, 'new.htaccess')
        eq(0, sh('merge-htaccess', fresh, b1).returncode, 'a missing .htaccess is created')
        eq(read(b1, 'rb'), read(fresh, 'rb'), 'containing the block and nothing else')
        if hasattr(os, 'geteuid'):
            eq(0o644, os.stat(fresh).st_mode & 0o777, 'with mode 644')

        # A block that lost its markers must never be merged: a later run
        # could not find it again.
        broken = os.path.join(d, 'broken')
        with open(broken, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(read(b1).replace('# END ServerScrub site\n', ''))
        before = read(ht, 'rb')
        ok(sh('merge-htaccess', ht, broken).returncode != 0, 'a block without its END marker is refused')
        eq(before, read(ht, 'rb'), 'and the live file is untouched')

        # Backup names had one-second resolution: a second changing merge in
        # the same second wrote the same .ss-bak-<epoch> and cp overwrote it,
        # so the original bytes were gone. Every name the script could pick in
        # the next few seconds is taken here; none may be overwritten.
        cd = os.path.join(d, 'collide')
        os.makedirs(cd)
        cht = os.path.join(cd, '.htaccess')
        with open(cht, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(CPANEL)
        now = int(time.time())
        taken = ['.htaccess.ss-bak-%d' % t for t in range(now, now + 4)]
        for f in taken:
            with open(os.path.join(cd, f), 'w') as fh:
                fh.write('earlier backup')
        eq(0, sh('merge-htaccess', cht, b1).returncode, 'a merge with its backup names already taken succeeds')
        survivors = [f for f in taken if os.path.exists(os.path.join(cd, f))]
        ok(all(read(os.path.join(cd, f)) == 'earlier backup' for f in survivors),
           'BACKUP COLLISION: no earlier backup was overwritten by this run')
        newb = [f for f in files(cd) if f.startswith('.htaccess.ss-bak-') and f not in taken]
        eq(1, len(newb), 'the run wrote its backup under a fresh name')
        ok(newb and read(os.path.join(cd, newb[0]), 'rb') == CPANEL.encode(),
           'and that backup holds the original .htaccess, so a rollback restores it')

        # Stepping to the first FREE name (the first collision fix) let a fast
        # merge reuse a name pruning had just freed: it sorted oldest and was
        # deleted at once, so BACKUP= named a file that was gone and rollback
        # had nothing to restore (Shakaal R1: seven merges in ~1 s, the newest
        # backup missing). Eight changing merges back to back, alternating
        # blocks; after each one its own backup must exist, hold the bytes
        # that were live before it, and be the newest of at most five.
        fd = os.path.join(d, 'fast')
        os.makedirs(fd)
        fht = os.path.join(fd, '.htaccess')
        with open(fht, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(CPANEL)
        # Five backups already ahead of the clock (what a burst of fast runs
        # leaves behind), so the outcome does not depend on how many runs fit
        # in one second on this machine.
        t0 = int(time.time()) + 100
        for k in range(5):
            with open(os.path.join(fd, '.htaccess.ss-bak-%d' % (t0 + k)), 'w') as fh:
                fh.write('earlier backup')
        lost = []
        for n in range(8):
            before = read(fht, 'rb')
            rr = sh('merge-htaccess', fht, b1 if n % 2 == 0 else b0)
            bline = [l for l in rr.stdout.decode('utf-8', 'replace').splitlines() if l.startswith('BACKUP=')]
            name = os.path.basename(bline[-1][7:]) if bline else ''
            baks = sorted((f for f in files(fd) if f.startswith('.htaccess.ss-bak-')),
                          key=lambda f: int(f.rsplit('-', 1)[1]))
            p = os.path.join(fd, name)
            if rr.returncode != 0 or not name or not os.path.exists(p) or read(p, 'rb') != before \
                    or baks[-1] != name or len(baks) > 5:
                lost.append(n)
        eq([], lost, 'FAST MERGES: every run keeps its own backup as the newest of at most five '
                     '(runs listed here lost it, so their rollback would restore nothing)')

        # ── The post-write check, against a fake host ─────────────────────────
        # R20 used to probe only https://<apex>/releases/latest.json. A block
        # whose plain-HTTP rule lost the /releases exemption was verified "OK"
        # and left live (Shakaal, 2026-11-26): http://serverscrub.com/releases/
        # latest.json answered 301 to www and the deploy exited 0. A fake curl
        # stands in for the live host so each break can be produced on demand.
        fb = os.path.join(d, 'fakebin')
        os.makedirs(fb)
        with open(os.path.join(fb, 'curl'), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write('#!/bin/sh\n'
                     'for a; do url="$a"; done\n'
                     'path="/${url#*://*/}"\n'
                     'redir() { printf \'HTTP/1.1 301 Moved Permanently\\r\\n'
                     'Location: https://www.serverscrub.com%s\\r\\n\\r\\n\' "$path"; exit 0; }\n'
                     'case "$FAKE_BREAK:$url" in\n'
                     '  http-releases:http://*/releases/*) redir ;;\n'
                     '  https-releases:https://*/releases/*) redir ;;\n'
                     '  well-known:http://*/.well-known/*) redir ;;\n'
                     '  plugin:https://serverscrub.com/serverscrub/*) redir ;;\n'
                     'esac\n'
                     'case "$path" in\n'
                     '  /releases/*) printf \'HTTP/1.1 200 OK\\r\\n\\r\\n\' ;;\n'
                     '  *) printf \'HTTP/1.1 404 Not Found\\r\\n\\r\\n\' ;;\n'
                     'esac\n')
        os.chmod(os.path.join(fb, 'curl'), 0o755)

        def verify(brk, www='1'):
            # PATH is set inside bash, not in env: Git for Windows' bin\bash.exe
            # launcher prepends mingw64/bin, which would put the REAL curl
            # first and probe the live site instead of the fake.
            env = dict(os.environ, FAKE_BREAK=brk, SG_DOMAIN='serverscrub.com', SS_FAKEBIN=fb)
            boot = ('fb="$(cygpath -u "$SS_FAKEBIN" 2>/dev/null || printf %s "$SS_FAKEBIN")"; '
                    'export PATH="$fb:$PATH"; exec bash "$0" "$@"')
            return subprocess.run([BASH, '-c', boot, DEPLOY, 'verify-exempt', www, '1'], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        probe = subprocess.run([BASH, '-c', 'fb="$(cygpath -u "$SS_FAKEBIN" 2>/dev/null || printf %s "$SS_FAKEBIN")"; '
                                'export PATH="$fb:$PATH"; command -v curl'],
                               env=dict(os.environ, SS_FAKEBIN=fb), stdout=subprocess.PIPE)
        ok(b'fakebin' in probe.stdout, 'the probes run against the fake host, never the live site')
        good = verify('none')
        eq(0, good.returncode, 'a correct block passes the exempt-path check: ' + good.stdout.decode('utf-8', 'replace')[-300:])
        for u in (b'https://serverscrub.com/releases/latest.json', b'http://serverscrub.com/releases/latest.json',
                  b'http://www.serverscrub.com/releases/latest.json', b'http://serverscrub.com/.well-known/'):
            ok(u in good.stdout, 'the check probes ' + u.decode())
        for brk, what in (('http-releases', 'a block that 301s /releases/ on plain HTTP (finding 1)'),
                          ('https-releases', 'a block that 301s /releases/ on HTTPS'),
                          ('well-known', 'a block that redirects /.well-known/ (AutoSSL validation)'),
                          ('plugin', 'a block that redirects the plugin\'s /serverscrub/ alias')):
            rv = verify(brk)
            ok(rv.returncode != 0, 'CAUGHT: %s fails verification, so the deploy rolls back' % what)
        ok(verify('http-releases', '0').returncode != 0,
           'and the plain-HTTP /releases/ redirect is caught with www disabled too')
        i_v = DEP.index('info "Verifying the rules against the live host')
        ok('verify_exempt "$WWW" "$HAVE_MANIFEST" || BROKEN=1' in DEP[i_v:i_v + 400],
           'the real deploy run uses this same check, and a failure sets BROKEN (-> rollback)')
    finally:
        shutil.rmtree(d, ignore_errors=True)

print()
print('%d passed, %d failed' % (_passed, _failed))
sys.exit(1 if _failed else 0)
