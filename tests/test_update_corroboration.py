#!/usr/bin/env python3
""""Already up to date" may only be printed on evidence a cache cannot fake.

Reported symptom (2026-11-23): the operator upgraded production minutes after
v4.37.8 was published and was told

    Already up to date - v4.37.7

That sentence was produced honestly, from evidence that was five minutes old,
and nothing in the output hinted that it might be. On a security product a
confident wrong negative about patch level is the same class of defect as the
WAF reporting action='block' while blocking nothing.

The two mitigations that were supposed to prevent it were ALREADY SHIPPED in
the copy that ran (git diff v4.37.7 HEAD -- update.sh was empty), and both
missed, for reasons measured the same day:

  1. ?cb= does not defeat raw.githubusercontent.com's edge cache. Same object,
     two consecutive requests:

       .../main/latest.json                   -> X-Cache: MISS  ETag "f7a7cab..."
       .../main/latest.json?cb=17954488137754 -> X-Cache: HIT   ETag "f7a7cab..."

     Identical ETag, cache HIT on the "cache-busted" url: the query string is
     not part of Fastly's cache key. The branch path carries max-age=300.

  2. The cross-check built to catch exactly that cannot fire on that channel:
     https://raw.githubusercontent.com/<repo>/main/latest/VERSION is a 404,
     because there is no latest/ tree in the repo. A 404 was being treated as
     "nothing to cross-check", which reads downstream as "cross-check passed".

What cannot be stale is a path that NAMES the version: the manifest committed
under the release tag (.../<repo>/v4.37.8/latest.json, measured correct on the
first request) and the per-build copy on the CDN. These tests execute the real
blocks out of update.sh and upgrade.sh against a stubbed curl, so a revert
fails them rather than a reworded comment.

And the second half: upgrade.sh was the unfixed twin. It took the FIRST channel
that answered, and when that channel (the CDN, frozen at 4.37.0 since
September) was behind the install it printed "Refusing to downgrade" and exited
1 WITHOUT EVER REACHING update.sh. The frozen mirror did not merely fail to
help, it blocked the documented upgrade path outright.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
UPDATE_SH = os.path.join(REPO, 'update.sh')
UPGRADE_SH = os.path.join(REPO, 'upgrade.sh')

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


# ── Pull the real code out of the scripts, by marker ─────────────────────────
#
# By marker and not by line number or character window, so the tests follow the
# code when it moves instead of quietly testing the wrong lines. A fixed slice
# has already broken here once when the function above it grew.

def _block(src, first_line, last_line):
    lines = src.splitlines()
    try:
        i = next(n for n, l in enumerate(lines) if l.startswith(first_line))
    except StopIteration:
        raise AssertionError('no longer contains: ' + first_line)
    try:
        j = next(n for n, l in enumerate(lines[i + 1:], i + 1) if l == last_line)
    except StopIteration:
        raise AssertionError('no closing %r after %r' % (last_line, first_line))
    return '\n'.join(lines[i:j + 1])


def _between(src, first_line, stop_line):
    """Everything from the line starting with `first_line` up to, but not
    including, the line starting with `stop_line`."""
    lines = src.splitlines()
    try:
        i = next(n for n, l in enumerate(lines) if l.startswith(first_line))
    except StopIteration:
        raise AssertionError('no longer contains: ' + first_line)
    try:
        j = next(n for n, l in enumerate(lines[i + 1:], i + 1) if l.startswith(stop_line))
    except StopIteration:
        raise AssertionError('no %r after %r' % (stop_line, first_line))
    return '\n'.join(lines[i:j])


with open(UPDATE_SH, encoding='utf-8') as fh:
    UPD = fh.read()
with open(UPGRADE_SH, encoding='utf-8') as fh:
    UPG = fh.read()

PINNED_FN   = _block(UPD, '_pinned_manifest_url() {', '}')
IMMUTABLE_FN = _block(UPD, '_immutable_channel_version() {', '}')
VER_GT      = _block(UPD, '    _ver_gt() {', '    }')
CORROBORATE = _between(UPD, '    # --- CORROBORATE:', '    [[ -z "$DOWNLOAD_URL"')
GATE        = _block(UPD, '    if [[ "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then', '    fi')
UPG_DECIDE  = _between(UPG, 'CACHE_BUST="$(date', 'echo -e "  ${BOLD}v${CURRENT}')

BASH = shutil.which('bash') or shutil.which('bash.exe')
if BASH is None:
    print('SKIP bash not available; cannot execute the updater blocks')
    sys.exit(0)

CDN  = 'https://cdn.example/releases'
GH   = 'https://raw.githubusercontent.com/example/repo/main'
REPO_SLUG = 'example/repo'
API  = 'https://api.github.com/repos/example/repo/tags'
# The tag path. NOT GH + '/v<ver>/...': on raw the version is a git ref and
# replaces the branch component, so appending it to .../repo/main/ is a 404 --
# which is what the shipped per-version fetch did on this channel.
GHTAG = 'https://raw.githubusercontent.com/example/repo/v%s/latest.json'


def manifest(ver, sha='a' * 64, base=CDN):
    return ('{"version":"%s","url":"%s/dist/serverscrub-%s.zip",'
            '"sha256":"%s","notes":"https://notes/%s"}' % (ver, base, ver, sha, ver))


def tags(*vers):
    return '[' + ','.join('{"name":"v%s","commit":{"sha":"%s"}}' % (v, 'f' * 40)
                          for v in vers) + ']'


def fixkey(url):
    bare = url.split('?')[0]
    bare = re.sub(r'^https?://', '', bare)
    return 'fix_' + re.sub(r'[^A-Za-z0-9]', '_', bare)


# The stub curl serves fixtures keyed on the url with its query string
# stripped, and logs every url it is asked for. A missing fixture is exit 22,
# which is what a 404 does -- and .../main/latest/VERSION really is a 404.
HARNESS_HEAD = r'''
set -euo pipefail
BOLD=''; NC=''; GREEN=''; YELLOW=''; RED=''; CYAN=''; BLUE=''
info() { echo "INFO $*"; }
warn() { echo "WARN $*"; }
ok()   { echo "OK   $*"; }
err()  { echo "ERR  $*"; }
section() { echo "SEC  $*"; }
die()  { echo "DIE  $*"; exit 1; }
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
CACHE_BUST="TESTBUST"
NOCACHE_HDRS=(-H 'Cache-Control: no-cache, no-store, max-age=0' -H 'Pragma: no-cache')
_nocache() {
    local u="$1" sep='?'
    case "$u" in *\?*) sep='&' ;; esac
    printf '%s%scb=%s' "$u" "$sep" "$CACHE_BUST"
}
URLLOG="${SG_FIXDIR}/urls.log"
: > "$URLLOG"
curl() {
    local url=""
    for a in "$@"; do case "$a" in http*) url="$a" ;; esac; done
    printf '%s\n' "$url" >> "$URLLOG"
    local bare="${url%%\?*}"
    local key
    key="$(printf '%s' "$bare" | sed -e 's#^https\?://##' -e 's#[^A-Za-z0-9]#_#g')"
    if [ -f "${SG_FIXDIR}/fix_${key}" ]; then
        cat "${SG_FIXDIR}/fix_${key}"
        return 0
    fi
    return 22
}
sleep() { :; }
RELEASES_REPO="example/repo"
GITHUB_BASE="https://raw.githubusercontent.com/example/repo/main"
'''


def run(script, fixtures, env=None):
    d = tempfile.mkdtemp(prefix='sg-corrob-')
    for url, content in fixtures.items():
        with open(os.path.join(d, fixkey(url)), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(content)
    path = os.path.join(d, 'harness.sh')
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(script)
    e = dict(os.environ)
    e['SG_FIXDIR'] = d.replace('\\', '/')
    if env:
        e.update(env)
    r = subprocess.run([BASH, path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True, env=e, cwd=d)
    out = {}
    for line in r.stdout.splitlines():
        if line.startswith('RESULT '):
            k, _, v = line[7:].partition('=')
            out[k] = v
    urls = []
    log = os.path.join(d, 'urls.log')
    if os.path.exists(log):
        with open(log, encoding='utf-8') as fh:
            urls = [l.strip() for l in fh if l.strip()]
    return out, urls, r


# ═════════════════════════════════════════════════════════════════════════════
# 1. update.sh: resolving the version against an immutable ref
# ═════════════════════════════════════════════════════════════════════════════

CORROB_TAIL = r'''
echo "RESULT latest_version=${LATEST_VERSION}"
echo "RESULT download_url=${DOWNLOAD_URL}"
echo "RESULT sha=${EXPECTED_SHA256}"
echo "RESULT immutable=${VER_IMMUTABLE}"
echo "RESULT source=${VER_SOURCE}"
echo "RESULT active_base=${ACTIVE_BASE}"
'''


def corroborate(fixtures, channels, latest, best_live='', best_live_base='',
                active=None, sha='a' * 64):
    script = (HARNESS_HEAD
              + PINNED_FN + '\n' + IMMUTABLE_FN + '\n'
              + VER_GT.replace('    _ver_gt', '_ver_gt') + '\n'
              + 'CHANNELS=(' + ' '.join('"%s"' % c for c in channels) + ')\n'
              + 'LATEST_VERSION="%s"\n' % latest
              + 'DOWNLOAD_URL=""\nMIRROR_URL=""\nRELEASE_URL=""\n'
              + 'EXPECTED_SHA256="%s"\n' % sha
              + 'BEST_LIVE="%s"\nBEST_LIVE_BASE="%s"\n' % (best_live, best_live_base)
              + 'ACTIVE_BASE="%s"\n' % (active if active else channels[0])
              + 'DIST_BASE="%s/dist"\n' % (active if active else channels[0])
              + 'VER_IMMUTABLE=false\nVER_SOURCE=""\n'
              + CORROBORATE + '\n'
              + CORROB_TAIL)
    return run(script, fixtures)


# ── THE REPORTED INCIDENT ────────────────────────────────────────────────────
#
# The branch path serves 4.37.7 out of Fastly's cache while the newest tag is
# v4.37.8. Installed version is 4.37.7. Before this change the updater had
# nothing left to ask and printed "Already up to date - v4.37.7".
res, urls, r = corroborate({
    GH + '/latest.json': manifest('4.37.7', base=GH),
    API:                 tags('4.37.8', '4.37.7', '4.37.6'),
    GHTAG % '4.37.8':    manifest('4.37.8', sha='d' * 64, base=GH),
}, [CDN, GH], latest='4.37.7')

eq('4.37.8', res.get('latest_version'),
   'THE REPORTED INCIDENT: a branch manifest cached at 4.37.7 beside a '
   'v4.37.8 tag resolves to 4.37.8 - the operator is offered the release that '
   'exists, not told they are current')
eq(GH + '/dist/serverscrub-4.37.8.zip', res.get('download_url'),
   'and the download url comes from the manifest committed under that tag, '
   'so it points at the build that exists')
eq('d' * 64, res.get('sha'),
   'with THAT build\'s checksum - the cached 4.37.7 manifest carried the '
   '4.37.7 hash, which would have failed verification mid-update')
eq('true', res.get('immutable'),
   'and the answer is marked corroborated, which is what permits a factual '
   'claim about patch level downstream')
ok(any(u.startswith('https://raw.githubusercontent.com/example/repo/v4.37.8/')
       for u in urls),
   'THE TAG PATH, NOT THE BRANCH PATH: the per-version manifest is fetched at '
   '.../repo/v4.37.8/latest.json. The shipped code appended v<ver> to the '
   'BRANCH base, giving .../repo/main/v4.37.8/latest.json, which is a 404 on '
   'this channel and always was')
ok(not any('/main/v4.37.8/' in u for u in urls),
   'and nothing asks for v<ver> underneath main/, which cannot exist')
ok(any(u.startswith(API) for u in urls),
   'the newest ref is discovered through the tags api: with latest/VERSION a '
   '404 and the manifest cacheable, it is the only immutable reading of '
   '"what is the newest version" this channel has')
eq(1, len([u for u in urls if u.startswith(API)]),
   'and exactly once per check - unauthenticated the limit is 60/hour/IP')

# ── NO IMMUTABLE SOURCE: the answer still stands, and is labelled ────────────
#
# Rate-limited, firewalled, or an api returning nonsense. The updater has to
# keep working; what it must not do is present the branch answer as confirmed.
res, urls, r = corroborate({
    GH + '/latest.json': manifest('4.37.7', base=GH),
}, [CDN, GH], latest='4.37.7')
eq('4.37.7', res.get('latest_version'),
   'NO IMMUTABLE SOURCE: the branch answer still stands - a firewalled server '
   'that can only reach a cacheable url still has to be able to update')
eq('false', res.get('immutable'),
   'but it is NOT corroborated, so nothing downstream may claim the install '
   'is current on the strength of it')
eq(0, r.returncode, 'and an unreachable tags api is not an error')

# ── THE TAUTOLOGY: a pinned manifest may not corroborate ITSELF ──────────────
#
# Shakaal's blocker, 2026-11-23. The first version of this fix substituted the
# branch answer when no immutable ref could be read, and then "confirmed" it by
# fetching v<that same version>/latest.json:
#
#     [[ -z "$IMM_VER" ]] && IMM_VER="$LATEST_VERSION"
#
# v<X>/latest.json proves that version X exists. It never proves X is the
# newest. Every released version has a tag, and cdn-sync.sh retains
# KEEP_VERSIONS old v<ver>/ folders, so the check could not fail -- and the
# output got STRONGER than the one it replaced:
#
#     ok   Already up to date - v4.37.7
#     ->     Confirmed against .../v4.37.7/latest.json (no cache can stale it)
#
# printed with the tags api rate-limited, a branch manifest cached at 4.37.7
# and a real v4.37.8 tag sitting there. An explicit assurance of freshness on a
# stale read, in the exact case requirement 4 exists to hedge.
#
# These fixtures are the real shape of the GitHub channel: the installed
# version's own tag manifest IS present, because it always is.
res, urls, r = corroborate({
    GH + '/latest.json': manifest('4.37.7', base=GH),
    GHTAG % '4.37.7':    manifest('4.37.7', base=GH),
    GHTAG % '4.37.8':    manifest('4.37.8', sha='d' * 64, base=GH),
}, [CDN, GH], latest='4.37.7')
eq('false', res.get('immutable'),
   'THE TAUTOLOGY: with the tags api unreachable, the branch answer is NOT '
   'corroborated even though v4.37.7/latest.json answers. That url proves '
   '4.37.7 exists; it cannot prove 4.37.7 is current, and there is a v4.37.8 '
   'tag right beside it')
eq('', res.get('source'), 'and no source is claimed for it')
ok(not any(('/v4.37.7/' in u) for u in urls),
   'the pinned manifest for the version in hand is not even fetched: a '
   'version no immutable source named is not a candidate, so asking about it '
   'is a request that can only produce a false confirmation')

# Same shape on a channel that has no ref listing at all. cdn-sync.sh keeps old
# v<ver>/ folders, so the CDN frozen at 4.37.0 still serves v4.37.0/latest.json
# -- which is why "the pinned manifest answered" can never be the whole test.
res, urls, r = corroborate({
    CDN + '/latest.json':         manifest('4.37.0'),
    CDN + '/v4.37.0/latest.json': manifest('4.37.0'),
}, [CDN], latest='4.37.0')
eq('false', res.get('immutable'),
   'A FILE CHANNEL WITH NO latest/VERSION: its retained per-build manifest '
   'does not corroborate the answer either. The frozen CDN serves exactly '
   'this, and it has been nine releases behind for a month')


# ── A TAG WITH NO MANIFEST UNDER IT ──────────────────────────────────────────
res, urls, r = corroborate({
    GH + '/latest.json': manifest('4.37.7', base=GH),
    API:                 tags('4.37.8'),
}, [CDN, GH], latest='4.37.7')
eq('4.37.7', res.get('latest_version'),
   'TAG WITHOUT A MANIFEST: a tag made over a tree that does not contain '
   'latest.json yields nothing to download, so the version is not moved to it')
eq('false', res.get('immutable'),
   'and the answer stays labelled uncorroborated rather than claiming a ref '
   'it could not read')
eq(0, r.returncode, 'and it does not abort the update')

# ── GENUINELY CURRENT ────────────────────────────────────────────────────────
res, urls, r = corroborate({
    GH + '/latest.json': manifest('4.37.9', base=GH),
    API:                 tags('4.37.9', '4.37.8'),
    GHTAG % '4.37.9':    manifest('4.37.9', sha='e' * 64, base=GH),
}, [CDN, GH], latest='4.37.9')
eq('4.37.9', res.get('latest_version'), 'GENUINELY CURRENT: the version does not move')
eq('true', res.get('immutable'),
   'and it is corroborated against the tag, so "Already up to date" is '
   'allowed to be printed')
eq(GHTAG % '4.37.9', res.get('source'),
   'naming the url that confirmed it, so the claim can be rechecked by hand')

# ── latest/VERSION 404 IS NOT A PASSED CROSS-CHECK ───────────────────────────
res, urls, r = corroborate({
    CDN + '/latest.json': manifest('4.37.5'),
}, [CDN], latest='4.37.5')
eq(0, r.returncode,
   'latest/VERSION 404: a channel serving only dist/ completes the check with '
   'no error and no abort')
eq('false', res.get('immutable'),
   'and the MISSING cross-check is not counted as a passed one - treating a '
   '404 as "nothing to disagree with" is how the safety net became a no-op')

# ── The deployed tree corroborates when it agrees ────────────────────────────
res, urls, r = corroborate({
    CDN + '/latest.json': manifest('4.37.9'),
}, [CDN], latest='4.37.9', best_live='4.37.9', best_live_base=CDN)
eq('true', res.get('immutable'),
   'THE TREE COUNTS: latest/VERSION is read out of the extracted build and a '
   '?cb= request was measured to miss cPanel\'s nginx cache, so when it '
   'agrees with the manifest the answer is confirmed')
eq(CDN + '/latest/VERSION', res.get('source'), 'and that is the source named')

# ── A lagging channel is never corroborated backwards ────────────────────────
res, urls, r = corroborate({
    CDN + '/latest.json':         manifest('4.37.0'),
    CDN + '/latest/VERSION':      '4.37.0\n',
    CDN + '/v4.37.0/latest.json': manifest('4.37.0'),
    GH + '/latest.json':          manifest('4.37.9', base=GH),
    API:                          tags('4.37.9'),
    GHTAG % '4.37.9':             manifest('4.37.9', sha='e' * 64, base=GH),
}, [CDN, GH], latest='4.37.9', active=GH)
eq('4.37.9', res.get('latest_version'),
   'LAGGING MIRROR: the frozen CDN at 4.37.0 cannot pull the answer back down')
ok(not any('/v4.37.0/' in u for u in urls),
   'and its per-build manifest is not even fetched - a ref older than the '
   'answer in hand is nothing to download from')

# ── Tag order is not trusted ─────────────────────────────────────────────────
res, urls, r = corroborate({
    GH + '/latest.json': manifest('4.9.0', base=GH),
    API:                 tags('4.9.0', '4.36.0', '4.10.0'),
    GHTAG % '4.36.0':    manifest('4.36.0', sha='c' * 64, base=GH),
}, [CDN, GH], latest='4.9.0')
eq('4.36.0', res.get('latest_version'),
   'TAG ORDER IS NOT TRUSTED: the highest tag by VERSION wins, whatever the '
   'api listed first - v4.9.0 sorts above v4.36.0 one character at a time, '
   'which is the bug that made 38 releases verify the wrong tag')

# ── Every version-bearing fetch is still cache-busted ────────────────────────
res, urls, r = corroborate({
    GH + '/latest.json': manifest('4.37.7', base=GH),
    API:                 tags('4.37.8'),
    GHTAG % '4.37.8':    manifest('4.37.8', base=GH),
}, [CDN, GH], latest='4.37.7')
ok(urls and all('cb=' in u for u in urls),
   'CACHE KEY: every fetch still carries a single-use cache-buster (%d urls). '
   'It is not sufficient on raw, but it is necessary in front of cPanel\'s '
   'nginx cache, where it was measured to be the only thing that worked'
   % len(urls))


# ═════════════════════════════════════════════════════════════════════════════
# 2. update.sh: the "Already up to date" gate
# ═════════════════════════════════════════════════════════════════════════════

def gate(immutable, current='4.37.7', latest='4.37.7', source='https://pinned/x',
         why='addressed by version, so no cache can hold a wrong answer for it',
         verbose=False):
    script = (HARNESS_HEAD
              + 'CURRENT_VERSION="%s"\nLATEST_VERSION="%s"\n' % (current, latest)
              + 'VER_IMMUTABLE=%s\nVER_SOURCE="%s"\nACTIVE_BASE="%s"\n'
                % (immutable, source, GH)
              + 'VER_SOURCE_WHY="%s"\nVERBOSE=%s\n' % (why, 'true' if verbose else 'false')
              + GATE + '\n'
              + 'echo "RESULT reached_end=1"\n')
    return run(script, {})


# The reason comes from the source. latest/VERSION is NOT addressed by
# version -- it is a mutable path on the mirror whose purge is best-effort --
# and this line claimed it was, for every source.
res, _, r = gate('true', source='https://cdn.example/releases/latest/VERSION',
                 why='read out of the deployed build, so it cannot name a '
                     'version the tree does not hold')
ok('read out of the deployed build' in r.stdout,
   'THE STATED REASON MATCHES THE SOURCE: confirming against latest/VERSION '
   'is justified by it being read out of the build, not by being "addressed '
   'by version" -- which that path is not')
ok('addressed by version' not in r.stdout,
   'so the wrong justification is not printed for it. Claiming the right '
   'version for a reason that does not hold is the same class of defect as '
   'the rest of this work')

res, _, r = gate('true')
ok('Already up to date' in r.stdout,
   'CORROBORATED: "Already up to date" is printed when the version was '
   'confirmed against a url that names it')
ok('https://pinned/x' in r.stdout,
   'and the output names the url that confirmed it')
eq(0, r.returncode, 'exit 0')

res, _, r = gate('false')
ok('Already up to date' not in r.stdout,
   'UNCORROBORATED: "Already up to date" is NOT printed. This is the sentence '
   'the operator was given minutes after v4.37.8 was published, from a '
   'manifest a cache had held for five minutes')
ok('not a confirmation that this install is current' in r.stdout,
   'the output says in plain words that this is not a confirmation that the '
   'install is current, and says it BEFORE the explanation: this prints on '
   'every daily cron run, and the operative sentence used to be the sixth '
   'line of six')
ok('5 minutes' in r.stdout,
   'and how stale the evidence can be, in minutes, rather than leaving the '
   'operator to guess')
ok(GH in r.stdout, 'naming the channel the answer came from')
ok(len([l for l in r.stdout.splitlines() if l.startswith('WARN')]) <= 4,
   'in at most four lines. It was six warn lines plus two curl commands on '
   'every cron run of a server where nothing was wrong, which is how an '
   'operator learns to skip the block that will one day matter')
ok('X-Cache' not in r.stdout,
   'and the cache measurement is NOT in the default output')
eq(0, r.returncode,
   'and it still exits 0: cron and the one-click updater both call this, and '
   'a nonzero exit would read as a failed update rather than an unconfirmed '
   'check. There is nothing to install either way')


# THE REPRODUCTION FROM THE FINDING, end to end: resolve then gate, with the
# tags api dead and the installed version's own tag manifest present.
script = (HARNESS_HEAD
          + PINNED_FN + '\n' + IMMUTABLE_FN + '\n'
          + VER_GT.replace('    _ver_gt', '_ver_gt') + '\n'
          + 'CHANNELS=("%s" "%s")\n' % (CDN, GH)
          + 'LATEST_VERSION="4.37.7"\nCURRENT_VERSION="4.37.7"\n'
          + 'DOWNLOAD_URL=""\nMIRROR_URL=""\nRELEASE_URL=""\nEXPECTED_SHA256=""\n'
          + 'BEST_LIVE=""\nBEST_LIVE_BASE=""\n'
          + 'ACTIVE_BASE="%s"\nDIST_BASE="%s/dist"\n' % (GH, GH)
          + 'VER_IMMUTABLE=false\nVER_SOURCE=""\n'
          + CORROBORATE + '\n' + GATE + '\n'
          + 'echo "RESULT reached_end=1"\n')
_, _, r = run(script, {
    GH + '/latest.json': manifest('4.37.7', base=GH),
    GHTAG % '4.37.7':    manifest('4.37.7', base=GH),
    GHTAG % '4.37.8':    manifest('4.37.8', sha='d' * 64, base=GH),
})
ok('Already up to date' not in r.stdout,
   'THE FINDING, END TO END: with the tags api dead, a branch manifest cached '
   'at 4.37.7 and a v4.37.8 tag present, the updater does NOT print "Already '
   'up to date". On the first version of this fix it printed it WITH a '
   '"no cache can stale it" assurance attached')
ok('no cache can stale it' not in r.stdout,
   'and claims no freshness it cannot demonstrate')
ok('not a confirmation that this install is current' in r.stdout,
   'it prints the hedge instead')
eq(0, r.returncode, 'still exit 0')


# ═════════════════════════════════════════════════════════════════════════════
# 3. upgrade.sh: a lagging mirror must not block the documented upgrade path
# ═════════════════════════════════════════════════════════════════════════════

UPG_TAIL = r'''
echo "RESULT latest=${LATEST}"
echo "RESULT channel=${CHANNEL_USED}"
echo "RESULT corroborated=${CORROBORATED}"
echo "RESULT pinned_prefix=${PINNED_PREFIX}"
echo "RESULT reached_end=1"
'''


def upgrade(fixtures, channels, current):
    script = (HARNESS_HEAD
              + 'INSTALL_DIR="/usr/local/serverscrub"\n'
              + 'CURRENT="%s"\n' % current
              + 'CHANNELS=(' + ' '.join('"%s"' % c for c in channels) + ')\n'
              + UPG_DECIDE + '\n' + UPG_TAIL)
    return run(script, fixtures)


FROZEN_CDN_AND_LIVE_GITHUB = {
    CDN + '/latest.json':         manifest('4.37.0'),
    CDN + '/latest/VERSION':      '4.37.0\n',
    CDN + '/v4.37.0/latest.json': manifest('4.37.0'),
    GH + '/latest.json':          manifest('4.37.9', base=GH),
    API:                          tags('4.37.9', '4.37.8'),
    GHTAG % '4.37.9':             manifest('4.37.9', sha='e' * 64, base=GH),
}

for order, label in (([CDN, GH], 'stale channel first'),
                     ([GH, CDN], 'stale channel last')):
    res, urls, r = upgrade(FROZEN_CDN_AND_LIVE_GITHUB, order, '4.37.7')
    eq('4.37.9', res.get('latest'),
       'THE BLOCKED UPGRADE (%s): with the CDN frozen at 4.37.0, GitHub at '
       '4.37.9 and 4.37.7 installed, upgrade.sh offers 4.37.9. On 4.37.9\'s '
       'own code this combination printed "Refusing to downgrade" and exited '
       '1 without ever reaching update.sh' % label)
    ok('Refusing' not in r.stdout,
       'and it does not refuse (%s) - a mirror behind the install is a '
       'stalled sync, not an instruction to roll back' % label)
    eq('1', res.get('reached_end'),
       'it reaches the hand-over to the updater (%s) rather than exiting '
       'first' % label)
    eq(0, r.returncode, 'with no failure status (%s)' % label)
    ok('cdn.example' in r.stdout and '4.37.0' in r.stdout,
       'the output names the lagging channel and the version it gave (%s), '
       'which is the only place nine unmirrored releases would have shown up'
       % label)
    ok('4.37.9' in r.stdout and 'raw.githubusercontent.com' in r.stdout,
       'and names the channel that was used (%s)' % label)
    eq('true', res.get('corroborated'),
       'and the answer is corroborated against the tag (%s)' % label)
    eq('https://raw.githubusercontent.com/example/repo/v4.37.9',
       res.get('pinned_prefix'),
       'recording the version-pinned prefix (%s), so the updater itself is '
       'fetched from the tree that ships WITH 4.37.9 rather than from a '
       'mirror frozen at 4.37.0' % label)

# ── Already current, corroborated ────────────────────────────────────────────
res, _, r = upgrade(FROZEN_CDN_AND_LIVE_GITHUB, [GH, CDN], '4.37.9')
ok('Already on v4.37.9' in r.stdout,
   'GENUINELY CURRENT: corroborated against the tag, so upgrade.sh says so '
   'once and stops')
ok(res.get('reached_end') is None, 'and exits before fetching anything')
eq(0, r.returncode, 'exit 0')

# ── Already current, NOT corroborated ────────────────────────────────────────
res, _, r = upgrade({CDN + '/latest.json': manifest('4.37.9')}, [CDN], '4.37.9')
ok('nothing to do' not in r.stdout,
   'UNCORROBORATED AND APPARENTLY CURRENT: it does not claim there is nothing '
   'to do on the strength of a cacheable url')
eq('1', res.get('reached_end'),
   'it hands over to the updater instead, which resolves the version again '
   'and installs nothing if there is nothing newer')
eq(0, r.returncode, 'exit 0')

# ── Only a behind-and-corroborated channel: a real rollback request ──────────
res, _, r = upgrade({
    CDN + '/latest.json':         manifest('4.37.0'),
    CDN + '/latest/VERSION':      '4.37.0\n',
    CDN + '/v4.37.0/latest.json': manifest('4.37.0'),
}, [CDN], '4.37.7')
ok('Refusing' in r.stdout,
   'A GENUINE DOWNGRADE: when the only corroborated answer anywhere is older '
   'than the install, that IS a rollback and it is refused')
eq(1, r.returncode, 'with a non-zero status')
ok('--allow-downgrade' in r.stdout,
   'and the output gives the command that does it deliberately')

# ── Behind, and not corroborated: the updater decides, not this script ───────
res, _, r = upgrade({CDN + '/latest.json': manifest('4.37.0')}, [CDN], '4.37.7')
ok('Refusing' not in r.stdout,
   'UNCORROBORATED AND BEHIND: this script does not refuse on an answer it '
   'could not confirm')
eq('1', res.get('reached_end'),
   'it hands over to update.sh, which has the downgrade guard and the '
   'rollback')
eq(0, r.returncode, 'and does not fail the run')

# ── upgrade.sh carries the same tautology, and must not either ──────────────
res, urls, r = upgrade({
    GH + '/latest.json': manifest('4.37.7', base=GH),
    GHTAG % '4.37.7':    manifest('4.37.7', base=GH),
    GHTAG % '4.37.8':    manifest('4.37.8', sha='d' * 64, base=GH),
}, [GH], '4.37.7')
eq('false', res.get('corroborated'),
   'THE TAUTOLOGY IN upgrade.sh: a pinned manifest for the version the branch '
   'already named does not corroborate it')
ok('Already on v4.37.7' not in r.stdout,
   'so it does not report "nothing to do" with a v4.37.8 tag sitting beside '
   'the answer it was given')
eq('1', res.get('reached_end'), 'it hands over to the updater instead')
eq(0, r.returncode, 'exit 0')

# ── An unreadable installed VERSION is not the mirrors' fault ───────────────
#
# Shakaal, 2026-11-23: `sort -V` puts the literal string `unknown` above every
# real version, so a missing ${SG_ROOT}/VERSION -- the broken install this
# script exists to repair -- took the "every channel is behind this install"
# branch and told the operator the release mirrors had stalled, four lines
# after reporting the newest version as corroborated.
res, _, r = upgrade(FROZEN_CDN_AND_LIVE_GITHUB, [CDN, GH], 'unknown')
ok('No channel offers anything newer' not in r.stdout,
   'UNREADABLE VERSION: it does not claim every channel is behind the install')
ok('stalled sync, not a release' not in r.stdout,
   'and does not blame the release mirrors for a fault on the server in front '
   'of the operator')
ok('Cannot read' in r.stdout,
   'it says what it actually could not do: read the installed version')
eq('1', res.get('reached_end'), 'and hands over to the updater')
eq(0, r.returncode, 'exit 0')
ok('4.37.0' in r.stdout,
   'the per-channel report still names the lagging mirror, which is a '
   'different statement from blaming it')


# ── No channel answers at all ────────────────────────────────────────────────
res, _, r = upgrade({}, [CDN, GH], '4.37.7')
eq(1, r.returncode,
   'NO CHANNEL AT ALL: unchanged behaviour - this is a real failure and it is '
   'reported as one')
ok('No release channel answered' in r.stdout, 'saying so')


print('')
print('%d passed, %d failed' % (_passed, _failed))
sys.exit(1 if _failed else 0)
