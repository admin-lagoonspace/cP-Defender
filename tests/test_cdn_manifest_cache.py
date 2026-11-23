#!/usr/bin/env python3
"""The CDN sync must not publish a manifest the public url will not serve.

Reported symptom (2026-11-13): cdn-sync.sh published v4.36.0, wrote
${DOCROOT}/latest.json correctly, logged "published v4.36.0" -- and
https://serverscrub.com/releases/latest.json went on serving 4.35.1 with a
Last-Modified of the 4.35.1 publish, six days earlier. A request with a cache
key the proxy had not seen (?cb=<timestamp>) returned 4.36.0 from the same host
in the same second.

This is the systemic half of the bug, and it was never specific to 4.36.0.
Replacing the file on disk says nothing about what the cPanel nginx
reverse-proxy cache in front of it serves, and the sync never purged it or
marked it uncacheable. EVERY release has therefore had a window in which the
canonical manifest advertised the previous version, with nothing in any log to
say so -- the likely source of the long-standing impression that installs
"silently fell back to the GitHub mirror". They were not falling back; they
were being told the old version was current.

The htaccess writer is executed for real here, against a temporary docroot,
because the thing that matters about it is that it does not destroy an
.htaccess it does not own. The script itself cannot be run end to end: it
publishes to a live docroot and fetches from the network.

Run by tests/run.php alongside the PHP suite.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SYNC = os.path.join(REPO, 'scripts', 'cdn-sync.sh')

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


with open(SYNC, encoding='utf-8') as fh:
    SRC = fh.read()


def block(first_line, last_line):
    lines = SRC.splitlines()
    try:
        i = next(n for n, l in enumerate(lines) if l.startswith(first_line))
    except StopIteration:
        raise AssertionError('cdn-sync.sh no longer contains: ' + first_line)
    j = next(n for n, l in enumerate(lines[i + 1:], i + 1) if l == last_line)
    return '\n'.join(lines[i:j + 1])


HTACCESS_FN = block('_write_docroot_htaccess() {', '}')

# ── 1. Ordering: the headers are in place before the manifest moves ──────────
#
# A manifest published before the directory says "do not cache me" can be
# picked up by the cache in the gap.
i_ht   = SRC.index('_write_docroot_htaccess || true')
i_pub  = SRC.index('place "${TMP}/latest.json"   "${DOCROOT}/latest.json"')
i_purge = SRC.index('_purge_manifest_cache || true')
# The anchor, not the assertion, moved: the read-back used to be called as
# `_verify_public_manifest || true`, and discarding its status is what let
# nine releases be logged as published while the public url served 4.37.0.
# The ORDERING property asserted below is unchanged.
i_verify = SRC.index('if _verify_public_manifest; then')
ok(i_ht < i_pub,
   'ORDER: the cache-control block is written BEFORE the manifest is placed, '
   'so there is no window in which a cacheable manifest is live')
ok(i_pub < i_purge,
   'the purge runs AFTER the manifest is in place — purging first just '
   'reloads the old object')
ok(i_purge < i_verify,
   'and the public read-back runs last, after everything that could fix it')

# ── 2. Scope: the manifest is uncacheable, the zips stay cached ──────────────
ok('no-store' in HTACCESS_FN and 'must-revalidate' in HTACCESS_FN,
   'the manifest is marked no-store/must-revalidate, not merely revalidated')
ok(re.search(r'FilesMatch "\^\(latest\\\.json\|VERSION\|get\\\.sh\)\$"', HTACCESS_FN) is not None,
   'and the rule covers latest.json, VERSION and get.sh — every file whose '
   'content decides what version a server believes is current')
ok('max-age=31536000' in HTACCESS_FN and 'immutable' in HTACCESS_FN,
   'while the zips stay cached hard: the version is in the filename, so a '
   'cached serverscrub-4.36.0.zip is by definition the right bytes, and the '
   'zips are the only part of this that is big')

# ── 3. It must not destroy an .htaccess it does not own ──────────────────────
#
# This docroot is shared with the website. A wholesale overwrite here would
# trade a stale manifest for a broken site.
BASH = shutil.which('bash') or shutil.which('bash.exe')
if BASH is None:
    print('SKIP bash not available; cannot execute the htaccess writer')
else:
    def write_htaccess(existing=None, runs=1):
        d = tempfile.mkdtemp(prefix='sg-cdn-')
        docroot = os.path.join(d, 'releases')
        os.makedirs(docroot)
        ht = os.path.join(docroot, '.htaccess')
        if existing is not None:
            with open(ht, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(existing)
        script = ('set -uo pipefail\n'
                  'log() { echo "LOG $*"; }\n'
                  'DOCROOT="%s"\n' % docroot.replace('\\', '/')
                  + HTACCESS_FN + '\n'
                  + ('_write_docroot_htaccess || echo "RC nonzero"\n' * runs))
        path = os.path.join(d, 'h.sh')
        with open(path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(script)
        r = subprocess.run([BASH, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, cwd=d)
        content = ''
        if os.path.exists(ht):
            with open(ht, encoding='utf-8') as fh:
                content = fh.read()
        return content, r

    content, r = write_htaccess()
    ok('no-store' in content and 'BEGIN ServerScrub cdn-sync' in content,
       'a fresh docroot gets the cache-control block, inside a named managed '
       'block so a human can see what wrote it')
    ok('${ht}.tmp' in HTACCESS_FN and 'mv -f "${ht}.tmp" "$ht"' in HTACCESS_FN,
       'written via a temp file and moved into place, as every other publish '
       'in this script is — a half-written .htaccess is a 500 on the whole '
       'docroot')

    FOREIGN = ('# the website\'s own rules\n'
               'RewriteEngine On\n'
               'RewriteRule ^old/(.*)$ /new/$1 [R=301,L]\n'
               'ErrorDocument 404 /404.html\n')
    content, r = write_htaccess(existing=FOREIGN)
    ok('RewriteRule ^old/(.*)$ /new/$1 [R=301,L]' in content
       and 'ErrorDocument 404 /404.html' in content,
       'AN .HTACCESS IT DOES NOT OWN IS PRESERVED: existing rules survive — '
       'this docroot is shared with the website, and trading a stale manifest '
       'for a broken site is not a fix')
    ok('no-store' in content,
       'and the cache-control block is appended alongside them')

    # Idempotence: ten syncs an hour, for ever. The file must not grow.
    once, _ = write_htaccess(existing=FOREIGN, runs=1)
    thrice, _ = write_htaccess(existing=FOREIGN, runs=3)
    eq(once.count('BEGIN ServerScrub cdn-sync'), 1,
       'the managed block appears exactly once after one run')
    eq(1, thrice.count('BEGIN ServerScrub cdn-sync'),
       'IDEMPOTENT: still exactly once after three runs — this runs every ten '
       'minutes from cron, and an appending writer would grow the file for ever')
    ok('RewriteRule ^old/(.*)$ /new/$1 [R=301,L]' in thrice,
       'and the foreign rules are still there after the rewrite pass')
    eq(1, thrice.count('END ServerScrub cdn-sync'),
       'with one closing marker, so the next run can still find its own block')

    # A BEGIN with no END is a truncated or hand-edited file. Rewriting it
    # would treat everything after BEGIN as ours and delete it.
    truncated = (FOREIGN
                 + '# BEGIN ServerScrub cdn-sync (managed block — edits here are lost)\n'
                 + '<FilesMatch "^(latest\\.json)$">\n')
    content, r = write_htaccess(existing=truncated)
    ok('RewriteRule ^old/(.*)$ /new/$1 [R=301,L]' in content
       and 'ErrorDocument 404 /404.html' in content,
       'TRUNCATED MARKERS: a BEGIN with no END is refused rather than '
       'rewritten, so the website\'s rules after it are not swallowed')
    ok('no END marker' in r.stdout,
       'and the refusal says why, naming the file to fix by hand')

# ── 4. The read-back must use the PUBLIC url, not the file on disk ───────────
#
# The entire failure was that those two disagree. A publish that verifies its
# own disk write proves nothing.
verify = block('_verify_public_manifest() {', '}')
ok('${PUBLIC_BASE}/latest.json"' in verify,
   'READ-BACK: the check fetches the public url')
ok(re.search(r'plain="\$\(curl[^\n]*\$\{PUBLIC_BASE\}/latest\.json"', verify) is not None,
   'with NO cache-buster on the first fetch — that is the url every installed '
   'server actually requests, and the point is to find out what it serves')
ok('?cb=' in verify,
   'and a second, cache-busted fetch to tell a caching problem apart from a '
   'publishing problem')
ok('clear_nginx_cache' in verify,
   'and the log says what to run as root when it is the cache')
ok('WARNING' in verify,
   'a disagreement is logged as a WARNING, so the sync no longer reports '
   'success while the canonical url serves the previous release')

purge = block('_purge_manifest_cache() {', '}')
ok('clear_nginx_cache' in purge, 'the purge tries cPanel\'s own ea-nginx helper')
ok('needs root' in purge,
   'and says plainly when it cannot, because this runs as an unprivileged '
   'cPanel user — an unattributed silent failure here is how the bug lasted')
ok('|| true' in SRC[i_purge - 40:i_purge + 40],
   'and a failed purge never aborts the publish: the files are already '
   'correct, and the read-back reports the consequence')

print('')
print('%d passed, %d failed' % (_passed, _failed))
sys.exit(1 if _failed else 0)
