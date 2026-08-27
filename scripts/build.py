#!/usr/bin/env python3
"""Sentinel Gate — release builder (cross-platform).

Exists because releases are cut on Windows, where make-release.sh cannot run:
there is no `zip` and no system `php`, so its checks were skipped on every
single release while printing lines that read like success. The working build
also lived in a temp directory that got wiped mid-project. Both belong in the
repository.

Produces exactly what make-release.sh produces:
    dist/sentinel-gate-<version>.zip     payload rooted at sentinel-gate/
    dist/notes-<version>.md              that version's notes only
    latest.json                          manifest with sha256

Refuses to package anything that fails scripts/preflight.py.

Usage:  python scripts/build.py
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ITEMS = ["backend", "frontend", "whm", "install.sh", "uninstall.sh",
         "update.sh", "test.sh", "VERSION"]
# Development tooling must never reach a customer server. ITEMS already omits
# these, but naming them makes the intent explicit and survives someone adding a
# directory to ITEMS later.
SKIP_DIRS = {".git", "__pycache__", "node_modules", "tests", "scripts", "php", ".github"}
NEVER_PACKAGE = ("/tests/", "/scripts/", "/php/", "/.github/", "/.git/")
SKIP_FILES = {".DS_Store", "Thumbs.db"}
CDN = "https://defender.lws-s1.com/sentinel-gate/code"
MIRROR = "https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main"


def discard(path):
    """Delete a rejected archive, and never let the deletion mask the rejection.

    A failed os.remove() once raised over the top of the real error, so the
    build reported a PermissionError instead of "development files leaked into
    the package" -- and left the bad zip on disk to be published by the next
    step. If it cannot be removed, say so loudly; the caller still returns 1.
    """
    for _ in range(5):
        try:
            os.remove(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.3)
    print("  WARNING: could not delete the rejected archive: %s" % path)
    print("           delete it by hand before publishing anything.")


def main():
    version = io.open(os.path.join(REPO, "VERSION"), encoding="utf-8").read().strip()
    print("Building Sentinel Gate v%s\n" % version)

    # ── Gate first. Never package unverified code. ────────────────────────────
    rc = subprocess.run([sys.executable, os.path.join(REPO, "scripts", "preflight.py")]).returncode
    if rc != 0:
        print("\nBuild aborted.")
        return rc

    # ── Cache-bust stamp on frontend assets ───────────────────────────────────
    idx = os.path.join(REPO, "frontend", "index.html")
    if os.path.exists(idx):
        s = io.open(idx, encoding="utf-8").read()
        s = re.sub(r'(css/app\.css|js/api\.js|js/app\.js)(\?v=[^"]*)?',
                   r'\1?v=' + version, s)
        # read fully, then write: opening 'w' in the same expression as the read
        # truncates the file before the read runs, which is how config.php was
        # emptied. Never combine the two.
        with io.open(idx, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(s)

    # ── Package ───────────────────────────────────────────────────────────────
    out_dir = os.path.join(REPO, "dist")
    os.makedirs(out_dir, exist_ok=True)
    zip_path = os.path.join(out_dir, "sentinel-gate-%s.zip" % version)
    if os.path.exists(zip_path):
        os.remove(zip_path)

    count = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for item in ITEMS:
            src = os.path.join(REPO, item)
            if not os.path.exists(src):
                continue
            if os.path.isfile(src):
                z.write(src, "sentinel-gate/" + item)
                count += 1
                continue
            for root, dirs, files in os.walk(src):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in files:
                    if f in SKIP_FILES:
                        continue
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, REPO).replace("\\", "/")
                    z.write(full, "sentinel-gate/" + rel)
                    count += 1

    # ── Verify the PACKAGED payload, not just the source tree ─────────────────
    with zipfile.ZipFile(zip_path) as z:
        names = z.namelist()
        leaked = [n for n in names if any(seg in n for seg in NEVER_PACKAGE)]
        if leaked:
            print("\nDevelopment files leaked into the package: %s" % leaked[:8])
            discard(zip_path)
            return 1
        empties = [n for n in names if n.endswith(".php") and z.getinfo(n).file_size == 0]
        if empties:
            print("\nPackaged payload contains empty PHP files: %s" % empties)
            discard(zip_path)
            return 1
        cfg = [n for n in names if n.endswith("backend/config/config.php")]
        if not cfg:
            print("\nPackaged payload has no config.php")
            discard(zip_path)
            return 1
        body = z.read(cfg[0]).decode("utf-8")
        if "define('SG_ROOT'" not in body:
            print("\nPackaged config.php does not define SG_ROOT")
            discard(zip_path)
            return 1

    # The packaging test asserts against the finished zip, so it cannot run in
    # preflight — the zip does not exist yet. Run it here, where it can.
    php = None
    for cand in (os.path.join(REPO, "php", "php.exe"), os.path.join(REPO, "php", "php")):
        if os.path.exists(cand):
            php = cand
            break
    if php:
        r = subprocess.run([php, os.path.join(REPO, "tests", "test_packaging.php")],
                           capture_output=True, text=True)
        bad = [l for l in (r.stdout or "").splitlines() if l.startswith("FAIL ")]
        if r.returncode != 0 or bad:
            print("\nPackaging test failed:")
            for l in (bad or (r.stdout or r.stderr).splitlines()[:5]):
                print("  " + l)
            discard(zip_path)
            return 1
        n = len([l for l in (r.stdout or "").splitlines() if l.startswith("PASS ")])
        print("  packaging: %d assertions passed against the finished zip" % n)

    data = open(zip_path, "rb").read()
    sha = hashlib.sha256(data).hexdigest()
    print("\n  zip      : %s" % os.path.basename(zip_path))
    print("  files    : %d" % count)
    print("  bytes    : %d" % len(data))
    print("  sha256   : %s" % sha)

    # ── Notes for this version only ───────────────────────────────────────────
    notes_path = os.path.join(out_dir, "notes-%s.md" % version)
    r = subprocess.run(["bash", os.path.join(REPO, "scripts", "extract-notes.sh"), version],
                       capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        with io.open(notes_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(r.stdout)
        print("  notes    : %s (%d lines)" % (os.path.basename(notes_path),
                                              r.stdout.count("\n")))
    else:
        print("  notes    : NONE — add a CHANGELOG section for %s" % version)

    # ── Manifest ──────────────────────────────────────────────────────────────
    manifest = {
        "version": version,
        "url": "%s/dist/sentinel-gate-%s.zip" % (CDN, version),
        "mirror": "%s/dist/sentinel-gate-%s.zip" % (MIRROR, version),
        "sha256": sha,
        "notes": "%s/v%s/CHANGELOG.md" % (CDN, version),
    }
    with io.open(os.path.join(REPO, "latest.json"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(manifest, indent=2) + "\n")
    print("  manifest : latest.json")
    print("\nBuild OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
