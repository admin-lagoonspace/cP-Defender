#!/usr/bin/env python3
"""Sentinel Gate — pre-release validation.

Runs anywhere Python does, so the same checks apply whether a release is cut on
Linux via make-release.sh or on Windows via build.py. Previous gates lived only
in the bash path and therefore never ran on the machine releases were actually
built on.

Checks, in the order they catch real failures we have shipped:

  1. No PHP file is empty. `php -l` reports success on a zero-byte file, so a
     truncated-to-nothing source passes a parse gate cleanly. 3.19.2 shipped an
     empty config.php exactly this way.
  2. Every PHP file parses, using a real interpreter.
  3. config.php defines the constants the runtime guards test for. Without them
     every request dies with "Direct access denied" and nothing says why.
  4. config.php's SG_VERSION matches ./VERSION, so the UI and the updater agree.

Usage:  python scripts/preflight.py [--php <path>]
Exit 0 = safe to package.
"""
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIRED_CONSTANTS = ["SG_ROOT", "SG_VERSION", "SG_DB", "QUARANTINE_DIR", "SG_LOGS"]

RED, GREEN, YELLOW, NC = "\033[0;31m", "\033[0;32m", "\033[1;33m", "\033[0m"


def fail(msg):
    print("  %s[x]%s %s" % (RED, NC, msg))


def ok(msg):
    print("  %s[+]%s %s" % (GREEN, NC, msg))


def find_php(explicit=None):
    if explicit:
        return explicit if os.path.exists(explicit) else None
    for cand in [os.path.join(REPO, "php", "php.exe"),
                 os.path.join(REPO, "php", "php")]:
        if os.path.exists(cand):
            return cand
    for cand in ("php", "php8", "php8.2"):
        try:
            subprocess.run([cand, "-v"], capture_output=True, check=True)
            return cand
        except Exception:
            continue
    return None


def php_files():
    out = []
    for sub in ("backend", "scripts"):
        base = os.path.join(REPO, sub)
        for root, _dirs, files in os.walk(base):
            for f in files:
                if f.endswith(".php"):
                    out.append(os.path.join(root, f))
    return sorted(out)


def main():
    php = None
    if "--php" in sys.argv:
        php = sys.argv[sys.argv.index("--php") + 1]
    php = find_php(php)

    files = php_files()
    problems = 0

    # 1. empty files
    empty = [f for f in files if os.path.getsize(f) == 0]
    for f in empty:
        fail("EMPTY: %s" % os.path.relpath(f, REPO))
        problems += 1
    if not empty:
        ok("no empty PHP files (%d checked)" % len(files))

    # 2. syntax
    if php is None:
        fail("no PHP interpreter found — cannot verify syntax")
        print("      put one at %s or pass --php" % os.path.join(REPO, "php", "php.exe"))
        problems += 1
    else:
        bad = 0
        for f in files:
            r = subprocess.run([php, "-l", f], capture_output=True, text=True)
            if r.returncode != 0:
                fail("PARSE: %s" % os.path.relpath(f, REPO))
                print("        " + (r.stdout or r.stderr).strip().splitlines()[0][:160])
                bad += 1
        problems += bad
        if bad == 0:
            ok("all %d PHP files parse (%s)" % (len(files), os.path.basename(php)))

    # 3 + 4. config.php sanity
    cfg = os.path.join(REPO, "backend", "config", "config.php")
    if not os.path.exists(cfg) or os.path.getsize(cfg) == 0:
        fail("config.php missing or empty — the product cannot start")
        problems += 1
    else:
        body = open(cfg, encoding="utf-8").read()
        missing = [c for c in REQUIRED_CONSTANTS if ("define('%s'" % c) not in body]
        if missing:
            fail("config.php does not define: %s" % ", ".join(missing))
            problems += 1
        else:
            ok("config.php defines all %d required constants" % len(REQUIRED_CONSTANTS))

        want = open(os.path.join(REPO, "VERSION"), encoding="utf-8").read().strip()
        m = re.search(r"SG_VERSION',\s*'([^']*)'", body)
        got = m.group(1) if m else None
        if got != want:
            fail("version mismatch: config.php=%s VERSION=%s" % (got, want))
            problems += 1
        else:
            ok("version consistent: %s" % want)

    print("")
    if problems:
        print("%sPREFLIGHT FAILED%s — %d problem(s). Not safe to package."
              % (RED, NC, problems))
        return 1
    print("%sPREFLIGHT PASSED%s" % (GREEN, NC))
    return 0


if __name__ == "__main__":
    sys.exit(main())
