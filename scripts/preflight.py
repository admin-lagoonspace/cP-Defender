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


def strip_php_comments(src):
    """Remove // # and /* */ comments so scans do not match prose."""
    out = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    out = re.sub(r"(?m)//[^\n]*", "", out)
    out = re.sub(r"(?m)#[^\n]*", "", out)
    return out


def private_call_scan():
    """Find Foo::bar() where bar() is private/protected in class Foo.

    php -l cannot see this: it is a runtime Error, not a syntax error. It cost a
    release. License::log() called the private Logger::write(), and because it
    ran inside a catch block the resulting fatal REPLACED the error it was
    reporting, so every page that consulted a licence went blank.
    """
    declared = {}
    sources = {}
    for f in php_files():
        src = strip_php_comments(open(f, encoding="utf-8", errors="replace").read())
        sources[f] = src
        m = re.search(r"\bclass\s+(\w+)", src)
        if not m:
            continue
        cls = m.group(1)
        for d in re.finditer(r"\b(?:private|protected)\s+static\s+function\s+(\w+)", src):
            declared.setdefault(cls, set()).add(d.group(1))

    hits = []
    for f, src in sources.items():
        m = re.search(r"\bclass\s+(\w+)", src)
        owner = m.group(1) if m else None
        for c in re.finditer(r"\b(\w+)::(\w+)\s*\(", src):
            cls, meth = c.group(1), c.group(2)
            if cls == owner or cls in ("self", "static", "parent"):
                continue
            if meth in declared.get(cls, ()):
                line = src[:c.start()].count("\n") + 1
                hits.append("%s:%d calls %s::%s(), which is not public"
                            % (os.path.relpath(f, REPO), line, cls, meth))
    return sorted(set(hits))


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

    # 2b. cross-class private calls
    hits = private_call_scan()
    for h in hits:
        fail(h)
    problems += len(hits)
    if not hits:
        ok("no calls to non-public methods across classes")

    # 2c. every cross-class static call resolves (tokenizer-based, exact)
    if php:
        r = subprocess.run([php, os.path.join(REPO, "scripts", "check-calls.php")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            for line in (r.stdout + r.stderr).strip().splitlines():
                if line.strip():
                    fail(line.strip())
            problems += 1
        else:
            ok("every cross-class static call resolves to a public method")

    # 2c-ui. every onclick/onchange resolves to a defined function
    if php:
        r = subprocess.run([php, os.path.join(REPO, "scripts", "check-ui-handlers.php")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            for line in (r.stdout + r.stderr).strip().splitlines():
                if line.strip():
                    fail(line.strip())
            problems += 1
        else:
            ok("every UI handler resolves to a defined function")

    # 2d. every read-only route actually executes
    if php:
        r = subprocess.run([php, os.path.join(REPO, "scripts", "smoke.php")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            fail("API smoke test failed:")
            for line in r.stdout.strip().splitlines():
                if line.startswith("  ") and ("[x]" in line or "not JSON" in line
                                              or "internal error" in line or "FATAL" in line):
                    print("        " + line.strip())
            problems += 1
        else:
            ok("all API routes execute and return JSON")

    # 2e. the regression suite
    if php:
        r = subprocess.run([php, os.path.join(REPO, "tests", "run.php")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            fail("regression tests failed:")
            for line in (r.stdout or "").strip().splitlines():
                if "FAIL" in line or "CRASH" in line or "assertions failed" in line:
                    print("        " + line.strip())
            problems += 1
        else:
            last = [l for l in (r.stdout or "").strip().splitlines() if "assertions" in l]
            ok("regression tests: " + (last[-1].strip() if last else "passed"))

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
