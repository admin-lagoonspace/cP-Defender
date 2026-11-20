#!/usr/bin/env python3
"""ServerScrub — pre-release validation.

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
  5. Both test suites run, and a suite that cannot be run FAILS rather than
     being skipped quietly. tests/run.php (unit + regression) and
     tests/run-tests.sh (installer and updater against a mock server).
  6. A package exists for the current VERSION, built into a scratch directory
     if it does not, so test_packaging.php always has a real zip to assert
     against instead of skipping its 57 checks, which it did for seven weeks.

This list has been short of what the file does for a while -- the static
analysis passes, the API smoke test and the regression suite all grew in
without being written down here, which is how a reader concluded the suites
were not gated when they were.

Usage:  python scripts/preflight.py [--php <path>]
Exit 0 = safe to package.
"""
import os
import re
import subprocess
import shutil
import tempfile
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIRED_CONSTANTS = ["SG_ROOT", "SG_VERSION", "SG_DB", "QUARANTINE_DIR", "SG_LOGS"]

RED, GREEN, YELLOW, NC = "\033[0;31m", "\033[0;32m", "\033[1;33m", "\033[0m"


def fail(msg):
    print("  %s[x]%s %s" % (RED, NC, msg))


def ok(msg):
    print("  %s[+]%s %s" % (GREEN, NC, msg))


def warn(msg):
    print("  %s[!]%s %s" % (YELLOW, NC, msg))


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
    # "cpanel" holds the page served to every hosting customer. It was not
    # walked here, so the file with the widest audience in the product had
    # neither the empty-file nor the parse gate applied to it -- the same
    # blind spot that shipped a zero-byte config.php in 3.19.2.
    for sub in ("backend", "scripts", "cpanel"):
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


def find_bash():
    """Locate bash. Releases are cut on Windows as often as on Linux."""
    for cand in ("bash",
                 "C:/Program Files/Git/bin/bash.exe",
                 "C:/Program Files (x86)/Git/bin/bash.exe",
                 "/bin/bash", "/usr/bin/bash"):
        try:
            r = subprocess.run([cand, "-c", "exit 0"], capture_output=True)
            if r.returncode == 0:
                return cand
        except Exception:
            continue
    return None


def run_suite(label, cmd, tail=14):
    """Run a test suite and report it. Returns the number of problems.

    A suite that cannot be run counts as a FAILURE, not a skip.

    That rule is the whole point of adding this. tests/run-tests.sh spent seven
    weeks failing 26 of 27 assertions because a stub had not kept up with
    install.sh, and nothing that gated a release looked at it -- so every
    release since 23 Sep went out over a suite that had not tested anything.
    A gate that can be absent without anyone noticing is not a gate.
    """
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, timeout=1800)
    except FileNotFoundError:
        fail("%s: cannot run %s" % (label, cmd[0]))
        return 1
    except subprocess.TimeoutExpired:
        fail("%s: timed out after 30 minutes" % label)
        return 1

    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0:
        summary = [l for l in out.splitlines() if "assertions passed" in l or "All tests passed" in l]
        ok("%s passed%s" % (label, (" -- " + summary[-1].strip()) if summary else ""))
        return 0

    fail("%s FAILED (exit %d)" % (label, r.returncode))
    for line in out.strip().splitlines()[-tail:]:
        print("        " + line.rstrip()[:200])
    return 1


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

    # 2c-cron. a scheduled task that names a class the script never required
    # fatals the moment it becomes due, and cron output goes to a log nobody
    # reads -- so the symptom is a feature that silently never runs. This has
    # happened three times now: UserReport, RealTimeMonitor and WAF.
    if php:
        r = subprocess.run([php, os.path.join(REPO, "scripts", "check-cron-requires.php")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            for line in (r.stdout + r.stderr).strip().splitlines():
                if line.strip():
                    fail(line.strip())
            problems += 1
        else:
            ok("every class a cron script uses is required by it")

    # 2c-js. the front-end must at least be bracket-balanced
    # There is no Node here, so for this whole project the only JS validation
    # was a regex brace counter that mis-handled template literals -- it
    # reported a different imbalance for correct code and could not tell a real
    # error from its own confusion. Every front-end change shipped unparsed.
    r = subprocess.run([sys.executable,
                        os.path.join(REPO, "scripts", "check-js-syntax.py")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        for line in (r.stdout + r.stderr).strip().splitlines():
            if line.strip():
                fail(line.strip())
        problems += 1
    else:
        ok("front-end JavaScript is bracket-balanced")

    # 2c-js2. a helper called outside the function that declares it
    # Bracket balance and handler resolution both passed while three shipped
    # features did nothing at all: g() -- the element lookup nearly every
    # handler uses -- was declared only INSIDE two functions, so module-scope
    # callers threw ReferenceError the moment they ran, silently, inside an
    # event handler.
    r = subprocess.run([sys.executable,
                        os.path.join(REPO, "scripts", "check-js-scope.py")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        for line in (r.stdout + r.stderr).strip().splitlines():
            if line.strip():
                fail(line.strip())
        problems += 1
    else:
        ok("no JS helper is called outside the function that declares it")

    # 2c-wire. controls that exist but are never activated
    # Three features shipped dead in a row and every check passed each time:
    # a button whose attribute was broken by JSON.stringify, a bulk button
    # given a class while the enable logic used a hardcoded id list, and a
    # card added to a page whose loader was never called. In all three the
    # function existed, the brackets balanced and the API route was there.
    r = subprocess.run([sys.executable,
                        os.path.join(REPO, "scripts", "check-js-wiring.py")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        for line in (r.stdout + r.stderr).strip().splitlines():
            if line.strip():
                fail(line.strip())
        problems += 1
    else:
        ok("every disabled control is enabled, and every loader is reached")

    # 2c-gate. a detection writer that bypasses the not-malware verdict
    # "Respect the operator's verdict" has to hold for EVERY finding or it
    # holds for none: one writer inserting straight into `threats` re-creates
    # a row that was already cleared, which from the panel is indistinguishable
    # from the feature being broken. There were six writers when the gate went
    # in -- five in Scanner.php and one in the Python daemon.
    r = subprocess.run([sys.executable,
                        os.path.join(REPO, "scripts", "check-threat-gate.py")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        for line in (r.stdout + r.stderr).strip().splitlines():
            if line.strip():
                fail(line.strip())
        problems += 1
    else:
        ok("every detection writer goes through the verdict gate")

    # 2c-attr. a value interpolated into an HTML event attribute
    # A threat row rendered onclick="excludeThreatPath(${JSON.stringify(path)})".
    # JSON.stringify emits DOUBLE quotes, which terminate the attribute, so the
    # browser never bound a handler and the button did nothing when clicked.
    # Every existing check passed: the function existed, brackets balanced, the
    # test asserted the name was present. The feature was completely dead.
    r = subprocess.run([sys.executable,
                        os.path.join(REPO, "scripts", "check-js-attrs.py")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        for line in (r.stdout + r.stderr).strip().splitlines():
            if line.strip():
                fail(line.strip())
        problems += 1
    else:
        ok("only numbers are interpolated into HTML event attributes")

    # 2c-dup. two top-level JS functions of the same name
    # JavaScript allows it and the later one silently replaces the earlier for
    # every caller in the file. A helper named fmtNum() was added to app.js
    # without noticing one existed 4,600 lines earlier, and the two behaved
    # differently -- every number on every other page would have changed
    # output, with no error anywhere.
    r = subprocess.run([sys.executable,
                        os.path.join(REPO, "scripts", "check-js-duplicates.py")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        for line in (r.stdout + r.stderr).strip().splitlines():
            if line.strip():
                fail(line.strip())
        problems += 1
    else:
        ok("no JS function is declared twice at top level")

    # 2c-sh. a shipped shell script must not be able to abort in silence
    # Under `set -e` + `pipefail`, `VAR="$(cmd | cmd)"` terminates the script
    # when any stage fails instead of leaving VAR empty. update.sh had eleven of
    # these. One was an informational curl of <channel>/latest/VERSION, which
    # 404s on a channel serving only dist/ -- so on 2026-10-20 a production
    # server ran the updater twice and both times it printed "Checking releases
    # channel..." and returned to the prompt, having changed nothing and said
    # nothing. Every one of those assignments was followed by an emptiness
    # check: the code was written for an empty value and the shell options
    # silently defeated it.
    r = subprocess.run([sys.executable,
                        os.path.join(REPO, "scripts", "check-shell-pipefail.py")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        for line in (r.stdout + r.stderr).strip().splitlines():
            if line.strip():
                fail(line.strip())
        problems += 1
    else:
        ok("no shipped shell script can abort silently (set -e + pipefail)")

    # 2c-py. the daemon must run on the oldest Python we support
    # cPanel runs on RHEL-family hosts shipping Python 3.6. The suite runs on
    # the developer's Python, which is far newer, so it proved nothing about the
    # customer's interpreter -- and a 3.8-only keyword shipped and crashed the
    # daemon on every start.
    r = subprocess.run([sys.executable,
                        os.path.join(REPO, "scripts", "check-python-compat.py"), "3.6"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        for line in (r.stdout + r.stderr).strip().splitlines():
            if line.strip():
                fail(line.strip())
        problems += 1
    else:
        ok("daemon and cron scripts run on Python 3.6")

    # 2c-lib. every lib must load without help from its caller
    #
    # UserReport used UserScanRequest and required nothing. The cron scripts
    # happened to load it; the CLI did not, so `serverscrub user-reports`
    # threw "Class not found" on all 132 accounts -- and writeAll() catches
    # Throwable per account, so it reported "no usable home directory" and
    # every customer's report.json froze for three releases.
    if php:
        r = subprocess.run([php, os.path.join(REPO, "scripts", "check-lib-standalone.php")],
                           capture_output=True, text=True)
        if r.returncode != 0:
            fail("a lib cannot be loaded on its own:")
            for line in (r.stdout + r.stderr).strip().splitlines():
                if line.strip():
                    print("        " + line.strip())
            problems += 1
        else:
            ok("every lib loads standalone and declares its class")

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

    # 2d-bis. make sure there IS a package to assert against.
    #
    # tests/test_packaging.php asserts against the FINISHED zip -- deliberately,
    # because the build and its intentions have diverged before. But it looked
    # for dist/serverscrub-<VERSION>.zip and, not finding one, printed SKIP and
    # returned. Preflight runs BEFORE publish.sh builds, so between a version
    # bump and the build that zip does not exist: all 57 of its assertions,
    # the four-list packaging agreement checks among them, silently did not run
    # in the one check that gates a release. They ran afterwards against the
    # previous version -- the one version nobody is about to ship.
    #
    # So build one here when it is missing, and tell the suite where it is.
    # make-release.sh is deterministic, touches no network and no git, and is
    # exactly what publish.sh runs a moment later.
    #
    # The build goes to a scratch directory, NOT to dist/. dist/<zip> is a
    # committed artifact whose sha256 the live manifest and the CDN advertise,
    # and a rebuild is byte-different from the released file (zip records
    # mtimes) even when its contents are identical. A check must not rewrite
    # the thing it is checking.
    want_ver = open(os.path.join(REPO, "VERSION"), encoding="utf-8").read().strip()
    want_zip = os.path.join(REPO, "dist", "serverscrub-%s.zip" % want_ver)
    suite_env = dict(os.environ)
    pkg_stage = None
    if os.path.isfile(want_zip):
        ok("package present for %s (%d bytes)" % (want_ver, os.path.getsize(want_zip)))
    else:
        bash = find_bash()
        if not bash:
            fail("no package for %s and no bash to build one -- the packaging"
                 " rules cannot be checked" % want_ver)
            problems += 1
        else:
            pkg_stage = tempfile.mkdtemp(prefix="sg-preflight-pkg-")
            print("    no dist/serverscrub-%s.zip yet -- building one so the"
                  " packaging assertions have an artifact..." % want_ver)
            try:
                r = subprocess.run([bash, os.path.join(REPO, "scripts", "make-release.sh"),
                                    "--out", pkg_stage],
                                   capture_output=True, text=True, errors="replace",
                                   cwd=REPO, timeout=1800)
                rc, blob = r.returncode, (r.stdout or "") + (r.stderr or "")
            except Exception as exc:
                rc, blob = 1, str(exc)
            built = os.path.join(pkg_stage, "serverscrub-%s.zip" % want_ver)
            if rc != 0 or not os.path.isfile(built):
                fail("make-release.sh could not build serverscrub-%s.zip (exit %s)"
                     % (want_ver, rc))
                for line in blob.strip().splitlines()[-12:]:
                    print("        " + line.rstrip()[:200])
                problems += 1
            else:
                suite_env["SG_PACKAGE_ZIP"] = built
                ok("built a package for %s to check (%d bytes, scratch copy)"
                   % (want_ver, os.path.getsize(built)))

    # 2e. the regression suite
    #
    # `if php:` with no else meant a machine without an interpreter skipped the
    # entire suite and still printed PREFLIGHT PASSED. The parse gate above
    # fails loudly in that case, so it never went unnoticed in practice -- but
    # a check that quietly does not run is the thing this file exists to stop.
    if not php:
        fail("regression tests: no PHP interpreter -- suite did not run")
        problems += 1
    if php:
        r = subprocess.run([php, os.path.join(REPO, "tests", "run.php")],
                           capture_output=True, text=True, env=suite_env)
        if r.returncode != 0:
            fail("regression tests failed:")
            for line in (r.stdout or "").strip().splitlines():
                if "FAIL" in line or "CRASH" in line or "assertions failed" in line:
                    print("        " + line.strip())
            problems += 1
        else:
            last = [l for l in (r.stdout or "").strip().splitlines() if "assertions" in l]
            ok("regression tests: " + (last[-1].strip() if last else "passed"))

    if pkg_stage:
        shutil.rmtree(pkg_stage, ignore_errors=True)

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

    # 5. the mock-env suite.
    #
    # The PHP suite under tests/ is already gated above (2e), so the unit and
    # regression tests -- the WAF rollback tests that pin the 7 Nov 502 outage
    # among them -- have been release-blocking all along.
    #
    # tests/run-tests.sh was not, and it is the only thing that exercises
    # install.sh and update.sh end to end against a mock server: the paths by
    # which the product arrives on a machine at all. It had been failing 26 of
    # 27 assertions since 23 Sep without blocking anything, because nothing
    # ran it.
    if os.environ.get("SG_SKIP_TESTS") == "1":
        warn("mock-env suite SKIPPED via SG_SKIP_TESTS=1 -- the installer and")
        warn("updater are not exercised in this release")
    else:
        bash = find_bash()
        if bash:
            problems += run_suite("mock-env suite (tests/run-tests.sh)",
                                  [bash, os.path.join(REPO, "tests", "run-tests.sh")])
        else:
            fail("mock-env suite: no bash found -- install Git Bash or pass SG_SKIP_TESTS=1 knowingly")
            problems += 1

    # 6. the docker cPanel environment.
    #
    # EVERY CHECK ABOVE THIS LINE READS SOURCE TEXT OR RUNS ON WINDOWS.
    #
    # None of them can tell whether the daemon actually quarantines a file,
    # whether a page renders, or whether an upgrade restarts the monitor.
    # v4.37.4, .5 and .6 each shipped on a green preflight -- 5,199 assertions
    # at the end -- and the containment fix they existed to deliver never ran
    # once on the server it was written for, because the updater left the
    # daemon stopped. A suite that cannot distinguish "the string is in the
    # file" from "the product works" was reporting the first and being read as
    # the second.
    #
    # docker/compose.yml builds a cPanel-shaped machine and runs the real
    # install.sh in it. That is the cheapest thing that executes this product
    # on Linux, and it is in the repo. Not running it was the gap.
    #
    # SG_SKIP_DOCKER=1 is deliberately noisy rather than silent: skipping it
    # is a choice about a release, not a default.
    if os.environ.get("SG_SKIP_DOCKER") == "1":
        warn("docker environment SKIPPED via SG_SKIP_DOCKER=1 -- nothing in")
        warn("  this release has been executed on Linux")
    elif shutil.which("docker") is None:
        warn("docker not found -- the product has NOT been executed on Linux")
        warn("  in this run. Every check above reads source text.")
    else:
        r = subprocess.run(["docker", "compose", "-f",
                            os.path.join(REPO, "docker", "compose.yml"),
                            "run", "--rm", "test"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = (r.stdout or b"").decode("utf-8", "replace")
        if r.returncode == 0:
            ok("docker cPanel environment: install + suite passed on Linux")
        else:
            fail("docker cPanel environment FAILED (exit %d)" % r.returncode)
            for line in out.strip().splitlines()[-25:]:
                print("      " + line)
            problems += 1

    print("")
    if problems:
        print("%sPREFLIGHT FAILED%s — %d problem(s). Not safe to package."
              % (RED, NC, problems))
        return 1
    print("%sPREFLIGHT PASSED%s" % (GREEN, NC))
    return 0


if __name__ == "__main__":
    sys.exit(main())
