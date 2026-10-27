#!/usr/bin/env python3
"""
Catch controls that exist but are never activated, and loaders never called.

WHY THIS EXISTS
---------------
Three features shipped dead in a row, and every existing check passed each time:

  1. An exclude button rendered
     onclick="excludeThreatPath(${JSON.stringify(path)})". JSON.stringify emits
     double quotes, which ended the HTML attribute, so no handler was ever
     bound. (check-js-attrs.py catches that one now.)

  2. A bulk "Not malware - exclude" button was given the threat-bulk-btn class,
     but updateBulkBar() enabled buttons from a hardcoded list of two IDs. The
     new one was never enabled, stayed `disabled` from the markup, and did
     nothing.

  3. A "Scan exclusions" card was added to the Scanner page, but
     loadExclusions() was never added to that page's loader. The card rendered
     permanently empty, which reads as "there are no exclusions" rather than
     "this was never loaded".

In all three the function existed, the brackets balanced, the API route
existed, and a test asserted the identifier appeared somewhere in the file.
None of that is evidence a control WORKS.

WHAT IS CHECKED
---------------
A. Every element that starts `disabled` in the markup must be enabled
   somewhere by JS -- by its id, or by a class that appears in a selector whose
   result has `.disabled` assigned.

B. Every load* function that writes to ids belonging to a page must be
   reachable from that page: named in PAGE_LOADERS for it, or called from an
   on* attribute inside that page's markup, or called by another function that
   is.

Exit 0 clean, 1 on findings.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(REPO, "frontend", "index.html")
APPJS = os.path.join(REPO, "frontend", "js", "app.js")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
NC = "\033[0m"


def read(p):
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


# ── A. disabled controls ────────────────────────────────────────────────────

def check_disabled(html, js):
    """Elements that ship disabled and are never re-enabled."""
    out = []
    # <button ... id="x" ... disabled>  (attribute order varies)
    for m in re.finditer(r"<(?:button|input|select|textarea)\b([^>]*)>", html):
        attrs = m.group(1)
        if not re.search(r"\bdisabled\b", attrs):
            continue
        idm = re.search(r'\bid="([^"]+)"', attrs)
        if not idm:
            continue
        el_id = idm.group(1)
        classes = re.findall(r'\bclass="([^"]*)"', attrs)
        classes = classes[0].split() if classes else []

        # Enabled by id?
        if re.search(r"""getElementById\(['"]%s['"]\)""" % re.escape(el_id), js):
            continue
        if re.search(r"""\bg\(['"]%s['"]\)""" % re.escape(el_id), js):
            continue

        # Enabled via a class selector?
        #
        # The assignment must be able to produce FALSE. A selector that only
        # ever sets `.disabled = true` disables the control during an
        # operation; it never enables it. Counting that as "wired" is what let
        # a dead button through the first version of this check.
        by_class = False
        for cls in classes:
            for qm in re.finditer(
                    r"""querySelectorAll\(['"][^'"]*\.%s[^'"]*['"]\)(.{0,400})"""
                    % re.escape(cls), js, re.S):
                for am in re.finditer(r"\.disabled\s*=\s*([^;\n]+)",
                                      qm.group(1)):
                    val = am.group(1).strip().rstrip(";")
                    # The assignment must be CONDITIONAL. A literal is a
                    # bracket around an operation -- `= true` before,
                    # `= false` after -- not a control enabled because
                    # the user selected something. Accepting `= false` is
                    # what let the dead bulk button through the second
                    # version of this check: it really was set enabled,
                    # but only after an unrelated action, never on
                    # selection.
                    if val not in ("true", "false"):
                        by_class = True
                        break
                if by_class:
                    break
            if by_class:
                break
        if by_class:
            continue

        out.append((el_id,
                    "ships disabled and nothing ever enables it, so it cannot "
                    "be clicked"))
    return out


# ── B. loaders that are never reached ───────────────────────────────────────

def page_ids(html):
    """id -> page it lives on."""
    pages = {}
    for m in re.finditer(r'<div id="page-([a-z0-9_-]+)"', html):
        name = m.group(1)
        start = m.start()
        nxt = re.search(r'<div id="page-[a-z0-9_-]+"', html[start + 10:])
        end = start + 10 + nxt.start() if nxt else len(html)
        for im in re.finditer(r'\bid="([^"]+)"', html[start:end]):
            pages.setdefault(im.group(1), name)
    return pages


def functions(js):
    """name -> body, for top-level functions."""
    out = {}
    pat = re.compile(r"^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", re.M)
    marks = [(m.group(1), m.start()) for m in pat.finditer(js)]
    for i, (name, pos) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(js)
        out[name] = js[pos:end]
    return out


def check_loaders(html, js):
    """A no-argument load* function that fills a page must be in its loader.

    The rule is deliberately strict: being referenced by a Reload BUTTON on the
    page does not count. A button is not initial population -- the Scan
    exclusions card had exactly that, a working Reload button and no entry in
    PAGE_LOADERS, so it rendered empty every time the page was opened and the
    operator had to press Reload to see their own settings.

    Functions that TAKE arguments are exempt: those are filters and actions
    (loadIntegrityChanges('modified')), not page population.
    """
    # Genuine exceptions, each with its reason. Kept deliberately tiny: an
    # allowlist is where a lint rule goes to die, so anything added here needs
    # to be a cross-page write rather than a section nobody populates.
    ALLOW = {
        # Owned by the Settings page. It also refreshes the small
        # "auto-quarantine on" badge in the Scanner header -- one id, not a
        # section, and the Scanner page fills that badge itself through
        # loadScannerQuarantineState().
        ("loadSettings", "scanner"),
    }

    out = []
    ids = page_ids(html)
    fns = functions(js)

    loaders = {}
    tbl = re.search(r"const PAGE_LOADERS = \{(.*?)\n  \};", js, re.S)
    if tbl:
        body = tbl.group(1)
        # Split on top-level "name: [" entries.
        marks = [(m.group(1), m.start())
                 for m in re.finditer(r"^\s{4}([a-z0-9_]+):\s*\[", body, re.M)]
        for i, (name, pos) in enumerate(marks):
            end = marks[i + 1][1] if i + 1 < len(marks) else len(body)
            loaders[name] = body[pos:end]

    # Functions that are themselves a page's loader. refreshDashboard() is the
    # dashboard's entry in PAGE_LOADERS but does not start with "load", so
    # following into it blamed every loader that calls it for the whole
    # dashboard.
    page_fillers = set()
    for entry in loaders.values():
        page_fillers.update(re.findall(r"([A-Za-z_$][\w$]*)\s*\(", entry))

    # Functions invoked from an event attribute, in the markup or in a row
    # template built in JS. Those are things a user CLICKS -- opening a file
    # viewer, showing a WAF event -- not population of the page, and whatever
    # they write to is not the calling loader's responsibility.
    actions = set(re.findall(r"""on[a-z]+\s*=\s*["']\s*([A-Za-z_$][\w$]*)\s*\(""",
                             html))
    actions |= set(re.findall(r"""on[a-z]+\s*=\s*\\?["']?\s*([A-Za-z_$][\w$]*)\s*\(""",
                              js))

    # How many functions call each helper AT ALL.
    #
    # Counting only load* callers was not enough: toast() is called from one
    # loader and from dozens of ordinary handlers, so by that measure it
    # looked like that loader's private renderer and contributed
    # #toast-container -- a global element -- to the loader's page set.
    #
    # A function with exactly ONE caller in the whole file is that caller's
    # helper. populateStorageUI() has one. toast() has many.
    loader_callers = {}
    for lname, lbody in fns.items():
        for cm in set(re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", lbody)):
            if cm in fns and cm != lname:
                loader_callers[cm] = loader_callers.get(cm, 0) + 1

    for fname, fbody in fns.items():
        if not fname.startswith("load"):
            continue
        # Takes arguments? Then it is an action, not page population.
        sig = re.match(r"(?:async\s+)?function\s+\w+\s*\(([^)]*)\)", fbody)
        if sig and sig.group(1).strip():
            continue

        # Ids written by this function OR by a helper it calls.
        #
        # Looking only at the function's own body missed a whole card.
        # loadStorageStats() touches no element itself -- it fetches, then
        # hands the payload to populateStorageUI(), which does all the
        # writing. So the check saw a load* function that filled no page,
        # concluded there was nothing to wire, and passed while the entire
        # Storage Management card read "--" until somebody pressed Refresh.
        #
        # Only into a helper THIS loader alone calls.
        #
        # Following every callee was too blunt: toast(), doRefresh() and
        # friends touch elements all over the app, so every loader that called
        # one inherited every page those helpers write to, and the check
        # reported pages that loader has nothing to do with.
        #
        # A helper called by exactly one load* function IS that loader's
        # renderer -- populateStorageUI() is called only by loadStorageStats().
        # A helper called by several is a utility, and whose page it writes to
        # is not this loader's business.
        def ids_touched(body, depth=1):
            found = set()
            for im in re.finditer(
                    r"""(?:getElementById|\bg)\(['"]([^'"]+)['"]\)""", body):
                pg = ids.get(im.group(1))
                if pg:
                    found.add(pg)
            if depth > 0:
                for cm in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(", body):
                    callee = cm.group(1)
                    if (callee in fns and callee != fname
                            and not callee.startswith("load")
                            and callee not in page_fillers
                            and callee not in actions
                            and loader_callers.get(callee, 0) == 1):
                        found |= ids_touched(fns[callee], depth - 1)
            return found

        touched = ids_touched(fbody)

        for pg in sorted(touched):
            entry = loaders.get(pg, "")
            if re.search(r"\b%s\s*\(" % re.escape(fname), entry):
                continue
            # Or REACHABLE from the entry, however many hops away.
            #
            # This followed exactly one call and so reported a false positive
            # the first time a loader delegated twice: the firewall page goes
            # loadFirewall -> loadFirewallStages -> loadFirewallRules, which is
            # perfectly well wired and was flagged as dead. The rule being
            # enforced is "reachable from the page loader", not "one call away
            # from it", so it follows the chain.
            def reaches(body, target, seen, depth=4):
                if depth <= 0:
                    return False
                if re.search(r"\b%s\s*\(" % re.escape(target), body):
                    return True
                for callee in set(re.findall(r"([A-Za-z_$][\w$]*)\s*\(", body)):
                    if callee in fns and callee not in seen:
                        seen.add(callee)
                        if reaches(fns[callee], target, seen, depth - 1):
                            return True
                return False

            if reaches(entry, fname, set()):
                continue
            if (fname, pg) in ALLOW:
                continue
            out.append((fname,
                        'fills the "%s" page but is not in its PAGE_LOADERS '
                        "entry, so that section is empty until something else "
                        "is clicked" % pg))
    return out


def main():
    html, js = read(HTML), read(APPJS)
    findings = []
    for el, why in check_disabled(html, js):
        findings.append(("control", el, why))
    for fn, why in check_loaders(html, js):
        findings.append(("loader", fn, why))

    for kind, name, why in findings:
        print("%s[-]%s %s `%s` %s" % (RED, NC, kind, name, why))

    if findings:
        print()
        print("%s[-]%s %d dead control(s) or unreached loader(s)."
              % (RED, NC, len(findings)))
        print("      These pass every other check: the function exists, the")
        print("      brackets balance, the route is there. They still do nothing.")
        return 1

    print("%s[+]%s every disabled control is enabled somewhere, and every "
          "loader is reached" % (GREEN, NC))
    return 0


if __name__ == "__main__":
    sys.exit(main())
