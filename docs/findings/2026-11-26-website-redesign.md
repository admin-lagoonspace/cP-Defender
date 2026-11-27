# Test run — 2026-11-26 (website redesign, logo, canonical https://www)

**Build:** uncommitted working tree on `fix/stale-channel-read-and-frozen-cdn`, website/ and
scripts/deploy-site.sh as Wasooli left them on 2026-11-23 (mtimes re-checked 2026-11-26: unchanged
since 16:45 on the 23rd). Spec: `docs/specs/2026-11-23-website-redesign-logo-canonical-https.md`.
**Environment:** `serverscrub-waf:live` (AlmaLinux 8.10, httpd 2.4.37 + mod_ssl, PHP 8.2 CLI,
curl 7.61.1), self-signed CA trusted system-wide, serverscrub.com / www / cpanel resolved to
127.0.0.1. Browser: built-in Chromium pane + headless Chrome 1440 and 375 px. Windows: embedded
Python for check-site.py and tests/test_site_redesign.py.
**Harness:** `docker/site-apache-test.sh` (new, Shakaal-owned). Run:
`docker run --rm -v "<repo>:/src:ro" --entrypoint bash serverscrub-waf:live /src/docker/site-apache-test.sh`
**Verdict (first run):** FAIL (one major against an explicit acceptance criterion; no blockers)
**Verdict (retest, same day, after Wasooli's fixes and design pass):** PASS WITH CAVEATS — see
"Retest" at the end. All four earlier findings are fixed; one new minor (backup pruning) and one
pre-existing minor outside this spec (preflight decoding).

## Not tested
- Real cPanel: ea-nginx in front of Apache, AutoSSL, cPanel's own global rewrites. `X-Forwarded-Proto`
  was simulated with a header, not a real proxy (OQ2 stays open until the prod R20 output).
- Acceptance 3 (status.html against live data): prod does not send `Access-Control-Allow-Origin`
  yet, so from any origin but the CDN itself every CDN read is CORS-blocked. Verifiable only after
  the deploy.
- Acceptance 6 favicon-at-16px tab screenshot; PNG/ICO sizes taken from Wasooli's note, not re-measured.
- Rendering outside Windows Chromium (Bahnschrift is Windows-only; macOS/Linux use fallbacks).
- Acceptance 9 (prod deploy output) — after release by definition.

## Findings

### 1. R20 verification misses a /releases/ redirect on plain HTTP — major
**What happens:** a block whose plain-HTTP rule lost the `/releases` exemption is deployed, verified
"OK", and left live. `http://serverscrub.com/releases/latest.json` → 301 to www; deploy exits 0, no
rollback. Same with no prior `.htaccess` (the broken file is kept), and on a re-run where the broken
block is already live.
**Reproduce:** harness section "rollback: a block that 301s /releases/" (deletes the first
`RewriteCond %{REQUEST_URI} !^/(releases|serverscrub)` line from a copy of htaccess.site, then
`SG_SITE_SRC=/tmp/broken bash deploy-site.sh`).
**Expected:** D4/R14a say `/releases/` is never redirected "on any scheme or host", and acceptance 7
asks for "a deliberately broken block that 301s /releases/" to be rolled back. R20 only probes
`https://serverscrub.com/releases/latest.json`. Add the `http://` probe with the same 200-and-no-Location
rule. Not a blocker today: the shipped block is correct and every known client fetches over HTTPS.
**Evidence:**
```
[+]   200  https://serverscrub.com/releases/latest.json (not redirected)
...Done.   (rc=0; curl http://serverscrub.com/releases/latest.json -> 301 https://www.serverscrub.com/releases/latest.json)
```
The HTTPS-side break **is** caught and rolled back byte-identical:
```
[x]   301  https://serverscrub.com/releases/latest.json  Location: https://www.serverscrub.com/releases/latest.json
[x] Restored /home/serversc/public_html/.htaccess from ....ss-bak-1795471433
```

### 2. status.html says "not published" for latest/VERSION when it could not read it — minor
**What happens:** when the CDN read is blocked (status 0), the "CDN extracted tree (latest/VERSION)"
row says `not published`, while every other row says `could not tell`. That is a claim it cannot
support. Pre-existing line (`status.html:250`, same in HEAD), but now that the page reads the CDN
cross-origin it is the default state until the CORS header is live, and Wasooli's new
could-not-tell handling missed this row.
**Expected:** `tree || unread(treeR)`, with `unreadCls`, like its neighbours.
**Evidence:** `docs/findings/screenshots/2026-11-23-site/status-desktop-1440.png`.

### 3. tests/test_site_redesign.py crashes when `bash` is WSL's stub — minor
**What happens:** from PowerShell, `bash` resolves to `C:\Windows\system32\bash.exe` (WSL, no
distro). The merge assertions get `execvpe(/bin/bash) failed`, then the script dies with
`IndexError: list index out of range` at line 318. 136/136 pass under Git Bash.
**Expected:** find Git Bash explicitly, or report "merge not exercised" and fail cleanly, not with a traceback.

### 4. Mobile hero install command breaks inside the URL — minor (cosmetic)
At 375 px the hero renders `https://serverscrub.com/releases/ge` / `t.sh`. Copy/paste is unaffected
but it looks like a typo in the one command a customer will copy. `overflow-wrap:anywhere` on that
`code`; prefer horizontal scroll like the lower code block, or a break before the URL.
**Evidence:** `index-mobile-375.png`.

### 5. Backup name has one-second resolution — note
Two changing merges in the same second write the same `.ss-bak-<epoch>`; the second `cp -p`
overwrites the first, so the original is lost. Not reachable in a real deploy (the probe and
checks take more than a second), so I am recording it, not asking for a fix.

## Judgement calls Wasooli asked about
1. **test_cpanel_menu_entry.php website block replaced — legitimate.** The old block pinned the
   website to the plugin's logo.png and palette. The user explicitly rejected that logo, and spec
   D2/D3 replace it on the website only. The new block still checks that the plugin logo is
   untouched, that the header uses a real file, and that the deploy manifest only lists files that
   exist. Nothing that still holds was weakened. Caveat for the user: this is the second hand-drawn
   SVG logo (an earlier one was rejected), and the website and plugin now carry different brands
   (OQ3). The user should look at the new mark before release.
2. **status.html "could not tell" — correct and in scope.** The spec's own failure-behaviour section
   requires it ("never a healthy or green state"). The banner, CDN tile and download tile all show
   neutral "Could not tell" from localhost. One row was missed (finding 2).
3. **Module counts dropped — fine.** No numbers remain. features.html has 16 module h3s in 4 groups.
   The WAF copy reads "whether it is blocking or only detecting". No `/serverscrub/code/`, logo.png,
   "minute", "trusted" or uptime strings.
4. **404 on /releases with no latest.json is a warning — verified, and safe.** With latest.json
   removed, the run warns and exits 0. With latest.json removed **and** a block that 301s /releases,
   it still rolls back (the 301 is not a 404), so the carve-out cannot mask a redirect.

## Visual / UX
Desktop is clean and credible: a strong condensed headline, one dark "faceplate" hero, restrained
blue CTAs, consistent header, footer and closing CTA on all five pages. It no longer looks like a
template. Honest weaknesses:
- Below the hero, the pages are grey-on-grey text columns with a lot of empty space. features.html
  (4.9k px) reads as a long document with no visual rhythm, illustration or screenshots.
- The hero's right panel (a dot grid with four dim rows) is abstract. Its "indicator lights" are
  barely visible.
- The wordmark is a thin monoline next to heavy condensed headings, so it looks lighter than the
  type around it.

Overall it is competent and trustworthy, not striking. It is a real improvement, but the user
should judge whether it meets "good looking".

## What passed
- **check-site.py** exits 0. test_site_redesign.py: 136/136 (Git Bash), including 12 seeded defects.
- **Acceptance 7 (Apache 2.4.37, real rules, merged by the real deploy-site.sh):** 78 checks passed.
  The redirect rules behave as specified:
  - `http://` apex → 301 `https://www/`.
  - `http://www/pricing.html?x=1` keeps its query string.
  - `https://` apex features.html → 301 www.
  - `https://www/` → 200 with `Strict-Transport-Security: max-age=31536000`. No HSTS over http or on cpanel.
  - `/releases/latest.json` → 200 with no Location on both schemes, with `ACAO: *`.
  - `/releases` → mod_dir 301 to `https://serverscrub.com/releases/`, apex not www.
  - `.well-known`, Host cpanel.serverscrub.com and Host 127.0.0.1 are not redirected.
  - `X-Forwarded-Proto: https` on :80 → 200, no loop. A POST to webhook.php is not redirected.
  - The www-disabled variant: https apex 200, http → `https://serverscrub.com/`.
  - **UpdateChecker::httpGet (the real class, via reflection)** reads latest.json as version 9.9.9.
    The control test, a redirected URL, comes back unreadable.

  The deploy's safety behaviour also held:
  - Without mod_headers or without mod_rewrite there is no 500.
  - The Apache error log is clean.
- **Acceptance 8:** `bash -n` is clean. A full root deploy from local source stages every file with no
  "missing from source".
  - Every published file, including status.html, favicon.ico, robots.txt, sitemap.xml and
    `.htaccess`, is `serversc:serversc`. `.htaccess` is 644, and htaccess.site is not published.
  - The block is prepended and the cPanel section is byte-identical, including the missing final newline.
  - A second run produces a byte-identical file, with "unchanged" and no new backup.
  - Real www probe: when DNS is removed it falls back to the apex and warns. When DNS is restored it
    goes back to an identical file.
  - Malformed markers (two BEGINs, or END-only) are refused: non-zero exit, file unchanged, pages
    still published.
  - The HTTPS-side rollback restores the backup byte-identical. With no prior file, it removes the file.
  - 5 backups are kept. CRLF files are handled and stay idempotent.
- **Browser:** these checks were run on all five pages.
  - One h1 per page and no skipped levels. Every img has alt. lang=en, a skip link, and canonicals
    are correct.
  - All internal links resolve. Zero console errors on the four marketing pages.
  - status.html logs only the expected CORS failures and renders could-not-tell, not placeholders.
  - No horizontal scroll at 360, 375 or 1440 px. The mobile nav keeps all four items visible
    (no toggle needed). A visible 2.4 px focus outline.
  - Contrast: worst body/footer text 5.77:1; ok 6.1, warn 5.9, bad 6.09, dim 7.07; buttons 6.75.

Screenshots: `docs/findings/screenshots/2026-11-23-site/`: `index-desktop-1440.png`,
`index-mobile-375.png`, `features-desktop-1440.png`, `pricing-mobile-375.png`, `status-desktop-1440.png`.

Handed to Wasooli: fix 1 (required for acceptance 7), 2 and 3. 4 is cosmetic. Then re-test with the
same harness.

---

# Retest — 2026-11-26 (Wasooli fixes + design pass, files dated 15:12-15:14)

**Verdict:** PASS WITH CAVEATS. No blockers, no majors. Caveats: findings R1 and R2 below, plus the
unchanged "Not tested" list (live status.html data needs the CORS header deployed; no real
cPanel/ea-nginx; Windows Chromium only).

## Earlier findings
| # | Was | Now | Evidence |
|---|---|---|---|
| 1 | major: http /releases redirect not caught | **fixed** | Harness section "retest 2026-11-26": http-only break of the /releases exemption rolls back (existing file restored byte-identical), removes a file that did not exist before, exits non-zero when the broken block is already live, still rolls back when latest.json is absent (404 carve-out does not hide the 301), and with `SG_FORCE_WWW=0`. A http-only `.well-known` break is also caught and rolled back. The good block passes all 12 new probes (apex+www x http/https x releases/.well-known/serverscrub) with zero warnings. |
| 2 | minor: VERSION row "not published" when unread | **fixed** | Preview from localhost: row now reads `could not tell`. |
| 3 | minor: test crashes under PowerShell | **fixed** | `tests/test_site_redesign.py` from PowerShell: 168 passed, 0 failed. |
| 4 | minor: mobile command breaks in URL | **fixed** | Hero command is one line, scrolls horizontally (index-mobile-375.png). |
| 5 | note: same-second backup collision | fixed, but see R1 | |

Harness totals: 88 passed, 2 failed — both failures are R1.

## New findings

### R1. A fast backup can reuse a just-pruned name and be deleted at once — minor
**What happens:** the collision fix steps forward from the current epoch to the first free name.
After pruning has deleted the oldest name, a later change in that same second gets that freed
(oldest) name, sorts first, and is pruned immediately. `merge_htaccess` then prints a
`BACKUP=` path that no longer exists; in a deploy, `rollback()` would say "No backup to restore"
and leave a failed block live.
**Reproduce:** seven changing `merge-htaccess` calls within ~1 s:
```
BACKUP=/tmp/ht.ss-bak-1795724674 ... 1795724679, then BACKUP=/tmp/ht.ss-bak-1795724674 (reused)
kept: 675=pre.3 676=pre.4 677=pre.5 678=pre.6 679=pre.7   -- pre.8 (the newest) is gone
```
**Expected:** the newest backup always survives pruning: take max(existing epoch, now)+1, or
prune by mtime, or prune before choosing the name and never pick a name below the newest.
**Why minor:** a real deploy does one merge per run and each run takes several seconds of curl
checks, so six changing merges inside the pruning window do not happen in practice. It is a
regression of the safety net introduced by the fix for note 5, so it should be fixed, not shipped
as a known hole.

### R2. preflight loses the mock-env suite's output (UnicodeDecodeError 'charmap') — minor, outside this spec
**What happens:** `scripts/preflight.py:159` runs suites with `capture_output=True, text=True`,
which on Windows decodes with cp1252. `tests/run-tests.sh` prints UTF-8 box-drawing (`╔═` =
`e2 95 90`; 0x90 is undefined in cp1252), so the reader thread dies, prints the traceback Wasooli
saw, and `r.stdout` becomes `None`. Identified by re-running preflight with `subprocess.run`
instrumented:
`DECODE-FAIL stdout in ['C:/Program Files/Git/bin/bash.exe', '...\tests\run-tests.sh'] rc=0`.
**Does it hide a real failure?** No, not today. `run_suite` judges on the exit code only, and
`run-tests.sh`'s EXIT trap exits 1 whenever FAIL>0, so a failing mock-env suite still fails
preflight. What is lost: (a) the pass summary (preflight prints "mock-env suite passed" with no
count, so a run that silently tested nothing would look the same), and (b) on a failure, every
diagnostic line. Steps that do `r.stdout + r.stderr` on failure would raise TypeError on a
`None` stdout. They fail closed, but with a traceback instead of the reason.
**Expected:** `encoding="utf-8", errors="replace"` on every `text=True` call in preflight.py.
Not a reason to hold this release.

## Port 8765
`127.0.0.1:8765` was still listening: PID 207928,
`python\python.exe -m http.server 8765 --bind 127.0.0.1`, started 15:12:50 today (Wasooli's
preview). It served the cwd on localhost only. **Stopped**; nothing listens on 8765 now. Preview
on 8900 (mine) also stopped.

## Contrast on the new dark bands (measured, 1440 px, computed colours)
| Pair | Ratio |
|---|---|
| band link "Installation guide" `#6e94ff` on `#1b2430` | 5.47 |
| band body / fine print `#a9b3bf` on `#1b2430` | 7.37 |
| band code comment on the darker code well | >= 9.89 |
| hero lede / fine `#a9b3bf` on `#1b2430` | 7.37 |
| hero primary button `#f6f7f8` on `#2747d0` | 6.75 |
| light pages, worst text (footer, code) | 5.77 |
All ≥ 4.5:1. Bands on index, features and install; pricing and status have none (fine).

## Browser pass (retest)
One h1 and no skipped heading levels on all 5 pages; every img has alt; none broken; no
horizontal scroll at 360/375/1440; mobile nav shows all four items; status.html renders
could-not-tell everywhere from localhost, and the only console errors are the expected CORS
failures. The four marketing pages have no scripts and no console errors.

## Design verdict (retest)
Clearly better than the first pass and now good, not just competent:
- the heavier wordmark finally holds its own beside the condensed headings;
- the hero channels now read as rack units with lit LEDs and fill their panel;
- the 6 px rail plus large bold section heads and the one dark band per page give the long pages
  a rhythm they lacked; the band breaks the grey-on-grey monotony.
Remaining weaknesses, for the user's judgement, not blockers: still no product imagery or
screenshot anywhere, so it sells by text alone; the hero panel floats with empty space above and
below it at 1440; the per-feature rack chips are tiny (about 28 px) and read as decoration
rather than meaning.

## Screenshots (overwritten, retest build)
`docs/findings/screenshots/2026-11-23-site/`: `index-desktop-1440.png`, `index-mobile-375.png`,
`features-desktop-1440.png`, `pricing-mobile-375.png`, `status-desktop-1440.png`.

Handed to Wasooli: R1 (fix before release). R2 can be a separate Z fix.

---

# Retest 2 — 2026-11-27 (R1 + R2 fixes; deploy-site.sh 15:37, preflight.py 15:41; pages unchanged since 15:14, so no new screenshots)

## R1 (backup pruning) — fixed
Docker harness: **94 passed, 0 failed**. The two earlier R1 failures pass (8 fast changes keep
the last 5 and the newest survives). New section "retest R1": 5 future-dated backups are seeded,
then 7 rapid changing merges run. The last reported `BACKUP=` exists and is the newest name, 5
are kept, and a broken deploy immediately afterwards rolls back to the pre-deploy file
byte-identical (`Restored ... from .ss-bak-1795726108`).

## R2 (preflight UTF-8) — fixed, verified redirected
`preflight.py > file 2>&1` from PowerShell/cmd: no UnicodeDecodeError or UnicodeEncodeError. The
mock-env summary now appears, `✔` included:
`mock-env suite (tests/run-tests.sh) passed -- All tests passed! ✔`. Redirected/piped is the
cp1252 path that used to crash. A real interactive console writes UTF-16 and never had the
problem; this tool can't drive one, so the "console" run was a PowerShell pipeline.

## But preflight does NOT pass on the current tree — blocker for packaging
Three sequential runs on 2026-11-26/27:
1. 15:55, run alone: **4 of 5579 regression assertions CRASHED**:
   `cdn_manifest_cache.py`, `release_mirror_verified.py`,
   `update_corroboration.py` ("an unreachable tags api is not an error (expected 0, got 1)"),
   and `update_stale_channel.py`. (An earlier pair of runs overlapped by my mistake and showed the
   same four; I discount those.) Each passes standalone (`test_cdn_manifest_cache.py` 24/0), and
   a direct `php tests/run.php` gave 5762/5762. This is the same flake Wasooli reported on
   2026-11-23. It looks network- or timing-dependent, not caused by this spec. But a gate that
   fails one run in two is not a gate, and its cause is unknown.
2. 2026-11-27, instrumented run: the four did not crash. Instead **"rebrand: no source file still
   refers to the old product name — /.claude/agents/mogambo.md"** failed, in the regression suite
   and again in the docker cPanel suite. `.claude/agents/{mogambo,dang,gogo,kancha,lotiya,teja}.md`
   were added 2026-11-27 13:29-13:31 by other work. mogambo.md line 21 says
   "internally cP-Defender / Sentinel Gate". This is not this spec's change, but preflight is red
   on the tree Gabbar would package.
3. PowerShell pipeline run (2026-11-27): the same four CRASHes again (5 of 5579), plus the rebrand
   failure. No decode or encode error; the ✔ summary prints. So the crashes reproduced in 2 of 3
   preflight runs, while standalone and direct `run.php` runs pass.

## Verdict
**FAIL for release (not for this spec).** The website change itself is clean: every finding is
fixed, the harness is 94/94 and test_site_redesign.py is 169/169 per Wasooli. **No green light for
Gabbar** until preflight passes on the tree to be packaged. Needed:
(a) the rebrand failure from the new agent files (exclude `.claude/` from the rebrand scan, or
reword mogambo.md — the user's/coordinator's call, since those files are not Wasooli's);
(b) the four intermittent update/CDN test crashes investigated, or explicitly accepted by the user
as a known flake.

Cleanup: one orphaned `serverscrub-test:php7.4` container from an aborted preflight was stopped.
No servers left running by me; port 8765 was already freed on 2026-11-26.

---

# Retest 3 — 2026-11-27 (tests/_bash.py, mogambo.md and FACTS.md reworded)

## The "flaky" crashes were the bash locator — fixed, not masked
`tests/_bash.py::find_bash()` skips WSL's System32/WindowsApps stub, tries the Git install found
via `git`, then Program Files, and only returns a candidate after `bash -c 'echo ss-ok'` succeeds.
It is correct. It is not a mask: the four tests keep the same SKIP-when-no-bash branch they had
in HEAD (that branch is unchanged, and it never fired in these runs). The locator only stops them
picking a bash that cannot run.
Proof, from PowerShell (`Get-Command bash` = `C:\Windows\system32\bash.exe`), with each test's
lookup swapped back to the old `shutil.which('bash')` vs the current file:

| test | old lookup | new |
|---|---|---|
| cdn_manifest_cache | rc=1, 18 passed / 6 failed | rc=0, 24/0 |
| release_mirror_verified | rc=1, 15 / 32 | rc=0, 47/0 |
| update_corroboration | rc=1, 19 / 66 | rc=0, 85/0 |
| update_stale_channel | rc=1, 2 / 29 | rc=0, 31/0 |

`tests/test_bash_locator.py`: 9/0. So the "2 of 3 runs" pattern was simply which shell launched
preflight. My Git Bash runs passed and my PowerShell runs failed. It was never timing.
(Temporary copies `tests/_shakaal_old_*.py` were created for this and deleted.)

## Preflight x3, back to back, from PowerShell
RUN 1 rc=0 262 s, RUN 2 rc=0 268 s, RUN 3 rc=0 260 s. Each one: `regression tests: 5771 assertions
passed`, `PREFLIGHT PASSED`. No SKIP, CRASH, rebrand, Decode/Encode or Traceback lines in any of
the three logs.

## Docker harness
See the final line below.
`docker/site-apache-test.sh` in `serverscrub-waf:live`: **TOTAL: 94 passed, 0 failed**.

## Cleanup
No containers running. Nothing listening on 8765 or 8900. All background tasks I started are stopped.

## Final verdict: PASS — green light for Gabbar
This holds for the current working tree on 2026-11-27. Every finding (1-4, note 5, R1, R2, the
bash-locator crashes, and the rebrand failure) is fixed and re-verified. There are no blockers and
no open findings.

Still not tested, to be stated at release:
- status.html against live CDN data. It needs the CORS header the deploy writes; that is
  acceptance 9, prod verification after release.
- Real cPanel/ea-nginx in front of Apache (OQ2). R20 rollback covers it on the real deploy.
- Rendering outside Windows Chromium.
