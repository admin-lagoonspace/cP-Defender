> **SUPERSEDED — not the verdict for any release.** This report was written
> against `386bca0` plus uncommitted working-tree changes, and it contains a
> finding Shakaal later corrected. The verdict that gated v4.36.0 is
> `2026-11-13-verdict-18d2ec2.md`. Kept for the record only.

# Test run — 2026-11-13

**Build:** `386bca0` ("Write up the quarantine incident work…"), 39 commits past
`8552261` (Release v4.35.1), **plus Wasooli's uncommitted mass-detection rework**
in the working tree (`backend/lib/MassDetection.php`, `backend/lib/Scanner.php`,
`backend/cron/scan.php`, `backend/lib/Database.php`,
`tests/test_mass_detection_bound.php`, `tests/test_mass_detection_no_halt.php`).
`VERSION` still reads `4.35.1`.

**Environment:** AlmaLinux 8.10, PHP 7.4.33 (and 8.2 for the upper bound),
sqlite 3.26.0, python 3.6.8, Docker 29.9.3.

**Verdict: FAIL** — 3 blockers. Two of them (firewall geo-block, WAF engine
claim) are nothing to do with this batch's headline work and would have shipped
unnoticed.

Because the rework landed under me mid-run, **everything about the
mass-detection bound below was tested against the working tree as of
~15:45 local, not against a commit.** Re-run `tests/test_mass_detection_no_halt.php`
and `tests/findings/shakaal_mass_detection_open.php` against whatever Wasooli
finally commits.

---

## Not tested

- **cpsrvd, WHM AppConfig, LiveAPI, the CGI wrappers.** Installed
  `--mode standalone`. cPanel-mode integration is proven only on a cPanel box.
  `install.sh` still exits non-zero after a successful standalone install
  because its self-test insists on the AppConfig, the CGI wrapper and the
  ConfigObj driver regardless of `--mode`.
- **Real ModSecurity under Apache.** Audit-log *parsing* is tested against
  real-shaped fixtures; rule evaluation and `SecRuleEngine` actually blocking
  are not. Finding 2 is partly shaped by that.
- **Real Exim.** `exim -bp` stubbed.
- **ClamAV.** Stubbed, EICAR only. So no finding below rests on a real
  signature match, and the planted ransom-note fixtures were *walked* but could
  not be *detected*.
- **Scale.** 8 seeded accounts, 1,645 files under `/home`. Not 132 accounts and
  not 154,323 findings — the 154,323 case is exercised as database rows, not as
  files on disk.
- **`quarantine restore` against a real 204 MB / 154,323-row quarantine.**
  Exercised with 5 hand-built rows.

---

## Findings

### 1. `quarantine restore --signature='*' --apply` defeats the unscoped-restore refusal and restored an attacker's webshell — blocker

**What happens:** `selector()` refuses a restore with no scope. It does *not*
check that the scope is **narrow**. A signature of `*` becomes
`threat_name LIKE '%'`, which matches every quarantined row in every job for
every account under every signature. One command, no dry run required, restored
a `{HEX}php.cmdshell.gifheader` webshell to `/home/victim/public_html/evil.php`
and exited 0.

The suppression code added in `04aefc1` refuses a signature prefix shorter than
eight characters for exactly this reason — "`{HEX}*` would switch off a whole
class of rules from six characters". The restore path, which is the one that
writes attacker code back onto a live docroot, has no such floor.

`--ext=md` alone is the same hole with a different flag: it passes the scope
check and covers every `.md` ever quarantined, across all jobs and accounts.

**Reproduce:** `bash tests/tools/restore-probe.sh` inside the container
(`docker compose -f docker/compose.yml run --rm --entrypoint bash shell -lc
'/usr/local/bin/entrypoint.sh install >/dev/null 2>&1; bash
/opt/serverscrub-src/tests/tools/restore-probe.sh'`). Section A is refused as it
should be; section B is not.

**Expected:** the same floor as a suppression. A wildcard that resolves to an
empty prefix must be refused; a scope consisting only of `--signature=<prefix>*`
or `--ext=` with no `--job`/`--account`/`--id` should require an explicit
second flag. The refusal text promises "'Everything' would put real detections
back as well as false ones" and then does precisely that.

**Evidence:**
```
──────── A. UNSCOPED restore (must be REFUSED) ────────
serverscrub: Refusing to restore without a scope. Name a job (--job=) … exit=1

──────── B. SCOPE BYPASS: --signature='*' with --apply ────────
Restored:        3 file(s), 64 bytes
Examined:        5 of 5 in scope
exit=0
webshell back on disk? YES-BAD
-rw-r--r-- 1 deepnest deepnest 20 Nov 13 20:29 /home/victim/public_html/evil.php
```

### 2. The Firewall page throws on every load, and "Save Geo Rules" silently removes every country block — blocker

**What happens:** `renderGeoGrid()` (`frontend/js/app.js:1955`) does

```js
const saved = (Database?.setting?.('geo_block_countries') || '').split(',').filter(Boolean);
```

`Database` is a PHP class. It does not exist in the browser, and `?.` does
**not** guard an *undeclared* identifier — it throws `ReferenceError`. So:

- the country grid never renders, and the exception escapes
  `loadFirewallStages()` as `page load failed: firewall`;
- `State.geoSelected` is therefore empty on every page load;
- clicking **Save Geo Rules** posts `[]` to `firewall/geo-block`, and
  `Firewall::setGeoBlock([])` rewrites `CC_DENY = ""` in the CSF config and
  runs `csf -r`;
- the operator gets a green toast reading `Geo block saved (0 countries)`.

`setGeoBlock()` also returns `['success' => true]` unconditionally — it checks
neither `file_put_contents` nor the `csf -r` result.

On a server with countries blocked, one visit to the Firewall page plus one
click removes the whole geographic block list and reports success. The page
looks entirely healthy; the only signal is the console.

**Reproduce:** open the panel, sign in, click **Firewall**, then
`read_console_messages`. The grid under GEOGRAPHIC BLOCKING is empty.

**Expected:** read the saved list through the API like every other panel, and
`setGeoBlock` must report what it actually wrote. An empty save on a non-empty
existing list should be confirmed, not silent — it is a removal of protection.

**Evidence:**
```
[error] page load failed: firewall ReferenceError: Database is not defined
    at renderGeoGrid (http://localhost:8777/js/app.js?v=4.35.1:1955:17)
    at loadFirewallStages (http://localhost:8777/js/app.js?v=4.35.1:1868:3)
```

### 3. The WAF card claims "ModSecurity is installed and logging matches" with no rule files, and prints a "not installed" message as the version — blocker

**What happens:** the WAF panel renders, simultaneously:

```
WAF ENGINE   Installed
ModSecurity is installed and logging matches, but not blocking them yet.
ModSecurity   installed package ea-apache24-mod_security2 is not installed
OWASP CRS     vunknown
...
The OWASP CRS directory … holds no rule files that could be read, so no
category counts can be shown.
```

Two defects behind it:

- `WAFInstaller::modsecVersion()` ends with
  `shell_exec('rpm -q --qf "%{VERSION}" ea-apache24-mod_security2 2>/dev/null')`.
  For a package that is not installed, rpm prints
  `package <name> is not installed` **on stdout** and exits 1. `2>/dev/null`
  redirects the wrong stream and the exit code is never checked, so that
  sentence is returned as the version string and concatenated after the word
  "installed".
- `crs_installed` is `crsPath() !== null`, which only tests that the directory
  exists. An empty CRS directory — the exact state `f1844fb` was written to
  clean up — reads as installed, so `ready` is true and the card asserts the
  engine is "logging matches" when there are no rules to match.

This is the `MODE = 'On'` class: a protection claim with nothing behind it.

**Reproduce:** `docker compose -f docker/compose.yml up -d panel`, sign in, open
**WAF**, `get_page_text`.

**Expected:** check rpm's exit status; return `null` and render "unknown"
rather than an error message. `crs_installed` must mean "readable rule files
are present", which is what the categories panel already measures correctly two
cards below.

### 4. A confirmed-real mass detection still leaves the files in place, and there is no supported way to finish the clean-up — major

**What happens:** the rework correctly removes the halt and correctly identifies
the 30 Apr shape as `mass-identical`. But `allow()` returns `act => false`
regardless of verdict, so past 500 files the remaining ~153,800 genuine ransom
notes are flagged and left on disk — which is the behaviour the brief said must
not happen.

Flag-and-let-a-human-decide is a defensible call at this scale. What is not
defensible is that there is **no lever for the human**. The CLI has
`quarantine restore` to undo a clean-up and nothing at all to proceed with one:
no `quarantine apply`, no bulk action on flagged findings, and
`scan_mass_signature_max` appears in no CLI command and no UI control
(`grep -rn scan_mass_signature_max backend/ frontend/` → `Database.php:399`, the
default row, and `MassDetection.php:127`). The only route is hand-editing the
settings table and re-running a 59-hour scan.

**Reproduce:**
`docker compose -f docker/compose.yml run --rm --entrypoint bash shell -lc 'cd /opt/serverscrub-src && php tests/findings/shakaal_mass_detection_open.php'`
— cases 1, 3 and 6.

**Expected:** either destructive action continues for a `mass-identical`
verdict, or the operator gets a reviewed, scoped command to act on what was
flagged. Shipping the undo without the do means the next real incident is
handled by a `sqlite3 UPDATE`.

### 5. `varied-content` is not a conclusion the hash evidence supports — major

**What happens:** `weigh(2000, 2000, 1)` returns `varied-content`, and
`test_mass_detection_no_halt.php:212` now asserts that. The operator is then
told "THE MATCHED FILES DIFFER FROM EACH OTHER, which is what a signature
matching ordinary files looks like" and pointed at `signatures suppress add`.

All-distinct is the 10 Nov changelog shape. It is *also* the shape of a ransom
note that embeds anything per-file — a counter, a victim id, a timestamp, the
account name in the body. Under full-file sha256 those two are
**indistinguishable**, so naming one of them is a claim the evidence does not
carry, and the suggested next step disables detection of a live infection.

`mass-identical` is sound in both directions: identical files at scale really
are a mass event. `undetermined` is sound. `varied-content` is the one verdict
that can only ever be a guess, and it is the one whose advice is dangerous.

The clustered case is now handled correctly — `CLUSTERED_SHARE = 0.10` catches
the per-account note (`weigh(600, 4, 150)` → `mass-identical`), and
`weigh(500, 251, 250)` now returns `undetermined`. Both of those were wrong
earlier today and are fixed; this is the remainder.

**Reproduce:** `php tests/tools/weigh-probe.php` in the container, row
"ransom note with a trailing counter (all distinct)".

**Expected:** `undetermined` for all-distinct, with the alarm saying the
contents differ and that this is consistent with *either* a noisy rule or a
per-file-unique artefact. Keep the `suppress add` suggestion only where the
evidence is actually one-sided.

### 6. `MassDetection::lastTrip()` is read by nothing — major

**What happens:** `grep -rn "MassDetection\|lastTrip\|scan_mass_last_trip\|mass_detection" backend/api backend/cli frontend cpanel whm`
returns **nothing**. The class docblock says the trip is recorded "for the CLI,
the UI and the operator"; `lastTrip()` and `clearLastTrip()` are dead outside
the test suite. The Scanner panel has a suppressions card, a verdicts card and
an exclusions card, and no mass-detection card — I confirmed its absence in the
rendered page.

The operator is not left blind — `Logger::event('mass_detection', 'critical', …)`
does reach the Events panel — but the designed surface does not exist, and a
`critical` event in a list is not the same as the panel telling you a bound
tripped and on what evidence. `04aefc1`'s own argument applies here: "a hole in
the defence that nobody can see is indistinguishable from a scanner that has
stopped working."

**Expected:** a card, or at minimum `serverscrub status` reporting the last
trip. Also drop `clearLastTrip()` or give it a caller.

### 7. A quick scan still covers `public_html` only, and misses a docroot that is not `public_html` entirely — major

**What happens:** `Scanner::accountsForScan()` builds
`'docroot' => is_dir($home . '/public_html') ? $home . '/public_html' : null`.
Nothing reads `documentroot` from `/var/cpanel/userdata`, although
`CMSGuard.php:137` does exactly that.

Measured in the container, on 8 seeded accounts and 1,645 files under `/home`:

| | files read | planted notes found |
|---|---|---|
| `scan --quick /home` | **55** | 0 of 6 |
| `scan --full /home` | **1,343** | 0 of 6 |

I planted 6 files in `$HOME`, `.cache/` and `tmp/webalizer/` — where the real
30 Apr artefacts lived. The full scan walks those paths (1,343 of 1,645; the
302-file gap is the virtfs tree, pruned). The quick scan reads 55 files and
never goes near them. For the `deepnest` account, whose userdata records
`documentroot: /home/deepnest/sites/live/current/public` and which has no
`public_html` at all, the quick scan's docroot is `null` — it covers **nothing**.

*Neither* scan detected the planted notes, but that is the stubbed ClamAV, not
a coverage result; do not read the "0 of 6" column as a product failure.

No change extending quick-scan coverage has landed, so this is unchanged from
the incident, not a regression in this batch. **On cost:** the full sweep of
`/home` took **4 seconds** at load 0.43 with virtfs present, and the prune is
shared between both walks (`getPhpFiles()` builds its regex from
`SCAN_SKIP_DIRS`), so the multiplicative trap does not fire here. That is 1,645
files, not a 132-account server — the shape is right, the magnitude is untested.

### 8. `serverscrub scan` silently ignores unknown flags — minor

`--type=full` is accepted and discarded (`elseif ($a[0] !== '-')` — anything
starting with `-` that is not `--full`/`--quick` falls through), so an operator
asking for a full scan gets a quick one. The JSON output does honestly report
`"type": "quick"`, which is the only reason this is minor. Also note
`$a[0]` on an empty argument is an uninitialised string offset at 7.4.

### 9. The dashboard scanner card's static markup is still the green tick — minor

`frontend/index.html:458` and `:464` are `badge badge-green` / `Protected` /
`✅` / `Last scan: —` as literal markup. The topbar pill was given a truthful
initial state in `c9d2a4d`, with a comment explaining why; the card it was
copied from was not.

**Narrower than it first looks, and I checked before writing it up:** a login
overlay covers the dashboard when unauthenticated, and `app.js` overwrites the
card on *both* the data path (→ "No scan yet") and the API-failure path (→
`badge-red`, "API unreachable"). So it is visible only in the gap between login
and the first `dashboard/stats` answer. Fix it for the same reason the pill was
fixed, not because it is currently reachable in a damaging way.

### 10. Two 404s on every panel load — minor

`GET /config.js` → 404 (aborted) and `GET /serverscrub.cgi?r=auth/status` → 404
before falling back to `api.cgi`. Both have working fallbacks in standalone
mode, both are noise in an operator's browser console and in the access log.

### 11. The database file is 0644 root:root — minor

`/usr/local/serverscrub/database` is `700 root:nobody` and
`/home/.serverscrub/quarantine` is `700 root:root`, both as specified. The
database *file* inside is `644 root:root`. Not reachable — the 0700 directory
blocks traversal — but the file holds threat paths, settings and the licence
key, and 0600 costs nothing.

---

## What passed

- **The regression test for the 154,323-file case exists and is not vacuous.**
  `tests/test_mass_detection_no_halt.php` is 44 passing assertions against the
  current code. Replayed against `2e160dc`'s `MassDetection.php` it fails hard
  and early — "THE SCAN IS NOT HALTED… expected 'running', got 'halted'",
  "expected '', got 'halted by the mass-detection bound: …matched 154323
  files'", plus six more. It genuinely encodes the behaviour change.
- **The halt is gone**, in the code and in the operator-facing text. No
  `halt`/`cancel` of a scan remains in `MassDetection`; the alarm says "THE SCAN
  IS STILL RUNNING"; the sentence "evidence about the signature" — shown for a
  100%-correct detection — is gone.
- **The identicality verdict reads 30 Apr correctly.** 154,323 matches of one
  distinct file → `mass-identical`, with "do NOT suppress the signature" in the
  reason. The blind case (no recorded hashes) returns `undetermined` and says
  "No file content hash was available", rather than guessing.
- **`quarantine restore`, everything except the scope floor.** `--apply` is the
  only thing that moves a file; a bare unscoped restore is refused; a hash
  mismatch is reported as **FAILED**, not skipped; a file that exists again at
  the original path is **skipped, never overwritten**; ownership came back as
  `deepnest:deepnest` inferred from the directory, **not** `root:root`; the
  legacy quarantine directory is searched and a row with no `quarantine_path`
  was found and restored from it; the report is restored / skipped-with-reason /
  failed-with-reason with examples, and names where it looked.
- **PHP 7.4 floor and the 8.2 ceiling.** Both images build; parse gate clean at
  7.4.33; **4,660 assertions pass, exit 0**, on both streams. No `match()`,
  no `str_contains`/`str_starts_with`/`str_ends_with`, no `?->`, no attributes
  anywhere in `backend/` or `frontend/`.
- **The harness can fail.** Verified rather than assumed: a deliberately
  failing test gives `run.php exit: 1`.
- **Upgrade 4.35.1 → candidate.** `PRAGMA integrity_check` → `ok`,
  `foreign_key_check` clean, `waf_exclusions` present, the settings canary
  survived, db dir `700`, `db-check` → `ok: yes, problems:` empty, and the new
  `waf exclude` CLI works against the upgraded database.
- **Concurrency.** Scan + scheduler + 25 CLI invocations against one sqlite
  file: no `SQLITE_BUSY`, no locked errors, no WAL growth,
  `PRAGMA integrity_check` → `ok` after.
- **virtfs pruning.** 0 findings under `/home/virtfs`; the full sweep read 1,343
  of 1,645 files, the 302-file difference being the pruned tree. Both walks
  build the prune from the same `SCAN_SKIP_DIRS`.
- **Empty states on the Scanner panel.** "No scans have run yet", "No threats
  found. Run a scan to check your server.", "Nothing marked yet.", and — the
  one that matters — "No signatures are suppressed. Every signature is
  reported." as a string distinct from an unreadable list. None of them green.
- **Controls respond.** Every Refresh/Reload clicked; the threats table shows
  `Updated 3:35:37 PM`, the scanner-log refresh answers within a second. All 37
  `api.cgi` calls returned 200.
- **The WAF MODE tile reads `Unknown`**, not `On`.

---

## Artefacts

- `tests/findings/shakaal_mass_detection_open.php` — findings 4 and 5 as
  assertions. Deliberately **outside** `tests/test_*.php` so it does not turn
  the suite red for unrelated work; run it directly.
- `tests/tools/restore-probe.sh` — finding 1.
- `tests/tools/weigh-probe.php` — finding 5.
- `tests/tools/coverage-probe.sh` — finding 7.
- `tests/tools/resource-probe.sh` — permissions, concurrency, bounds.
- `tests/tools/MassDetection.2e160dc.php` — the old halting class, kept for the
  non-vacuity replay.
- `tests/ui/README.md` — extended with the 2026-11-13 pass.
