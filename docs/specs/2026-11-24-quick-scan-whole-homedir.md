# Quick scan covers the whole cPanel home directory

**Asked for:** "i want to change our definition of Quick Scan in settings. Quick scan should be scanning everything inside a cpanel user's directory and not just public_html. make this change happen and get me a release. Make sure entire team is not wasting tokens."
**Status:** ready-for-shakaal
**Size:** Z (changes the behaviour of a shipped scan type; no new setting, no new architecture)

Builds on, and supersedes Item 1 of,
`docs/specs/2026-11-13-quick-scan-blindspot-and-mass-detection-bound.md`.
That spec widened quick to `$HOME` + dotdirs; this one widens it to the whole
home directory. Its Item 1 resource bounds (file-count, depth, wall-clock caps)
and its `.cache` prune fix are reused here by reference, not restated. Item 2
(mass-detection bound) is unaffected and stays a separate piece of work.

## What the user is actually trying to achieve

Malware on this server was found outside `public_html` (the qTox dropper at
`/home/officialwebspace/.cache/.<41 hex>`, the bgkgvs web shell context). A
"quick" scan that only reads web roots tells the operator an account is clean
when it has not looked where compromises actually lived. The user wants quick
to mean "every account, all of it" while still being meaningfully faster than
full.

## What exists today

- `backend/lib/Scanner.php:1273-1284` — `resolveScanPaths('quick')` returns each
  account's `docroot` (`public_html`) only. Docblock at `:1255` says so.
- `backend/lib/Scanner.php:1710-1724` — `SCAN_SKIP_DIRS` prunes `cache` and
  `.cache` by name at every depth, for both `walkFiles()` (`:1768`) and
  `getPhpFiles()` (`:2181-2187`). So even full scans miss `~/.cache/`.
- `frontend/index.html:1609-1611` — Settings "Scheduled scan type" select;
  `frontend/js/app.js:1112` describes quick as "web roots".
- No mtime, size, or extension filter exists anywhere in the scanner; quick and
  full differ only in path set.

## Decision: what makes quick quicker than full

*Amended 2026-11-24 by the user:* "i want quick scan to scan everything,
inside user directory that means mail too".

**Quick = every account's home directory, entire (mail, backups, archives,
`node_modules`, `.git` included), under per-account caps, reporting a capped
account as "incomplete", never "clean". Full = every configured root, entire,
uncapped.** Same signatures and engine. The caps are now the only difference.
Inside a home directory nothing is pruned by name, for either type; only
`virtfs`, `.snapshot`, `.zfs`, `.trash`, `.cagefs` and ServerScrub's own dirs
stay pruned (they are not customer content).

Rejected alternatives:
- *mtime window (changed since last clean scan):* no per-file baseline exists
  (new state = Y-sized), and attackers backdate mtimes; a security product must
  not trust a value the attacker controls.
- *Signature subset:* signature cost is per file; file count is the 57h driver,
  so this saves little and silently weakens detection.
- *Extension/size filter:* the qTox dropper had no extension. Would recreate the
  blindspot this spec exists to close.

## Requirements

1. `resolveScanPaths('quick')` returns each cPanel account's home directory
   (from `listAccounts()`), not its docroot. An account with no `public_html`
   is included.
2. Quick scans exclude nothing inside a home directory. The by-name prunes of
   `node_modules`, `.git`, `.svn`, `cache`, `.cache` in `SCAN_SKIP_DIRS` do not
   apply under an account home, for quick or full (full must never see less
   than quick).
3. `cache` / `.cache` are removed from the unconditional `SCAN_SKIP_DIRS` prune
   (prior spec Item 1 req 5). `.cache` inside a home directory is scanned by
   both quick and full. If a narrower cache prune is kept (e.g. a WordPress
   page-cache path), it must be path-anchored, not a bare name.
4. `virtfs`, `.snapshot`, `.zfs`, `.trash`, `.cagefs` and ServerScrub's own
   directories remain pruned for both types.
5. Per-account caps from the prior spec (file count, depth, wall-clock) apply to
   quick. A cap hit is logged with the account name and the cap, and the
   account's result is reported as "incomplete", never "clean".
6. Operator-facing text describing quick (WHM scan-type select, Settings
   select, `app.js:1112` summary, CLI `--help`, `resolveScanPaths` docblock)
   says "all account home directories, including mail, with per-account time
   and file limits" — no remaining "web roots" wording.
7. The scan's `note` reports the account count and how many hit a cap, e.g.
   `132 home dir(s), 3 incomplete`.

## Explicitly out of scope

- New settings or UI controls for configuring the exclude list.
- mtime/incremental scanning.
- Any change to full or custom scan scope beyond the `.cache` prune fix.
- Item 2 of the prior spec (mass-detection bound).
- Changing the default schedule on prod.

## Failure behaviour

- No accounts found: fall back as today, with the existing "scanning in full"
  note.
- Home dir unreadable or missing: skip that account, log it, count it, mark the
  scan result non-clean ("N accounts not scanned").
- Cap hit: as req 5 — "incomplete", never "clean".

## Resource bounds

- Per-account and whole-sweep caps: as numbered in the prior spec's Item 1
  "Resource bounds" 1-3. Wasooli must give the numbers in code; defaults
  proposed, raised because Maildir stores one file per message: 1,000,000
  files / account, depth 25, 60 min / account, 20 h / sweep (must fit a daily
  schedule; full took 57h41m). These figures are guesses, not measurements.
- No content read beyond what the existing scanner reads per file.
- `virtfs` pruned (req 4) — without it the walk is multiplicative.

## Acceptance criteria

Demonstrated in `docker/compose.yml`, not by source assertions.

1. Fixture account with a dropper at `$HOME/.cache/.<41 hex>`, nothing in
   `public_html`: quick scan finds it. Full scan finds it.
2. Fixture droppers in `$HOME/`, `$HOME/tmp/`, `$HOME/.cphorde/`,
   `$HOME/public_html/vendor/`: quick finds all four.
3. Same dropper placed in `$HOME/mail/`, `$HOME/backup-x/`,
   `$HOME/public_html/node_modules/` and `$HOME/.git/`: quick and full both
   find all four.
4. Account with no `public_html`: included in quick's path set.
5. `/home/virtfs/<acct>/...` copy of a dropper: never reported by either type.
6. Each cap is shown firing on a fixture and produces "incomplete", not "clean".
7. No UI or CLI string still describes quick as "web roots" (grep returns 0).
8. `scripts/check-version-bump.sh` passes for a Z bump (4.37.10 -> 4.37.11).

## Open questions

- With mail in scope, the cap figures are even less tested. Mail-heavy
  accounts may hit them every run and show "incomplete" daily, and a
  132-account sweep may not fit 20 h. Prod is not reachable from dev; the
  first scheduled run after release must be checked and the caps tuned from it.

## Wasooli hand-off (2026-11-24)

Branch `feat/quick-scan-whole-homedir` (worktree off `main`).

- `Scanner::resolveScanPaths('quick')` returns every account's `home`; note
  `N home dir(s)`; fallback note `no accounts found, scanning in full`.
- `SCAN_SKIP_DIRS` no longer lists `node_modules`, `.git`, `.svn`, `cache`,
  `.cache` (both walks, all types). `virtfs`, `.snapshot`, `.zfs`, `.trash`,
  `.cagefs`, `proc`, `sys`, `dev`, own dirs remain.
- Bounds: `QUICK_MAX_FILES` 1,000,000 (files walked), `QUICK_MAX_DEPTH` 25,
  `QUICK_ACCOUNT_SECONDS` 3600, `QUICK_SWEEP_SECONDS` 72000. Applied only when
  the job type is `quick`, inside `walkFiles()` and `getPhpFiles()`.
- The per-path worker loop moved from `cron/scan.php` into
  `Scanner::runPaths()`; end status into `Scanner::finalStatus()`. A capped,
  missing or unreached account makes the job `incomplete` with the reason in
  `stop_reason` (`N of M home dir(s) incomplete: acct: bound; ...`).
- UI: Settings hint under "Scheduled scan type", scan target label, amber
  `incomplete` in the scan log, "Scan incomplete" toast; CLI `--help`.

Decisions the spec left open:
- Req 7's "N incomplete" is only known at the end, so it is in `stop_reason`,
  not the start-time note.
- "Unreadable" = `!is_dir || !is_readable` before the walk. A subdirectory
  unreadable mid-walk is still silently skipped (pre-existing behaviour).
- Legacy cron mode `scan.php quick` now resolves paths via
  `resolveScanPaths('quick')` instead of the first scan root.

Existing tests changed because the requirement or the code location changed
(not to make them pass): `test_scan_types.php` (quick = homes),
`test_scan_skip_virtfs.php` (node_modules now walked),
`test_scan_concurrency.php`, `test_scan_stop.php`,
`test_mass_detection_bound.php` (loop/status moved; the last two now assert
behaviour of `finalStatus()`).

Not done / for Shakaal:
- Without ClamAV the pattern engine still only reads files
  `Heuristics::shouldInspect()` accepts, so an extensionless `~/.cache/.<hex>`
  is walked but not read. Out of scope; flagging.
- `getPhpFiles()` matches the prune regex against the absolute path, so an
  account literally named `dev`, `sys` or `proc` is skipped entirely
  (pre-existing).
- Dashboard "files scanned" reads the last `done` job, so it ignores
  `incomplete` ones.
- The cap figures are guesses; check the first prod run.
