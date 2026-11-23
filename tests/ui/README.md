# UI pass — driving the panel in a browser

Run against the container, not the developer's machine:

```bash
PHP_STREAM=7.4 docker compose -f docker/compose.yml up -d panel   # :8777
```

Sign in with the credentials `docker/entrypoint.sh` sets (`admin` / the fixed
`SG_ADMIN_PASS` in that file — fixed so a browser-driven run is repeatable).

Prefer `read_page` and `get_page_text` over screenshots: they assert on text and
structure rather than pixels, and they do not need the pane visible. For every
panel below: load it, read it, click its controls, then check
`read_console_messages` and `read_network_requests`. **A clean-looking page with
a 500 in the network log is a finding.**

## Known environment noise — not findings

- `GET /config.js` → 404. Expected in the container.
- `GET /serverscrub.cgi?r=auth/status` → 404, then `api.cgi` → 200. The frontend
  probes for the cPanel-mode endpoint first and falls back.

Everything else in the console or network log is a finding until proven otherwise.

---

## The rule that governs every row below

**Nothing is a failure state the UI must not dress as success.** Zero installs,
zero threats, zero events, an unreadable source, a sweep that could not run — all
of these must read as *absent* or *unknown*, never as healthy. The WP sweep
reporting "Read 0 of 0 installs" in green is the canonical defect; so is a MODE
tile whose text is hardcoded. For every value shown as fact, find where it comes
from: grep `frontend/js/app.js` for hardcoded status strings and treat each one as
a candidate.

---

## Scanner

**Must be present**

- Quick / Full / Custom scan selector, Start Scan, Refresh, Update Sigs.
- SCAN EXCLUSIONS listing the automatic exclusions, including `/home/virtfs` and
  the `cache` / `.cache` blind-spot note.
- SCANNER LOGS table with its column headers.
- With no scans ever run: `No scans have run yet` as plain text.
- With no threats: `No threats found. Run a scan to check your server.`
- When the scheduled scan was last refused, a card reading
  *"The scheduled scan did not start. Last refused Nm ago: <reason>"* plus the
  blocking job's id and age. **This must render when there is no scan running** —
  that is the early-return path in `adoptRunningScan()` and the case the
  2026-11-22 incident actually needed. Arm it by populating
  `scan_schedule_refused_at` / `_why` / `_job` / `_job_started` in `settings`.
- A reconciled job in SCANNER LOGS shows `interrupted` in red with its
  `stop_reason` in the dim parenthesis beside it.
- When liveness could not be established (no readable process table), a card
  saying so, naming what could not be read. Never silence, never health.

**Must be ABSENT**

- Any green or "Protected"-style treatment on a zero-result sweep.
- A progress card, Stop button or "running" status when `scan_jobs` holds no
  in-progress row.
- A refusal card when `scan_schedule_refused_at` is 0 — the card is created only
  when there is something to say and must be removed from the DOM otherwise.
- A refusal card claiming a job is "in progress" when that job is finished or
  absent. (Open finding, 2026-11-23 run, item 3.)
- A "paused for a backup" claim when `backupRunning()` is empty. (Open finding,
  item 2.)
- Any status string that is not traceable to an API field.

**Controls to click**

Start Scan, Stop, Refresh (SCANNER LOGS), Reload (Not malware / Suppressed
signatures / Exclusions), Save exclusions, "Would this be scanned?", Update Sigs.
Each must respond visibly within a moment — the scanner-log refresh button once
appeared to do nothing purely because there was no feedback — and what it claims
to change must actually change in the database.

---

## Dashboard

**Must be present**

- Files scanned, threats detected, firewall blocks, WAF events tiles.
- RECENT SECURITY EVENTS with severity / type / source / target / time / action.
- After a reconcile, a `warning` severity event naming the job id and the reason.

**Must be ABSENT**

- `—` or `0` presented as a positive verdict. "Protected" must be derived from
  something, not printed unconditionally.
- A tile still reading `Loading…` after the page settles — that is a failed call
  wearing a neutral face; check the network log.
- A coverage percentage of 0% shown without any indication that nothing has run.

---

## WAF

**Must be present**

- The engine mode, read from the file the product actually writes.
- Exclusions list, with scope (server-wide vs narrowed) stated per row.

**Must be ABSENT**

- `action` rendered as a constant. It was the literal string `'block'` on every
  row while the engine sat in DetectionOnly.
- A MODE tile set by `textContent = 'On'`.
- Two mode controls that write different files and disagree on screen — set the
  mode from one and confirm the other reflects it.
- "Applied" where the container reports `applied: no` / `mode: unknown`.

---

## Firewall

**Must be present:** blocked list; ServerScrub's own blocks and CSF's `CC_DENY`
reported *separately*, never merged.
**Must be ABSENT:** a blocked address in the table when the backend refused the
block (the dishonest row); an "emptied" confirmation for a list the product
declined to empty.

---

## CMS / WordPress

**Must be present:** install count from the API; findings listed as open for an
operator to judge.
**Must be ABSENT:** a green toast on a zero-install sweep; "Read 0 of 0 installs"
as success; fewer read than found with no visible reason.

---

## Real-Time Monitor

**Must be present:** watch count, engine, files checked, detections.
**Must be ABSENT:** `Checking…` as a terminal state; "Watching …" with no path;
a disabled daemon reported as a clean run rather than as skipped.

---

## After every panel

```
read_console_messages  onlyErrors: true
read_network_requests
```

Then, because six writers share one sqlite file:

```bash
docker compose -f docker/compose.yml exec -T panel \
  php /usr/local/serverscrub/backend/cli/serverscrub.php db-check
docker compose -f docker/compose.yml exec -T panel \
  sqlite3 /usr/local/serverscrub/database/serverscrub.db 'PRAGMA integrity_check;'
```

## Reproduction probes

`tests/probes/` holds the harnesses from the 2026-11-23 run. They are written
against the *installed* tree at `/usr/local/serverscrub` and real `/proc`, and are
meant to be run inside the container:

| probe | what it establishes |
| --- | --- |
| `probe_stale_snapshot.php` | the cached `procSnapshot()` judging a live worker `dead`, in one process |
| `probe_scheduler_tight.sh` | the same thing end to end through a production-shaped scheduler tick |
| `probe_double_start.php` | the one-scan-at-a-time cap failing as a result |
| `probe_heartbeat.php` | `progress_at` advancing per batch during a real sweep |
| `probe_pause_gate.php` | `scan_paused_for_backup` turning a `stalled` verdict into `paused` |
| `probe_stuck_pause_flag.php` | that flag surviving a reconcile pass with no rows to close |
| `probe_refusal_staleness.php` | the refusal card outliving the job it names |
| `probe_wrong_pgid.php` | that the stall path does not signal an unrelated process group |
| `probe_test_headroom.php` | the remaining headroom in `test_scan_concurrency.php:307` |
