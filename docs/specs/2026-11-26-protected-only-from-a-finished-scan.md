# "Protected" only from a scan that actually finished

**Asked for:** "a last job that ended `cancelled`, `failed` or `interrupted` still shows green "Protected", with pill text "The last scan finished and nothing is open". That's false: the scan did not finish." (problem as handed over by the orchestrating agent; user's own words not available)
**Status:** ready-for-shakaal
**Size:** Z (fix to the shipped dashboard card and status pill)

## Work location
Do this in a **separate git worktree off `main`** (e.g. `git worktree add ../cP-Defender-wt-protected main -b fix/protected-from-finished-scan`). The main tree holds other people's uncommitted work, and its `frontend/js/app.js` differs from `main` (it lacks the 4.37.11 `incomplete` branch). Line numbers below are from `main` (3b04217, v4.37.11).

## What the user is actually trying to achieve
Green must mean "a scan looked at everything recently and nothing is open". Today it means "the newest job row has no open threats", whatever happened to that job.

## What exists today
- `backend/lib/Scanner.php` `getStats()` (~line 3801): `last_scan` = `SELECT * FROM scan_jobs ORDER BY id DESC LIMIT 1`, any status. Status values: `running`, `done`, `incomplete`, `cancelled`, `failed`, `interrupted`.
- `frontend/js/app.js` `topStatusFor()` (~664-687): unknown, never (no `finished_at`), threat, partial (`incomplete`), else clean.
- `frontend/js/app.js` card (~841-880): same order, same rule.
- Update-time cancels: jobs get `cancelled (stopped by the X update)`. `backend/cron/scheduler.php` `resumescan` (~669) starts a **new** job, so after a resume the newest row is `running`.
- Latent consequence of the same root cause: while any scan is `running`, the newest row has no `finished_at`, so both the card and the pill show "Not yet scanned" on a server scanned many times. This spec fixes that too.

## Decisions
1. **Reuse the amber `partial` treatment**, with its own wording. Do not add a new CSS state. "Did not finish" and "hit a limit" are the same claim to the operator: the scan did not cover everything. The visual stays amber. The text says which one happened.
2. **Green comes from the newest `done` job**, and only while it is **at most 8 days old** (the age is computed by the server). This means a routine update-cancel followed by a resume does not alarm: yesterday's `done` scan keeps it green. 8 days covers a weekly schedule plus a day of slack.

## Requirements
1. `getStats()` additionally returns `last_done_scan`: the newest job with `status='done'`, with `id`, `finished_at`, `scan_type`, `scan_path` and `age_secs` (server `time()` minus `finished_at`). It is `null` if there is none. It also returns `last_finished_scan`: the newest job with `finished_at` set, whatever its status. `last_scan` keeps its current meaning, so its other callers are unchanged.
2. The pill and the card use one decision, in this order:
   a. threat count unreadable: **unknown** (as today).
   b. open threats > 0: **threat** (as today).
   c. no job ever finished and none running: **never**, "Not yet scanned" (as today).
   d. `last_finished_scan.status === 'incomplete'`: **partial**, "Last scan incomplete" (as in 4.37.11).
   e. `last_done_scan` exists and `age_secs <= 691200` (8 days): **clean**, "Protected" / "No open threats". The title names the time of that scan. If a later job ended `cancelled`/`failed`/`interrupted`, or one is running, the title also says so, for example "No open threats as of the complete scan 6h ago. A later scan was cancelled (stopped by the 4.37.12 update)." The colour stays green.
   f. the newest finished job is `cancelled`/`failed`/`interrupted`: **partial**. Card: "Last scan did not finish", badge "Not finished". Pill: "Last scan did not finish". The title gives the status and reason, and the age of the last complete scan or "no complete scan on record".
   g. otherwise, when the last `done` scan is older than 8 days: **partial**, "Last complete scan N days ago".
   h. only `running` jobs, none finished: **never**, but the title reads "First scan in progress".
3. The string "The last scan finished and nothing is open" is only shown when it is true, which means the newest finished job is `done`. Otherwise the clean title uses the wording in 2e.
4. The card and the pill can never disagree: both come from the same function.

## Explicitly out of scope
- Whether a quick scan of one account should earn server-wide green. Any `done` job counts, as today.
- Making the 8-day threshold configurable.
- Changes to the resume mechanism or to the Scan Log.

## Failure behaviour
- `last_done_scan` missing from the payload (old backend, or a failed fetch): treat it as no complete scan, which means amber or never, not green.
- `finished_at` unparsable or in the future (`age_secs < 0`): it does not count as recent. Fall through to f or g.

## Resource bounds
Two extra indexed single-row queries per `getStats()` (`WHERE status='done' ORDER BY id DESC LIMIT 1`, `WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1`). No filesystem access.

## Acceptance criteria
Extend `tests/test_top_status_pill.php` to cover each case, and exercise them in docker (`docker/compose.yml`) by seeding `scan_jobs`:
1. Newest job `cancelled (stopped by the X update)`, a `done` job 1 day old, 0 threats: green, and the title mentions the cancelled scan.
2. Same, but the newest job is `running` (resumed): green, not "Not yet scanned".
3. Newest finished job is `failed`, `interrupted` or `cancelled` (three cases), and there is no `done` job within 8 days: amber "Last scan did not finish". Never green.
4. The only `done` job is 9 days old and the newest job is `done`: amber "Last complete scan 9 days ago".
5. Newest finished job is `incomplete` while a recent `done` job exists: amber "Last scan incomplete". The 4.37.11 behaviour is kept.
6. No jobs at all: "Not yet scanned". Only a running job: "Not yet scanned" with the title "First scan in progress".
7. Open threats > 0 in any of the above: red threat state.
8. `last_done_scan` absent from the payload: not green.
9. The card and the pill give the same state for every case above.

## Open questions
None blocking. These assumptions are labelled so Shakaal can check them:
- The 8-day window is chosen to fit weekly schedules. Prod runs daily, so a stricter 48h would also work.
- Amber, not red, for a scan that did not finish.

## Wasooli: what was done (2026-11-26)
- **Correction applied (from the orchestrator):** only server-wide `done` scans
  count toward green. `Scanner::isServerWideJob()`: `requested_by` must be
  `''`, `@schedule`, `@operator` or `@cli` (the last added after Shakaal's review), and the paths must include `/` or cover
  every account home that exists NOW. The row records no "all accounts" flag
  (a quick scan of /home is stored as the expanded list of homes), so this is
  the strictest derivable reading: an account added after the last sweep
  drops green until the next sweep. `last_done_scan` is the newest QUALIFYING
  done job, looking back at most 25 done jobs.
- **Decision moved server-side:** `Scanner::protectionStatus()` (pure) is the
  one decision; `getStats()` returns it as `protection` beside
  `last_done_scan` and `last_finished_scan`. `topStatusFor()` renders it and
  the card renders `topStatusFor()`. Reason: the test container has no JS
  runtime, so only a PHP decision can be tested by behaviour on seeded rows.
  A payload without `protection` cannot reach the green branch.
- Any finished status other than `done`/`incomplete` (incl. `halted`) counts
  as "did not finish".
- Extra case not in the spec: `done` jobs exist but none server-wide: amber
  "No complete server scan".
- Five old source assertions pinned the replaced cascade
  (`!lastJob?.finished_at`, `lastJob.status === 'incomplete'`,
  `sc.last_scan.status === 'incomplete'`, the fixed green title). Changed in
  place, each with a CHANGED comment; the behaviour they protected is now
  asserted on seeded rows.
- The card's "Last scan: never" meta line read "never" while a scan ran on a
  scanned server; it now reads "Scan in progress". Same root cause.
