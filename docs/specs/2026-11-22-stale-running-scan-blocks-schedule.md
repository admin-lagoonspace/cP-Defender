# Reconcile a scan whose worker is gone, and stop it blocking the schedule

**Asked for:** "If the scan has ran for over 2 days and the scan process has not
run since why are we not updating status on this page? Scanner logs still show
its running, thats ridiculous."

**Status:** ready-for-shakaal
**Size:** Z — both halves are fixes to shipped behaviour (`Scanner::reapStaleJobs`
has existed since 3.30.x; the scheduler's refusal path since 4.2x). No new
feature, no architectural change. One additive column, no new page.

## What the user is actually trying to achieve

Two things, and they are the same defect seen from two ends:

1. The panel must not state as fact that a scan is running when nothing is
   running. This is a security product; a scan row at `running` for 57 hours is
   the same class of lie as the WAF reporting `action = 'block'` in
   DetectionOnly. The operator should not have to press Stop to make the
   product tell the truth.
2. The daily scan must actually run daily, and when it cannot, the panel must
   say why — on the Scanner page, not only in a log file nobody is tailing.

## What exists today

Reconciliation is built and is being called. It is returning zero.

- `Scanner::reapStaleJobs()` — `backend/lib/Scanner.php:368-417`. Selects every
  job in `('running','pending','cancelling')`, skips any whose worker it judges
  alive, tries to adopt an unrecorded worker from `/proc`, otherwise sets
  `status='interrupted'`, `finished_at`, and republishes the customer's status.
  It does **not** write a reason.
- `Scanner::jobWorkerAlive()` — `Scanner.php:348-358`. No pid recorded → alive
  only within `WORKER_GRACE` (120s, `Scanner.php:221`). Pid recorded →
  `processAlive($pid)`.
- `Scanner::processAlive()` — `Scanner.php:2484-2491`:

  ```php
  if ($pid <= 1) { return false; }
  if (is_dir('/proc')) { return is_dir('/proc/' . $pid); }
  ```

  **This is gap 1.** It asks whether *a* process holds that pid, never whether
  it is this job's scan worker. On a shared host with 132 accounts the pid space
  wraps in hours; a dead worker's number is reused by a php-fpm child, a cron,
  anything — and the job reads as alive for ever. `scanWorkerPids()`
  (`Scanner.php:235-256`) already knows how to identify a real worker
  (`/proc/<pid>/cmdline` contains `backend/cron/scan.php` and `--job-id=<id>`),
  but `jobWorkerAlive()` only reaches for it when the pid is *absent*, never to
  validate a pid that is present.

- **Gap 2: there is no heartbeat, so a worker that is alive but wedged is never
  reconciled.** `Scanner::recordProgress()` (`Scanner.php:1005-1013`) writes
  `files_scanned` and `threats_found` per batch (`scan_batch_size`, default 200)
  and no timestamp. `grep` for `progress_at|heartbeat|last_seen` across
  `backend/` returns nothing on `scan_jobs`. The only stall detection in the
  product is in the browser: `State._scanStallTicks` in
  `frontend/js/app.js:1158-1190`, which after ~30s prints "No new files scanned
  for 30s — the scan process may have stopped. Check logs/scan_<job>.log" and
  takes no action, by design — the comment there says the scan runs detached so
  the UI cannot see it die. So the product can tell the operator something is
  wrong and has no path to doing anything about it.

- **Gap 3: nothing reconciles on a schedule of its own.** `reapStaleJobs()` is
  reached from `liveScans()` (`Scanner.php:427`), `activeScan()`
  (`Scanner.php:440`), `startScan()` (`Scanner.php:813`), `POST scanner/reap`
  (`backend/api/index.php:589-600`) and the CLI (`backend/cli/serverscrub.php:815`).
  `backend/cron/scheduler.php` has no reconcile step; it only reaps as a
  side-effect of a scan being due. With `scan_schedule` off, or with the
  scheduler lock held (`scheduler.php:126-145`), nothing reconciles at all.

- **The Scanner page's log table never reconciles.** `GET scanner/logs`
  (`backend/api/index.php:635-662`) reads `scan_jobs` raw. It does already
  render `stop_reason` beside the status (`frontend/js/app.js:1693-1695`) and
  already colours `interrupted` red (`app.js:1658`), so a reconciled row with a
  reason displays correctly today with no frontend change.

### Why the daily scan stopped — mechanism, read out of the code

`backend/cron/scheduler.php:218-231` (the `scan` task) calls
`$sc->startScan(...)`. `startScan()` at `Scanner.php:813-822`:

```php
$live = self::liveScans();
$max  = self::maxConcurrent();          // 1, unless scan_max_concurrent is raised
if (count($live) >= $max) {
    throw new RuntimeException('Already running ' . count($live) . ' of a maximum ' . $max . ' scan(s) (job ' . $ids . ')...');
}
```

The scheduler catches that, logs it, and `return false` — which, by the
deliberate design at `scheduler.php:966-980`, means the task is **not** marked
run and stays due. So every tick, every 15 minutes, for two days: the scan task
fires, `liveScans()` reaps nothing because the stuck row looks alive, `startScan`
refuses, the task stays due, nothing runs, and the only trace is one line in the
scheduler log. The hypothesis in the bug report is correct, and the stuck row is
also blocking `update.sh`'s post-update resume path (`update.sh:1342-1345`),
which declines to stack on a `liveScans()` entry for the same path.

### The `cancelled (stopped by the 4.3x.x update)` rows

Already addressed and not a live defect: `install.sh:2338-2353` records the live
jobs to `logs/.resume-scans.json` before `stopAllScans('stopped by the <ver>
update')`, and `update.sh:1328-1360` restarts them afterwards. Those rows are
history from before that landed. The residual problem is cadence, not
cancellation: a full `/home` scan on this server was at 57h41m and 289,200 files
when it stopped, which is longer than the gap between releases and far longer
than the daily schedule. That is a scheduling-policy question, out of scope
here, and noted in Open questions.

## Requirements

1. A job's worker is judged alive only if the process holding the recorded
   `worker_pid` **is that job's scan worker** — identified the way
   `scanWorkerPids()` already identifies one, by `/proc/<pid>/cmdline`
   containing `backend/cron/scan.php` and `--job-id=<that job's id>`. A pid
   belonging to any other process is not alive for this purpose.
2. Where `/proc` is unavailable, liveness cannot be established by identity.
   The job must then be reported as unknown rather than alive or dead, and left
   alone — with the reason logged once per pass. Preferring "we do not know" is
   required here; a wrong "dead" verdict kills a scan that is working.
3. `scan_jobs` gains a progress heartbeat timestamp, written by
   `recordProgress()` on every batch alongside the counters, and set when the
   job is created. Additive column, added in `Database.php`'s existing
   `PRAGMA table_info(scan_jobs)` migration block (`Database.php:599-632`); no
   table rewrite, no data migration, and an existing row with a NULL heartbeat
   falls back to `started_at`.
4. A job whose worker is alive but whose heartbeat has not moved for longer
   than `scan_stall_timeout` (default 1800s, clamped 300–86400) is reconciled
   to a terminal state as in requirement 6, and the worker and the clamscan it
   spawned are stopped through the existing `stopScan()` path — so the row and
   the machine agree. Nothing else is killed.
5. A job that is paused on purpose is not stalled. When
   `scan_paused_for_backup` is `'1'` (set by `waitOutBackup()`,
   `Scanner.php:2292-2340`, which sleeps in 30s steps for up to
   `scan_backup_max_wait`, default 14400s) the stall timer does not apply to
   that job, and the Scanner page says the scan is paused for a backup rather
   than stalled.
6. A reconciled job ends at `status='interrupted'` — the status the product
   already writes and the UI already renders — with `finished_at` set and
   `stop_reason` carrying a specific, human reason naming the evidence. At
   minimum these three are distinguishable:
   - `worker pid <n> is gone` (no process, or the pid belongs to something else)
   - `no pid recorded within <n>s of starting`
   - `no progress for <n>m (last file at <time>); worker <n> stopped`
   A new status name is deliberately not introduced: `died` would need frontend
   colour, test and filter changes for no gain over `interrupted` plus a reason.
7. Partial results are kept. `files_scanned` and `threats_found` keep the values
   the worker recorded, and findings already written to `threats` are untouched.
   A reconciled job is never reported as `done`.
8. Reconciliation runs on every scheduler tick, before the task loop, and
   independently of `scan_schedule` — so it happens on a server whose schedule
   is `off` and on a tick where no task is due. Its outcome is logged only when
   it changed something (the scheduler is silent when idle by design,
   `scheduler.php:984`).
9. Each reconciliation is visible without opening a log file:
   - in SCANNER LOGS, as the row's status and reason (existing rendering);
   - on the dashboard, as a `Logger::event()` security event, severity warning,
     naming the job id, path and reason, so it appears in Recent events
     (`backend/api/index.php:454-457`);
   - in `Logger::warn` as it does today.
10. `GET scanner/logs` reconciles before it lists, so the page an operator is
    looking at cannot be the thing that keeps showing `running`. The reconcile
    is the same bounded pass as requirement 11, not a per-row `/proc` walk.
11. One reconciliation pass examines at most 50 candidate rows and enumerates
    `/proc` at most once, reusing that snapshot for every candidate. It touches
    no path under `/home` and performs no directory walk.
12. When the scheduled scan is refused because one is genuinely still running,
    the Scanner page says so: the reason and the age of the blocking job, from
    the last refusal, stored as settings by the scheduler. Two days of silent
    15-minute refusals is the part of this incident that made it undiagnosable.
13. The reconciliation pass runs once on upgrade, from
    `install.sh --register-only` (the new copy — update-time steps in
    `update.sh` run one release late), so the row stuck on the production
    server is closed out by installing the release rather than by an operator
    running a command.
14. `serverscrub scan-reap` (the existing CLI reap path,
    `serverscrub.php:815`) reports per job what was decided and why, including
    jobs it deliberately left alone and jobs it could not judge.

## Explicitly out of scope

- Any change to what a scan scans, how it walks, or `scan_batch_size`.
- A maximum scan duration that kills a scan which is genuinely progressing. A
  57-hour scan on this server may be correct behaviour for a full `/home`; a cap
  would silently destroy coverage, which is worse than a long scan. See Open
  questions.
- Changing `maxConcurrent()`, or letting a second scan start alongside a
  suspect one. Two clamscans on a live host is the incident this guard exists
  to prevent.
- Resuming or restarting a reconciled scan automatically. The next scheduled
  tick starts a fresh one; a half-done scan is not resumable.
- The `cancelled (stopped by the ... update)` history and the
  scan-longer-than-the-release-cadence problem — separate spec.
- Any new status value, new page, or new card.
- Touching the `threats` rows a dead scan left behind. Flag and report; the
  findings stand.

## Failure behaviour

- **No `/proc`** (non-Linux, hardened container): liveness is unknown.
  Reconcile nothing, log once, leave the rows. The CLI and the page both say
  the state could not be determined rather than implying health.
- **Worker alive, wedged in uninterruptible IO** (`/home/virtfs`, a stuck NFS
  mount): the stall rule fires, `stopScan()` signals the group, and if the
  process is still present afterwards the row still ends `interrupted` with the
  reason recording that the process would not die. A row that cannot be made
  true by killing is still made honest.
- **Database write fails mid-pass**: the pass aborts, logs, and the rows stay as
  they were. A partially reconciled set is acceptable; a crash that takes the
  scheduler tick down is not — one failing step must not stop the other tasks
  (`scheduler.php:985-989`).
- **The heartbeat column is missing** (migration did not run): fall back to
  `started_at` and apply only the pid-identity rule. No fatal error.
- **Pid recorded as 0 and the job is young**: unchanged — the existing 120s
  grace applies, because the worker writes its pid as its first act
  (`backend/cron/scan.php:166-169`).
- **A worker that is adopted** (pid column predates the row, process found by
  cmdline): unchanged behaviour, adopt and leave running. Marking a live worker
  interrupted makes the scan invisible, which the existing comment at
  `Scanner.php:377-385` records as a previous defect.

## Resource bounds

- Candidate rows per pass: **50** maximum, `status IN ('running','pending','cancelling')`.
- `/proc` enumerations per pass: **1**. Reads only `cmdline`, `stat` and `comm`
  for each pid — metadata, no process memory, no file content.
- Passes: one per scheduler tick (**every 15 minutes**), one per
  `scanner/logs` request, one per explicit CLI or API reap.
- Stall threshold: `scan_stall_timeout`, default **1800s**, clamped **300–86400**.
- Heartbeat writes: one `UPDATE` per batch of **200** files — the same cadence
  and the same statement as the counter write that already happens there, so no
  additional write.
- Filesystem: **zero** paths walked, nothing under `/home`, `/home/virtfs`
  never touched.
- Processes signalled: only the `worker_pid`/`worker_pgid` recorded on the job
  being reconciled, and clamscans in that process group — the existing
  `stopScan()`/`reapOrphanClamscans()` scope. cPanel's own mail clamscan is not
  in scope and must not be signalled.

## Acceptance criteria

Shakaal must demonstrate, in the repo's docker environment:

1. **Pid reuse — the production mechanism.** A `running` job whose
   `worker_pid` is the pid of a live process that is *not* a scan worker (e.g.
   a `sleep`), `started_at` two days ago. Before: `activeScan()` returns it and
   `startScan()` throws. After: one reconcile pass sets it `interrupted` with
   `stop_reason` naming the pid as gone, and `startScan()` succeeds.
2. **A live worker is not touched.** A process whose cmdline contains
   `backend/cron/scan.php --job-id=<id>` for that job, heartbeat fresh: the job
   stays `running`, `stop_reason` empty, no signal sent, across repeated passes.
3. **Stalled but alive.** A job with a live, identity-matching worker whose
   heartbeat is older than `scan_stall_timeout`: reconciled to `interrupted`
   with the "no progress for Nm" reason, and the worker process is gone
   afterwards.
4. **Paused for a backup is not stalled.** Same as (3) with
   `scan_paused_for_backup='1'`: the job stays `running` however old the
   heartbeat, and the page reports it as paused.
5. **Partial results survive.** The reconciled job in (1) and (3) keeps its
   `files_scanned` and `threats_found`, its `threats` rows still exist and are
   still `active`, and no row anywhere reads `done`.
6. **The schedule recovers.** With the stuck row present and `scan_schedule=daily`
   and the scan due, `php backend/cron/scheduler.php` starts a scan on the
   first tick after the reconcile — demonstrated end to end, not by asserting
   on source text.
7. **Refusal is visible.** With a genuinely live scan and the scheduled scan
   due, the Scanner page shows the refusal reason and the blocking job's age,
   and this is read from the API in a browser, not from the log file.
8. **Dashboard.** After (1), `GET dashboard/stats` Recent events contains a
   warning event naming the job id and the reason.
9. **Logs page.** `GET scanner/logs` immediately after the stuck row is created
   does not return it as `running`, and the rendered row shows `interrupted`
   with the reason in the dim parenthesis the UI already draws.
10. **No `/proc`.** With process inspection unavailable, nothing is reconciled,
    nothing is signalled, the pass logs that liveness is unknown, and no row is
    marked `interrupted` — demonstrated, because a false "dead" verdict here
    would kill working scans on every non-Linux target.
11. **Bounds.** With 200 stuck rows present, one pass touches at most 50 and
    enumerates `/proc` once; shown by instrumentation or log output, not by
    inspection of the code.
12. **Upgrade closes out the real case.** A database carrying a two-day-old
    `running` row with a reused pid is reconciled by `install.sh
    --register-only` alone, with no operator command.
13. **Existing coverage still passes**, specifically `tests/test_scan_concurrency.php`,
    `tests/test_scan_stop.php` and `tests/test_user_scan_live.php` — the first
    asserts the current reap contract and the grace period, and requirement 1
    changes the predicate underneath it.

## Open questions

Neither blocks implementation; both are recorded because they were decided
here rather than confirmed.

1. **Not confirmed on production.** There is no SSH key for
   `host.lws-s1.com` in this environment (`ssh root@host.lws-s1.com` →
   `Permission denied (publickey)`), so the mechanism above is read out of the
   code, not observed on the server. It is consistent with every symptom
   reported, and the two candidate causes — a reused pid (gap 1) and a wedged
   worker (gap 2) — are both covered by the requirements, so the fix does not
   depend on knowing which fired. What is still wanted, read-only and bounded,
   is confirmation of which one it was:
   `sqlite3 -readonly /usr/local/serverscrub/database/serverscrub.db "SELECT id,status,worker_pid,worker_pgid,started_at,files_scanned FROM scan_jobs WHERE status IN ('running','pending','cancelling');"`,
   then `cat /proc/<worker_pid>/cmdline` (expects `backend/cron/scan.php
   --job-id=12467`; anything else is pid reuse, nothing is a dead pid), plus
   `grep -c 'Already running' /usr/local/serverscrub/logs/*.log`. The fix logs
   its own reason in `stop_reason`, so the next occurrence answers this without
   anyone being asked.
2. **Whether a scan may ever exceed a day.** A full `/home` scan here ran 57h41m.
   With a daily schedule, either the schedule is wrong for this server or the
   scan is too slow, and the right answer is a policy decision, not a watchdog.
   This spec therefore does **not** cap duration: an upper bound that kills a
   progressing scan would trade a visible stuck row for invisible missing
   coverage. Requirement 12 instead makes the overlap visible. Raised for a
   separate spec alongside the update-cancellation cadence.

---

## Implementation (Wasooli, 2026-11-23)

Preflight passes, including the docker Linux stage (5,344 assertions at PHP
7.4). Changelog entry is under `## [Unreleased]`.

### What was built, per requirement

1. **Pid identity.** `Scanner::judgeJob()` (new) is the single place a job's
   worker is judged. Identity is `/proc/<pid>/cmdline` containing
   `backend/cron/scan.php` **and** this job's id. `jobWorkerAlive()` is now a
   thin predicate over it, so every existing caller gets the new rule.
   `procSnapshot()` parses `--job-id=(\d+)` and compares **integers** — the old
   `strpos($cmd, '--job-id=' . $jobId)` also matched job 1247 when asked about
   job 124, which could adopt one job's worker onto another job's row. Found
   while implementing, not reported.
2. **No `/proc` → unknown.** Verdict `unknown`, left alone, logged once per
   pass, reported through `lastReapPass()['available']` to the CLI and the API.
   **One deliberate deviation, below.**
3. **Heartbeat.** `scan_jobs.progress_at`, added in the existing
   `PRAGMA table_info(scan_jobs)` block in `Database.php`. Written by
   `recordProgress()` in the same `UPDATE` as the counters, and set at creation
   in `startScan()`. `heartbeatOf()` falls back to `started_at`;
   `hasHeartbeatColumn()` means an install whose migration has not run keeps
   working instead of fataling once per batch.
4. **Stall rule.** `scan_stall_timeout` (seeded 1800, clamped 300-86400 in
   `stallTimeout()`). A stalled job is stopped through `stopScan()` and then
   closed out; `stopWedgedWorker()` appends `; the worker process would not
   die` when the process survives.
5. **Paused is not stalled.** `pausedForBackup()` gates the stall rule and the
   Scanner page says so. Added beyond the spec: when a pass closes out *every*
   in-progress row, `scan_paused_for_backup` is reset to `0` — a worker killed
   mid-wait leaves that flag at `1` for ever, which would exempt every later
   scan from the stall timer.
6. **`interrupted` + specific `stop_reason`.** All three reasons are
   distinguishable and name the evidence; the reused-pid case adds
   `(that pid now belongs to another process)`.
7. **Partial results.** Only `status`, `finished_at` and `stop_reason` are
   written. Asserted in the test and verified in docker.
8. **Every scheduler tick**, before the task loop, independent of
   `scan_schedule`, wrapped so a failure cannot take the tick down. Silent
   unless it changed something.
9. **Visible:** the row and its reason (existing rendering), `Logger::warn`,
   and a `Logger::event('scan_reconciled', 'warning', ...)` security event
   naming job, path and reason.
10. **`GET scanner/jobs` reconciles before it lists** (that is the SCANNER LOGS
    table). `scanner/active` reconciles too, through `activeScan()`.
11. **Bounds:** `REAP_MAX = 50` and `LIMIT 50` on the candidate query; one
    `procSnapshot()` per pass, cached 5s and shared by every candidate, with
    `procScanCount()` for instrumentation. No path walked.
12. **Refusal recorded** by the scheduler into four settings and read back by
    `Scanner::scheduleRefusal()`; `scanner/active` returns it;
    `renderScanScheduleNotice()` draws it on the Scanner page on every visit,
    *including when there is no scan to adopt* — which is exactly when the
    question gets asked. Cleared when a scheduled scan starts.
13. **`install.sh`** runs `serverscrub scan-reap` in the section that executes
    on `--register-only` (beside the containment sweep), guarded on the
    database existing, never fatal.
14. **`serverscrub scan-reap`** prints verdict, action and reason per job,
    including the jobs it left alone and the ones it could not judge.

### Files touched

- `backend/lib/Scanner.php` — `procSnapshot()`, `setProcDir()`/`procDir()`
  (test seam, same shape as `setCpanelUsersDir()`), `procScanCount()`,
  `judgeJob()`, `jobWorkerAlive()`, `reapStaleJobs()` (bounded pass +
  `lastReapPass()`), `stopWedgedWorker()`, `announceReap()`, `stallTimeout()`,
  `heartbeatOf()`, `pausedForBackup()`, `recordScheduleRefusal()`/
  `clearScheduleRefusal()`/`scheduleRefusal()`, `hasHeartbeatColumn()`,
  heartbeat in `recordProgress()` and `startScan()`. Every `/proc` read in the
  file now goes through `procDir()`.
- `backend/lib/Database.php` — `progress_at` migration, `scan_stall_timeout`
  seed.
- `backend/cron/scheduler.php` — reconcile step before the task loop; refusal
  recorded and cleared in the `scan` task.
- `backend/api/index.php` — `scanner/jobs` reconciles first; `scanner/active`
  returns `paused`, `refusal`, `reconcile`; `scanner/reap` reports the pass.
- `backend/cli/serverscrub.php` — `scan-reap` per-job report.
- `frontend/js/app.js` — `renderScanScheduleNotice()`, called from
  `adoptRunningScan()` before its early return.
- `install.sh` — the one-time pass on `--register-only`.
- `scripts/smoke.php` — `scanner/active` and `scanner/running` added.
- `tests/test_scan_stall_reconcile.php` — new, 73 assertions.

### Verified in docker, against a real process table

`docker compose -f docker/compose.yml run --rm test` passes. Beyond the suite,
two throwaway probes ran inside the container against real `/proc`:

- A `running` row two days old whose `worker_pid` is a live `sleep`: verdict
  `dead`, reason `worker pid 628 is gone (that pid now belongs to another
  process)`, row `interrupted`, `files_scanned` 289,200 kept, `activeScan()`
  empty afterwards — and **the `sleep` was not signalled**.
- A process whose `cmdline` reads `php .../scan.php --job-id=<id>
  --path=/home` (built with `exec -a` + `php -r 'sleep(300);'`; note the
  image's `sleep` is a coreutils multicall binary that rewrites its own
  cmdline, so `exec -a ... sleep` cannot be used for this): adopted with pid
  **and pgid** when no pid was recorded; then `alive` across three passes with
  `stop_reason` empty and the process untouched; `paused` with a 27-hour-old
  heartbeat while `scan_paused_for_backup=1`, still untouched; `stalled` once
  unpaused, closed out with `no progress for 1666m (last file at ...Z); worker
  628 stopped`, and the worker gone afterwards.
- 200 stuck rows: one pass closed out **50**, examined 50, left 150 for the
  next pass, enumerated `/proc` once.
- `php backend/cron/scheduler.php` with the stuck row present and
  `scan_schedule=daily`: `started full scan of /home (job 2)` on the first
  tick. The schedule recovers end to end.
- A warning `scan_reconciled` row is in `security_events` naming the job and
  the reason.

Against the pre-change code (HEAD `ef09d3e`, with only the hardcoded `/proc`
string redirected so the case could be constructed on Windows) the same stuck
row reads `jobWorkerAlive: true`, `reapStaleJobs: 0`, `liveScans: 1`,
`status: running`. The mechanism is confirmed, and that is also why the old
test's pid 2147483646 could never have caught it.

### Deviations and judgement calls

- **A pid that provably does not exist is still reaped when `/proc` is
  unreadable.** The spec says reconcile nothing without a process table. Taken
  literally that leaves every non-Linux install with a row nothing can ever
  close, and it breaks the contract `tests/test_scan_concurrency.php:93-104`
  has asserted since 3.30. So: pid present but unverifiable → `unknown`, left
  alone; pid **absent** → `dead`. "That pid does not exist" is still a claim we
  can verify, so no honesty is lost. Acceptance criterion 10, constructed with
  a *live* reused pid (the realistic case), still holds.
- **The live-pid-unknown case is not asserted on Windows.** Without `/proc`
  the fallback is `posix_kill`, which the developer's build has not got, so
  that branch of the unit test is gated on `function_exists('posix_kill')` and
  prints a line saying it was not exercised. It runs on Linux. Flagged because
  a gated assertion is something to check rather than trust.
- **`scan_paused_for_backup` is a global setting, not per job.** Requirement 5
  is worded per job. At `scan_max_concurrent = 1` they are the same thing; with
  it raised, one paused scan exempts another live scan from the stall timer for
  as long as the backup runs. Per job means another column, and the spec asked
  for one. Recorded rather than decided.
- **Every** `startScan()` failure in the scheduled task is recorded as a
  refusal, not only the concurrency one — "nothing to scan", the backup gate
  and a database error all land in the same four settings, with the reason
  verbatim. One fact, one place, and "The scheduled scan did not start" is true
  of all of them.
- **`frontend/index.html` was not touched** (Gabbar's file). The notice card is
  created by `renderScanScheduleNotice()` and exists only when there is
  something to say.
- **`scripts/smoke.php`** gained `scanner/active` and `scanner/running`: both
  now run the process-table pass on every request, and an unsmoked route is one
  whose first execution happens on a customer's server.

### Revision after Shakaal's first pass (2026-11-23)

`docs/findings/2026-11-23-stale-running-scan-reconcile.md` returned FAIL on one
blocker and three majors, all in code this change introduced. Fixed; minors 5,
6 and 8 fixed with them; the full response, with measurements, is at the end of
that findings file. What it changes in the notes above:

- **Requirement 11's "one `/proc` enumeration per pass" is now one on a pass
  that finds nothing wrong, and two on a pass that acts.** The single cached
  snapshot could be older than the job it was judging: the scheduler is one
  process, it reconciled at the top of a tick, started the daily scan, and a
  later task in the same tick judged the new job against the pre-scan snapshot
  — marking its own healthy scan `interrupted` with `worker pid <n> is gone`,
  orphaning the worker, and letting a second concurrent clamscan sweep start
  because `liveScans()` read 0. A cheaper pass that can lie is not worth
  keeping, so the cached read now only decides *whether* there is anything to
  do, and anything that would change a row is re-read and re-judged first. The
  second read is still shared by every candidate, so the bound is 2, not 1+N.
- **The 120s startup grace covers a recorded pid as well as a missing one.**
  The row exists before the process does; the grace used to apply only when
  `worker_pid` was absent.
- **A negative verdict is never formed from evidence older than the job.**
  `procSnapshot()` carries the time it was taken and `judgeJob()` returns
  `unknown` when the read predates the job settling.
- **Requirement 5's pause is checked against the machine.** My original
  mitigation (reset the flag when a pass closed out every in-progress row)
  could not fire in the `scan_backup_max_wait` case, because the worker closes
  its own row. `waitOutBackup()` now gives the pause back on every exit, and
  `pausedForBackup()` clears a flag that no running backup supports rather than
  letting it exempt every later scan from the stall timer.
- **Requirement 12's card no longer claims a job is in progress without
  establishing that it is.** `scheduleRefusal()` reads the job's current status
  and sends `job_live` / `job_status`; `job_age` is 0 unless it really is
  running.
- **Requirement 4's threshold is floored at three batch timeouts.**
  `scan_batch_timeout` and `scan_stall_timeout` were clamped independently, so
  a legal pair reaped a healthy scan — the outcome this spec puts out of scope.
  `Scanner::batchTimeout()` is now the single definition and feeds both.
- **A zombie pid is treated as gone**, so `stopScan()` no longer reports that a
  worker "would not die" when it died correctly, and a zombie is not
  misattributed to pid reuse.
- **The upgrade pass (requirement 13) moved below the install-only span.** It
  was above it, where on a full install the CLI it calls does not exist yet, so
  it was skipped in silence on that path. It now runs on a full install and on
  `--register-only`, and says so when it is skipped.
- **Correction to the file list above:** every *process-table* read in
  `Scanner.php` goes through `procDir()`. `/proc/self/fd` in `fdsAboveStderr()`
  is this process's own descriptor list, not a liveness question, and stays
  literal.
- **The accepted `/proc` deviation carries one more caveat:** with no readable
  process table, `posix_kill($pid, 0)` is false on EPERM as well as ESRCH, so a
  worker owned by another uid would read as absent and be reaped. Latent today
  — worker, scheduler, CLI and panel all run as root — and now written into
  `processAlive()`'s docblock.
- **Two passing assertions in `tests/test_scan_concurrency.php` were
  rewritten** from fixed character windows to `t_fn_body()`, because the fixes
  above are inside the functions those windows slice. Same claims, same
  ordering requirement, nothing weakened. Stated plainly because editing a
  passing test is normally not allowed here.

### Second revision after Shakaal's second pass (2026-11-23)

`docs/findings/2026-11-23-stale-running-scan-reconcile-pass2.md` returned PASS
WITH CAVEATS: two minors, both in code this change introduced, both fixed here.

- **Finding 9. A pause is revoked only on a fresh look.**
  `pausedForBackup()` writes -- it clears the flag when nothing supports it --
  and it was deciding that from `backupRunning()`'s 30-second cache, while the
  `$fresh` parameter added in the same change sat unused. Shakaal traced the
  one interleaving that reaches it: a scheduler tick with
  `scan_pause_on_backup=1`, whose scan task probes for a backup and caches "no
  backup" before `startScan()` reaches the reconcile. A backup starting in that
  sub-second gap, with a worker already holding the pause, had the gate throw
  away a pause that was genuinely in force -- and the reconcile then signals a
  scan that is waiting out a real backup, which this spec puts out of scope.
  It now reads `backupRunning(true)`: one process-table read, and only when the
  flag is set.
- **The wait loop asks freshly too, which its own comment has claimed since
  before there was a way to ask.** `waitOutBackup()` called plain
  `backupRunning()` under "Force a fresh look rather than the 30s cache", so a
  wait could run up to 30 seconds past the end of a backup. The note below
  about the loop being "driven by `backupRunning()`, not by the flag" was
  correct about the mechanism and wrong about the freshness; both the call and
  the comment are now right.
- **Finding 10. A zombie is not a running backup.** The fix for finding 5
  landed in `procSnapshot()` and `processAlive()` and was missed in
  `RealTimeMonitor::backupProcesses()`, which matches on `/proc/<pid>/comm` --
  populated for a zombie, unlike `cmdline` -- and never looked at the state. A
  dead, unwaited `rsync` therefore read as a backup in progress, which is worse
  than it first appears: it is the signal finding 2's fix now depends on, so the
  Scanner page claimed a backup and the stall watchdog stood down; and the
  real-time monitor suspends itself while a backup runs, so a corpse left
  monitoring off. It also invalidated two of Shakaal's probe runs. The state is
  now checked for a pid that is about to be counted -- one stat read per
  candidate, not per process on the host.

`pidIsZombie()` is deliberately a three-line copy in each class rather than a
dependency: `Scanner` and `RealTimeMonitor` already require each other lazily,
in both directions, and a hard edge between them is how a cron script fatals.

Covered by `tests/test_scan_stall_reconcile.php` sections 15 and 16, built on
the process table the test controls: a stale cache against a real backup, and a
zombie `rsync` against a live one. With either one-liner reverted, four
assertions fail -- checked, not assumed.

Finding 9 is also confirmed in the container with Shakaal's own
`probe_pause_cache_window.php` (the pause held), and a live `rsync` is still
reported there. The zombie half of finding 10 was NOT re-demonstrated against
a real zombie in the container -- my fixture reaped itself and the retry ran
out of container time -- so that one rests on the suite and on Shakaal's own
fixture. Said plainly rather than implied.

#### What to look at hardest on the second pass

1. **The two-phase pass under load.** The fresh read happens between judging
   and writing, so the remaining window is the microseconds between that read
   and the UPDATE. I believe the startup grace covers everything inside it, but
   it is where I would look.
2. **`pausedForBackup()` writes a setting from what reads like an accessor.**
   It clears a flag no running backup supports. That is self-healing and logged,
   and it is called from `judgeJob()`, which the API reaches on every Scanner
   page load. Worth checking it cannot fight a worker that is genuinely in
   `waitOutBackup()` at that moment: the wait loop is driven by
   `backupRunning()`, not by the flag, so a cleared flag does not shorten a
   wait -- but that is the interaction to probe. (Shakaal did, and found
   finding 9 in it: the gate was deciding from a cached reading. Fixed above.)
3. **`RealTimeMonitor::backupProcesses()` gained an optional process-table
   root.** Default unchanged, one caller passes `Scanner::procDir()`. The
   monitor's own callers are unaffected, and that is worth confirming rather
   than taking from me.
4. **Acceptance 3 end to end on a host whose init reaps**, now that a zombie is
   read as gone. In the container a setsid'd worker leaves `/proc` entirely and
   the reason carries no "would not die"; a worker parented by a shell that
   does not wait is the case the suite covers synthetically.
5. **`waitOutBackup`'s `sleep(30)` window test** has 93 characters of headroom
   and is the next fixed-window assertion in that file to break.

### What Shakaal should look at hardest

1. **Acceptance 7, in a browser.** The refusal card is the only part of this
   verified at the API and not in the UI. It must appear when there is **no**
   scan running — that is the path `adoptRunningScan()` returns early on, and
   the one the incident needed.
2. **That nothing kills a working scan.** `stopWedgedWorker()` is the only new
   code that signals anything; a `paused` or `adopt` verdict reaching it would
   be the worst available regression. The stall rule also depends on the
   heartbeat genuinely moving — check `progress_at` advances during a real
   clamscan sweep on Linux, not only that `recordProgress()` writes it.
3. **The 5-second `procSnapshot()` cache.** `liveScans()` and `activeScan()`
   both reconcile and one API request calls both, so the cache is what holds a
   request to a single `/proc` walk. The scheduler runs for minutes, so a
   verdict can be formed from a 5-second-old snapshot. I believe that is safe
   because every verdict it can produce is re-checked on the next pass, but it
   is the assumption I am least sure of.
4. **`tests/test_scan_concurrency.php:307`** reads an 1,800-character window of
   `Scanner.php` starting at `reapStaleJobs`. It passes — the three strings it
   wants sit at 702, 1130 and 1587 — but it is 213 characters from breaking for
   reasons that have nothing to do with the code. It is the pattern CLAUDE.md
   warns about. I have not changed it, because changing a passing test is not
   this change; it wants rewriting around `t_fn_body()`.

### Not done, by decision

- No scan duration cap (out of scope; open question 2 stands).
- Nothing touching the historic `cancelled (stopped by the ... update)` rows.
- No new status, page, card, filter or colour, and no change to what a scan
  scans.
- No `maxConcurrent()` change: a suspect scan still blocks a second one.
- Nothing run against `host.lws-s1.com`. The read-only confirmation commands in
  open question 1 are still unexecuted; after this release the row's own
  `stop_reason` answers that question without anyone having to be asked.
