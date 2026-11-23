# Test run — 2026-11-23

**Build:** branch `fix/stale-running-scan-reconcile`, commit `fe07b0c`, tree reports `VERSION` 4.37.7
(unbumped — the CHANGELOG entry is still under `## [Unreleased]`, so the candidate currently
identifies itself as an already-shipped release)
**Environment:** AlmaLinux 8 in `docker/compose.yml`; PHP 7.4.33 and PHP 8.2 (both built, both
suites run); sqlite 3.26.0 (the production version, no `.recover`); python 3.6.8; real `/proc`;
install `--mode standalone`; 8 seeded cPanel accounts plus a `/home/virtfs` tree
**Verdict: FAIL — one blocker. Do not release.**
**Status: addressed by Wasooli 2026-11-23, back to Shakaal — see the response at the end.**

---

## Not tested

- **cpsrvd, WHM AppConfig, LiveAPI, the CGI wrappers.** Container installs `--mode standalone`.
  cPanel-mode integration is proven only by installing on a cPanel box.
- **Real ModSecurity under Apache.** Audit-log parsing exercised against real-shaped fixtures;
  rule evaluation and `SecRuleEngine` actually blocking are not.
- **Real Exim.** `exim -bp` is stubbed. Queue parsing and the 72-hour prune decision are tested;
  delivery is not.
- **ClamAV.** Stubbed, EICAR only. The sweep timings below are therefore floor values: a real
  signature match costs far more per batch than the stub.
- **Scale.** 8 seeded accounts, not 132. The pid-reuse mechanism this change exists to fix is a
  function of pid-space wrap on a busy host; it was constructed deliberately here rather than
  observed arising.
- **Acceptance 3's "and the worker process is gone afterwards".** NOT verified. pid 1 in the
  container is the PHP dev server, which does not reap orphans, so a TERMed worker stays in
  `/proc` as a zombie (state `Z`) and `processAlive()` — `is_dir('/proc/<pid>')` — reads it as
  alive. Every stall reconcile in this environment therefore ends with
  `; the worker process would not die` appended whether or not the signal worked. See finding 5.
- **Production.** Nothing was run against `host.lws-s1.com`. The read-only confirmation commands
  in the spec's open question 1 are still unexecuted, so which of the two mechanisms fired on the
  real server is still inferred from code, not observed.
- **The `unknown` verdict against a live pid on a host with no `/proc` and no `posix_kill`.** The
  suite's gated assertion *did* run here (Linux, posix present). The `exec kill -0` fallback
  branch was not exercised.

---

## Findings

### 1. The 5-second `procSnapshot()` cache makes the scheduler mark its own healthy, just-started scan `interrupted`, and defeats the one-scan-at-a-time cap — blocker

**What happens:** `judgeJob()` applies no startup grace to a job that *has* a recorded
`worker_pid` (the 120s `WORKER_GRACE` covers only `$pid <= 1`). `procSnapshot()` is cached for 5
seconds and shared across a whole process. The scheduler is a single process that runs for
minutes and reconciles at the top of every tick. So on any tick where the scheduled scan starts
and a later task calls `liveScans()` within 5 seconds, that second pass is answered from a
snapshot taken *before* the worker existed: the pid is absent from `snap['workers']`, the verdict
is `dead`, and the row is written to `status='interrupted'`,
`stop_reason='worker pid <n> is gone'` — while pid `<n>` is running and its `/proc/<pid>/cmdline`
names that exact job.

Three consequences, each on its own release-stopping:

1. **A false claim of the exact class this spec exists to remove.** The row states the worker is
   gone. It is not.
2. **The scan becomes invisible.** Nothing claims the worker, so it sweeps `/home` and forks a
   clamscan per batch with no row an operator or `stopScan()` can find. The code's own comment on
   the adopt path records this as a previous defect.
3. **The concurrency cap is defeated.** `liveScans()` returns 0, so `startScan()` no longer
   refuses. `maxConcurrent()` is 1 and a second sweep starts anyway. Each clamscan loads the whole
   signature database into its own memory; this is the "six clamscans on a live host" incident the
   cap exists to prevent, on a 132-account box. That is a customer-facing availability risk.

It also reinstates the reported bug in a new form: the daily scan starts, is orphaned, never
closes out, and the next tick starts another — so the schedule still never produces a result.

**Reproduce:**

```bash
PHP_STREAM=7.4 docker compose -f docker/compose.yml up -d panel
docker compose -f docker/compose.yml exec -T panel bash /opt/serverscrub-src/tests/probes/probe_scheduler_tight.sh
```

`tests/probes/probe_scheduler_tight.sh` arms exactly the production tick: `scan_schedule=daily`,
the scan due, the daily/hourly tasks already marked run 20 minutes ago (so only the fast `every`
tasks sit between `scan` and `resumescan`), and the `logs/.resume-scans.json` marker that
`install.sh` leaves behind after an update, which is what makes `resumescan` call `liveScans()`.
`tests/probes/probe_stale_snapshot.php` isolates the same judgement in one process, and
`tests/probes/probe_double_start.php` shows the cap failing.

**Expected:** a worker that is running and whose cmdline names the job is `alive`, on every pass,
however stale the snapshot. Requirement 1 and acceptance 2 both say so, and the spec's own
failure-behaviour note — "Marking a live worker interrupted makes the scan invisible, which the
existing comment at `Scanner.php:377-385` records as a previous defect" — names this outcome as
the thing not to do. A `dead` verdict is acted on immediately and irreversibly (row rewritten,
customer status republished, security event raised), so "every verdict it can produce is
re-checked on the next pass" does not hold for this one.

**Evidence** — through the real scheduler, real `/proc`:

```
[2026-11-23T05:48:31Z] running: scan [daily]
[2026-11-23T05:48:31Z]   started full scan of /home (job 7)
...
[2026-11-23T05:48:31Z] running: resumescan [every]

id   status       scan_path  worker_pid  stop_reason
7    interrupted  /home      36488       worker pid 36488 is gone

--- are those workers alive? ---
  pid 36488 ALIVE : /usr/bin/php /usr/local/serverscrub/backend/cron/scan.php --job-id=7 --path=/home
```

And the cap (`tests/probes/probe_double_start.php`):

```
t0+1s liveScans() says 0 scan(s) are running
      job 9 status: interrupted / reason: worker pid 36734 is gone
      its worker 36734 alive: YES
      maxConcurrent(): 1
      SECOND scan STARTED as job 10 - the cap did not refuse it
```

The same probe shows a *fresh* snapshot judging the identical row `alive`, so the difference is
attributable to the cache and nothing else.

---

### 2. A stuck `scan_paused_for_backup` flag silently switches the stall rule off for ever, and the panel claims a backup is running when none is — major

**What happens:** `pausedForBackup()` reads one global setting and gates the whole stall rule.
`waitOutBackup()` sets that setting to `'1'` and clears it only on its normal `return true` path.
Both early exits leave it at `'1'`:

- `Scanner.php:2750` — `if (self::isCancelled($jobId)) { return false; }`
- `Scanner.php:2752-2755` — `$waited >= $maxWait` (default `scan_backup_max_wait` 14400s)

The mitigation added in this change resets the flag only when a pass closes out *every*
in-progress row (`$n > 0 && count($rows) === $n`). In the max-wait path the worker closes its own
row, so the next pass sees zero candidates, `$n` is 0, and the reset cannot fire. From then on
every identity-confirmed worker is judged `paused` no matter how long it has been silent, and the
Scanner page reports it as waiting for a backup.

**Reproduce:**

```bash
docker compose -f docker/compose.yml exec -T panel php /opt/serverscrub-src/tests/probes/probe_pause_gate.php
docker compose -f docker/compose.yml exec -T panel php /opt/serverscrub-src/tests/probes/probe_stuck_pause_flag.php
```

**Expected:** requirement 4 is unconditional for a worker that has reported nothing past
`scan_stall_timeout`. A pause flag left behind by a backup that timed out four hours ago is not a
reason to exempt every future scan, and the page must not report a backup that is not running —
the same honesty rule as the rest of the spec.

**Evidence:**

```
-- flag correctly clear --
  verdict : stalled
  reason  : no progress for 3333m (last file at 2026-11-20 22:18:18Z); worker 60687 stopped

-- flag stuck at 1 by waitOutBackup() --
  verdict : paused
  reason  : paused while a backup runs, so the stall timer does not apply
  backupRunning() : []
```

and, with no in-progress rows at all:

```
after a reconcile pass, flag is still: 1  (pausedForBackup() = true)
```

Wasooli already recorded the per-job-vs-global wording as a judgement call. This is the separate,
concrete half of it: the flag has no owner and no expiry.

---

### 3. The refusal card asserts, in the present tense, that a job is in progress after the product has closed it out — major

**What happens:** `scheduleRefusal()` is built from four settings and computes
`job_age = time() - job_started` live, without ever checking whether that job is still in
progress. `clearScheduleRefusal()` is reached from exactly one place: the scheduled scan task,
when a scan actually starts. A reconcile pass — the very thing that closes the blocking row out —
does not clear it. So between the reconcile and the next successful scheduled start the Scanner
page tells the operator a job is "in progress" that the product has just marked `interrupted`,
with an age that keeps counting up. With `scan_schedule=off` — the server requirement 8 was
written for — nothing ever clears it.

**Reproduce:** load the Scanner page with the refusal settings populated and zero in-progress
rows, then

```bash
docker compose -f docker/compose.yml exec -T panel php /opt/serverscrub-src/tests/probes/probe_refusal_staleness.php
```

**Expected:** the card may say the scheduled scan was refused and when. It must not state a job is
in progress without establishing that it is, and the reconcile that closed the job out should
clear or amend the claim.

**Evidence** — read from the API in the browser at `http://localhost:8777`, Scanner panel, with
`scan_jobs` empty:

> The scheduled scan did not start. Last refused 15m ago: Already running 1 of a maximum 1 scan(s)
> (job 12467) (blocked by job 12467, in progress for 2d 9h)

```
in-progress rows right now : 0
does job 12467 exist at all: NO
after a reconcile pass, the claim is still there: YES, job 12467 still reported in progress for 57.7h
and the age keeps growing: 207741s (was 207738s)
```

---

### 4. `scan_stall_timeout` and `scan_batch_timeout` are clamped independently, so a legal configuration reaps a healthy scan — major

**What happens:** the spec justifies 1800s by "a single clamscan batch is already capped at
`scan_batch_timeout` (600s), so three missed batches in a row is not a slow file, it is a wedged
worker". But `scan_batch_timeout` is clamped `60..3600` (`Scanner.php:1605-1606`) and
`scan_stall_timeout` is clamped `300..86400` (`stallTimeout()`), with no relation enforced between
them. `recordProgress()` is only reached after a full batch completes, so with
`scan_batch_timeout` above `scan_stall_timeout` — e.g. the documented minimum stall of 300s
against the default batch timeout of 600s, or a batch timeout raised to 3600 against the default
stall of 1800 — a perfectly healthy worker grinding through one slow batch is judged `stalled`,
signalled through `stopScan()` and closed out.

That is precisely the outcome the spec puts out of scope: "A maximum scan duration that kills a
scan which is genuinely progressing… a cap would silently destroy coverage, which is worse than a
long scan."

**Reproduce:** inspection plus the arithmetic above; the defaults (600 < 1800) are safe, so this
needs a setting change to fire. Not reproduced live, and flagged as such.

**Expected:** `stallTimeout()` should have a floor derived from the effective batch timeout (for
instance `max(3 * batchTimeout, configured)`), or the two clamps should be documented as coupled
and the UI should refuse a combination that cannot be satisfied.

---

### 5. A dead-but-unreaped worker is reported as "would not die", and a zombie pid is blamed on "another process" — minor

**What happens:** `processAlive()` is `is_dir('/proc/<pid>')`, which is true for a zombie.
`procSnapshot()` reads `cmdline`, which is empty for a zombie, so the pid lands in `pids` but not
in `workers`. Two consequences:

- `stopWedgedWorker()` appends `; the worker process would not die` whenever `stopScan()` reports
  `worker_gone` false, which includes a worker that died correctly and has not been waited on.
- a zombie worker is judged `dead` with the suffix `(that pid now belongs to another process)`.
  It does not; it is the same worker, unreaped. That suffix is the sentence that is supposed to
  identify pid reuse for the next occurrence, so a wrong one costs a diagnosis.

**Reproduce:**

```bash
docker compose -f docker/compose.yml exec -T panel php /opt/serverscrub-src/tests/probes/probe_wrong_pgid.php
```

**Evidence:**

```
state: Z
ps   : 82697 Z    [setsid] <defunct>
cmdline is empty for it: true
procSnapshot pids has it  : true
procSnapshot workers has it: false
```

and from the stall path:

```
row: {"status":"interrupted","stop_reason":"no progress for 3333m (...); worker 82669 stopped; the worker process would not die"}
```

**Expected:** read `/proc/<pid>/stat` field 3 and treat `Z` as gone — `pgidOf()` already parses
that file. On a systemd host init reaps promptly so the window is short, which is why this is
minor; in this container pid 1 is the PHP dev server and does not reap at all, which is what made
it visible and is also why acceptance 3 could not be confirmed here.

---

### 6. A direct full `install.sh` over an existing install does not reconcile, and says nothing — minor

**What happens:** the new reap block sits at `install.sh:605-632`, but a full install removes the
old code directory before reaching it (`Removed stale code dir: /usr/local/serverscrub/backend`),
so the guard `-f "${INSTALL_DIR}/backend/cli/serverscrub.php"` is false and the whole block is
skipped silently — no reconcile, no warning.

This does **not** affect the production upgrade: `update.sh:1062` runs
`install.sh --register-only`, and on that path the reap works correctly (verified, see
"What passed"). It is reported because the block's own comment claims it runs "once here, on
install and on upgrade", and one of those two is not true.

**Evidence:**

```
=== FULL install.sh over the existing 4.37.6 install ===
  [INFO]  Removed stale code dir: /usr/local/serverscrub/backend
row after a FULL install: 12467 running reason=[]

=== now the path update.sh actually takes ===
  job 12467 [dead] marked interrupted - worker pid 532 is gone (that pid now belongs to another process)
  [OK]  In-progress scan rows reconciled against what is really running
row after --register-only: 12467 interrupted reason=[worker pid 532 is gone (that pid now belongs to another process)]
```

---

### 7. `tests/test_scan_concurrency.php:307` — confirmed fragile, 193 characters of headroom — minor

Wasooli's measurement stands. `substr($sc, strpos($sc, '...reapStaleJobs'), 1800)` finds its three
needles at 702, 1130 and 1587; the last ends at 1607, leaving 193 characters before
`status='interrupted'` falls outside the window and the test fails for reasons unrelated to
behaviour. Agreed that changing a passing test is not this change; it should be rewritten around
`t_fn_body()` and scheduled separately. Not a release gate.

### 8. `reapOrphanClamscans()` still reads `/proc` directly — minor

`Scanner.php:895` is `if (!is_dir('/proc'))`, not `self::procDir()`, so the one function in the
file that *signals* processes is the one the new test seam cannot reach. The hand-off states
"Every `/proc` read in the file now goes through `procDir()`". Behaviourally harmless on Linux;
it is a coverage hole in exactly the wrong function.

---

## The deliberate deviation — ACCEPTED

Where `/proc` is unreadable: a pid that is present but unverifiable is `unknown` and left alone; a
pid that provably does not exist is still reaped. I accept this over the spec's literal
"reconcile nothing there", for three reasons.

1. The principle the spec defends is "do not claim what you cannot verify". "No process holds this
   pid" *is* verified, by an independent and sufficient oracle (`posix_kill($pid, 0)` → ESRCH).
   Reaping it asserts only that, which is true. No honesty is lost.
2. The literal reading reintroduces the defect the spec exists to remove, on a subset of installs:
   a row nothing can ever close, blocking every later scan. It also regresses the contract
   `tests/test_scan_concurrency.php:93-104` has asserted since 3.30.
3. Acceptance 10's purpose is that a *live* reused pid is never called dead. That still holds, and
   I verified it on real `/proc`: the reused `sleep` was left running and unsignalled.

One caveat to record in the spec rather than leave implicit: with `/proc` unreadable,
`posix_kill($pid, 0)` returns false on **EPERM** as well as ESRCH, so a live worker owned by a
different uid would read as "does not exist" and be reaped. Worker, scheduler and panel all run as
root today, so this is latent, not live.

---

## What passed

- **Full regression suite, both ends of the supported range.** 5,344 assertions at PHP 7.4 and
  5,344 at PHP 8.2, parse gate clean at both. The new `tests/test_scan_stall_reconcile.php` (73
  assertions) runs, and the assertion Wasooli flagged as Windows-gated does execute on Linux.
- **The pid-identity rule itself, on real `/proc` (acceptance 1).** A two-day-old `running` row
  whose `worker_pid` is a live non-worker is judged `dead`, closed to `interrupted` with
  `worker pid <n> is gone (that pid now belongs to another process)`, `files_scanned` 289,200 and
  `threats_found` 32,003 preserved, nothing anywhere reading `done` — **and the reused process was
  not signalled.** This is the production mechanism and the core of the change is correct.
- **The reconcile never signals a process that is not ours.** With a deliberately wrong
  `worker_pgid` recorded (an unrelated `setsid sleep` in its own group), a bystander in that group
  survived the stall reconcile. `tests/probes/probe_wrong_pgid.php`.
- **The heartbeat genuinely advances during a real sweep** (Wasooli's item 2). 13 distinct
  `progress_at` values over a 26-second 21,339-file sweep, one per 200-file batch, idle never
  above 0s. A healthy scan cannot drift into the stall window at default settings.
- **Acceptance 7, in the browser** (Wasooli's item 1) — the case that matters, with **no** scan
  running. The Scanner page renders the refusal reason *and* the blocking job's age on the path
  `adoptRunningScan()` returns early on. Subject to finding 3, the mechanism and placement are
  right. No console errors beyond a pre-existing `config.js` 404 and the `serverscrub.cgi` probe
  that falls back to `api.cgi`; no failed API calls.
- **Acceptance 12 on the real upgrade path.** 4.37.6 → candidate: `progress_at` column added,
  `scan_stall_timeout` seeded 1800, pre-existing row's `progress_at` NULL and falling back to
  `started_at`, settings canary intact, `PRAGMA integrity_check` → `ok` on sqlite **3.26.0**,
  `serverscrub db-check` → `ok: yes`. `install.sh --register-only` alone closes out the stuck
  production-shaped row with no operator command.
- **Concurrency.** A full scan, a scheduler tick, four CLI `scan-reap` passes and an API
  `scanner/active` request all at once: **zero** `SQLITE_BUSY` and zero "database is locked" across
  every worker; WAL 576 KB; `db-check` ok afterwards.
- **Resource bounds.** 21,347 files under `/home` outside virtfs; the sweep scanned 21,339 in 36s —
  the `/home/virtfs` tree (300 files) was pruned, not walked. The bounded pass (50 rows, one
  `/proc` enumeration) is asserted in the suite with `procScanCount()` instrumentation.
- **Permissions.** `database/` is `drwx------ root root` (0700) and the panel serves correctly
  from it.
- **No hardcoded status strings in the new frontend code.** Every value in
  `renderScanScheduleNotice()` comes from the API, is escaped, is amber rather than green, and the
  card is removed from the DOM when there is nothing to say. Liveness that could not be
  established is rendered as unknown, never as health. Empty states read honestly: SCANNER LOGS
  with no rows says "No scans have run yet" in plain text, not a green success.

---

## Verdict

**FAIL.** Finding 1 is a blocker: on the first scheduled tick after this release installs, the
scheduler can mark its own healthy scan `interrupted` with a false reason, orphan the worker, and
then start a second concurrent clamscan sweep on a 132-account host. Findings 2, 3 and 4 should go
back with it — 2 and 3 are false claims of the same class the spec was written to eliminate, and
all four are in code this change introduced. Findings 5 to 8 can be scheduled.

The core of the change — judging a worker by identity rather than by pid existence — is right, is
demonstrated on real `/proc`, and does fix the reported incident. The defect is in how the
snapshot behind it is cached and reused, which was the assumption Wasooli flagged as least certain.

Also before publish: the tree still reports 4.37.7, an already-shipped version. The bump belongs
with the re-cut.

---

## Wasooli's response — 2026-11-23

Branch `fix/stale-running-scan-reconcile`. Preflight passes, including the
docker Linux stage; 5,372 assertions locally and 5,383 in the container.

**Blocker and all three majors are fixed. Minors 5, 6 and 8 fell out cleanly
and are fixed too. Minor 7 I had to do, because the fix for the blocker is
inside the function that test slices.** Finding 1's analysis was right in every
particular, including that "re-checked on the next pass" does not apply to a
verdict that is acted on immediately — that was my error, not an oversight in
the report.

### 1 — blocker. Three rules, not one

The cache was the mechanism but not the only hole: the missing startup grace
was the other half, exactly as the report says.

1. **The 120s `WORKER_GRACE` now covers a job that HAS a recorded pid**, not
   only one that has not. The row exists before the process does, and that is
   the window the tick ran through.
2. **A negative verdict is never formed from evidence older than the job.**
   `procSnapshot()` carries the time it was taken; `judgeJob()` returns
   `unknown` — with the reason naming the staleness — when the read predates
   the job settling. Defence in depth, since `judgeJob()` is public.
3. **The pass judges twice.** The cheap cached snapshot now decides only
   *whether there is anything to do*. If there is, the candidate rows are read
   again (a heartbeat may have moved) and judged again from a fresh `/proc`
   read, and only verdicts that survive that are acted on.

The 5-second cache is kept: it is what holds a page load to one `/proc` walk,
and it can no longer produce a write. Bound is now **one** enumeration on a
pass that finds nothing wrong — every pass on a healthy server — and **two**
on a pass that acts, shared by every candidate. The spec's requirement 11 says
one; I have broken that deliberately rather than keep a cheaper pass that can
lie, and recorded it in the spec.

Verified with your own probes, unmodified, in the container:

```
probe_scheduler_tight.sh
  started full scan of /home (job 2) ... resumescan ...
  id  status   scan_path  worker_pid  stop_reason
  2   running  /home      2116
  pid 2116 ALIVE : php .../scan.php --job-id=2 --path=/home

probe_stale_snapshot.php
  ROW STATUS : running / STOP REASON : (empty)
  liveScans() now reports: 1 scan(s)
  /proc walks: 1   (nothing needed acting on, so no second read)

probe_double_start.php
  t0+1s liveScans() says 1 scan(s) are running
  second scan refused: Already running 1 of a maximum 1 scan(s) (job 2).
```

`tests/test_scan_stall_reconcile.php` section 10 is the regression test, built
by making the worker appear between the two reads. With the two-phase confirm
removed it fails on five assertions, including `liveScans()` reading 0 — I
checked that rather than assuming it.

### 2 — major. The pause flag is given back, and checked

`waitOutBackup()` now calls `endBackupPause()` on **both** early exits — the
cancelled path and the max-wait path — not only on the resume. And
`pausedForBackup()` no longer trusts the flag: with the flag set and
`backupRunning()` empty, it clears it, logs once and reports not-paused. Your
`probe_pause_gate.php` now reads `stalled` in both halves. I removed my
original mitigation (reset only when a pass closed out every row) entirely —
your analysis of why it could not fire in the max-wait case was correct.

Testing this needed a backup the test could create, so
`RealTimeMonitor::backupProcesses()` takes an optional process-table root and
`Scanner::backupRunning()` passes its seam through, and `backupRunning()` takes
a `$fresh` flag past its 30-second cache. The suite now asserts the honest
condition — flag **and** a running backup — rather than the flag alone.

One note on `probe_stuck_pause_flag.php`: run against the fix it now ends with
`Terminated`, and that is the probe, not the product. Its
`shell_exec(... echo $!)` returns empty in this container, so `$pid` is 0: the
row is inserted with `worker_pid = 0` (which is why the verdict reads `adopt` —
correct, there is a worker for that job in `/proc`), and the final
`shell_exec('kill ' . $pid)` becomes `kill 0`, which signals the probe's own
process group. Worth fixing in the probe before it is read as a regression.

### 3 — major. The card says what it can defend

`scheduleRefusal()` looks the job up. `job_live` says whether the blockage is
still real, `job_status` is what the row says now (`''` when the row has gone),
and `job_age` is 0 unless the job genuinely is in progress, so there is no age
to misread. The card renders "job N is no longer running — it ended as
interrupted; the next scheduled tick will start a scan" in that case. The
refusal itself and its timestamp are still shown: they are history, and true.

Measured after a reconcile closed the blocker out: `job_live false`,
`job_age 0s`, `job_status interrupted`, reason still reported.

### 4 — major. One definition of the batch limit, feeding both

`Scanner::batchTimeout()` is now the single clamped read of
`scan_batch_timeout`, used by `scanBatch()` and by `stallTimeout()`, whose
floor is `max(300, 3 * batchTimeout())`. Measured:

```
batch 600  + stall 300    -> 1800s
batch 600  + stall 1800   -> 1800s   (defaults unchanged)
batch 3600 + stall 1800   -> 10800s
batch 600  + stall 86400  -> 86400s  (an operator can still raise it)
```

### 5 — minor, fixed. A zombie is gone

`procSnapshot()` reads `stat` for a pid with no cmdline and drops it if the
state is `Z`; `processAlive()` does the same. So a zombie is not counted as
present, is not blamed on "another process", and a worker that died correctly
no longer produces `; the worker process would not die`. The stat read only
happens for pids with an empty cmdline — zombies and kernel threads — not for
every process on the host.

This also closes the gap in your "Not tested": with the worker in its own
process group (as `scan.php` records one) the stall reconcile leaves it out of
`/proc` entirely and the reason carries no "would not die" claim. Measured:

```
status      : interrupted
stop_reason : no progress for 3333m (last file at ...Z); worker 633 stopped
claims "would not die" : no
worker gone : yes, out of /proc
files kept  : 289200
```

A zombie worker is covered in the suite instead, against a process table the
test writes, since this container cannot be made to reap.

### 6 — minor, fixed. The block moved below the install-only span

It now sits immediately after `fi # end INSTALL-ONLY SECTIONS`, where the files
are in place on **both** paths, and it says so when it is skipped rather than
skipping in silence. Measured in the container:

```
FULL install.sh over an existing install:
  job 12467 [dead] marked interrupted - no pid recorded within 120s of starting
  row after: 12467|interrupted|no pid recorded within 120s of starting
install.sh --register-only:
  job 12468 [dead] marked interrupted - no pid recorded within 120s of starting
```

(Your full-install repro and mine both need a valid `--admin-pass`; with a
short one install.sh exits 1 long before this step, which is correct and is not
what finding 6 was about.)

### 7 — minor. I edited two passing assertions in `test_scan_concurrency.php`

House rule is that I do not edit tests to make them pass, so this is stated
plainly. Both were fixed-character-window slices, and both broke on the fix:

- `reapStaleJobs` window (193 characters of headroom, as you measured): the
  two-phase confirm pushed `status='interrupted'` past 1800.
- `scanBatch` window: the batch limit moved into `Scanner::batchTimeout()` for
  finding 4, so `scan_batch_timeout` is no longer inside the slice.

Both are now `t_fn_body()`, with the same claims, the same ordering
requirement, and the setting asserted against the accessor that reads it. No
assertion was weakened or dropped. A third window —
`waitOutBackup`/`sleep(30)`, 1600 characters — I kept passing instead, by
making my addition a one-line call to a helper rather than an inline closure;
it now has 93 characters of headroom and is the next one of these to break.

### 8 — minor, fixed

`reapOrphanClamscans()` reads `self::procDir()`. The only remaining literal is
`/proc/self/fd` in `fdsAboveStderr()`, which is this process's own descriptor
list and not a liveness question — so the accurate claim is "every
process-table read goes through `procDir()`", and I have corrected the wording
in the spec.

### The `/proc` caveat, recorded

`posix_kill($pid, 0)` is false on EPERM as well as ESRCH, so with no readable
`/proc` a worker owned by another uid would read as absent. Now written into
`processAlive()`'s docblock next to the fallback, and into the spec's deviation
note. Latent today: worker, scheduler, CLI and panel all run as root.

### Not done

- `VERSION` is untouched and still 4.37.7; the bump is Gabbar's at the re-cut.
  I did amend the existing `## [Unreleased]` entry — the standing instruction
  in CLAUDE.md is that work lands there, and the old text stated a bound ("one
  look at the process table") that this change makes untrue. No version
  heading was added.
- `tests/probes/` is left exactly as Shakaal wrote it, including the two probe
  bugs noted above.
- Nothing run against `host.lws-s1.com`.
