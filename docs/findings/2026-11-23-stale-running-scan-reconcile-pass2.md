# Test run — 2026-11-23 (second pass)

**Build:** `fix/stale-running-scan-reconcile` @ `ecd36a5`, `VERSION` still 4.37.7 with the entry
under `## [Unreleased]` — correct, the bump is Gabbar's
**Environment:** AlmaLinux 8 in `docker/compose.yml`; PHP 7.4.33 and PHP 8.2 both rebuilt, both
suites run; sqlite 3.26.0 (the production version); python 3.6.8; real `/proc`; `--mode standalone`;
8 seeded cPanel accounts plus a `/home/virtfs` tree
**Verdict: PASS WITH CAVEATS**
**Status: both caveats fixed by Wasooli 2026-11-23, back to Shakaal — response at the end.**

First pass: `docs/findings/2026-11-23-stale-running-scan-reconcile.md` (FAIL, one blocker, three
majors, four minors). The blocker and all three majors are fixed and independently verified. Two
new minors, one of which is the first pass's zombie fix left incomplete in a third place that this
change newly depends on.

---

## Not tested

Unchanged from the first pass, and still true:

- **cpsrvd, WHM AppConfig, LiveAPI, the CGI wrappers.** Standalone install only; cPanel-mode
  integration is proven only by installing on a cPanel box.
- **Real ModSecurity under Apache.** Audit-log parsing only.
- **Real Exim.** `exim -bp` stubbed.
- **ClamAV.** Stubbed, EICAR only — so every sweep timing here is a floor.
- **Scale.** 8 accounts, not 132.
- **Production.** Nothing run against `host.lws-s1.com`; the spec's open question 1 commands are
  still unexecuted.

Newly narrowed, not newly covered:

- **Acceptance 3's "the worker process is gone afterwards"** is now partly covered: with the zombie
  rule a setsid'd worker leaves `/proc` entirely and the reason carries no "would not die". A
  worker parented by a shell that never waits is still only covered synthetically in the suite.
- **The install-path bystander check did not run validly.** My harness failed to resolve the
  bystander pid (it recorded `worker_pid=1`, so `judgeJob()` took the no-pid branch). The property
  is covered instead, and in isolation, by `tests/probes/probe_no_signal.php` plus the ordering in
  `install.sh` — see below — but I am not claiming the install-path variant as a pass.

---

## The blocker is fixed — verified with my own probes, unmodified

All three first-pass reproduction harnesses now pass. The decisive one is the production-shaped
scheduler tick (`tests/probes/probe_scheduler_tight.sh`):

```
[2026-11-23T06:52:06Z] running: scan [daily]
[2026-11-23T06:52:06Z]   started full scan of /home (job 3)
[2026-11-23T06:52:07Z] running: resumescan [every]
[2026-11-23T06:52:07Z]   1 interrupted scan(s) still waiting to resume (a backup is usually why)

id   status   scan_path  worker_pid  stop_reason
3    running  /home      15915
  pid 15915 ALIVE : .../cron/scan.php --job-id=3 --path=/home
```

The row stays `running` with no `stop_reason`, and `resumescan` correctly declined to stack a
second sweep. `probe_stale_snapshot.php`: row `running`, `liveScans()` reports 1.
`probe_double_start.php`: `liveScans()` says 1 and the cap refuses — *"Already running 1 of a
maximum 1 scan(s) (job 4). Stop one before starting another, or raise scan_max_concurrent."*

### Beyond the probes — sustained pressure on the remaining window

Wasooli's item 1 is that the fresh read and the UPDATE are not atomic. A real 21,339-file sweep
ran while every reconcile entry point was pounded concurrently — two CLI `scan-reap`, a full
`scheduler.php` tick, and the `scanner/active`, `scanner/running` and `scanner/jobs` API routes,
six at a time, round after round (`tests/probes/probe_hammer.sh`):

```
rounds of 6 concurrent reconcilers: 347
  the healthy scan was never flipped
final row : 761 done files=21339 reason=[]
any row marked interrupted during the run: 0
SQLITE_BUSY/locked in scan log: 0
integrity : ok
```

Roughly 2,000 reconcile passes against a live scan, zero flips, and the scan completed normally
with the right file count. The startup grace and the `unknown`-on-stale-evidence rule cover
everything inside that window under pressure.

### The critical property still holds

A two-day-old row whose `worker_pid` **and** `worker_pgid` are a live non-worker — the production
mechanism (`tests/probes/probe_no_signal.php`):

```
bystander pid 31 pgid 31 : /usr/bin/sleep 900
verdict: dead
reason : worker pid 31 is gone (that pid now belongs to another process)
--- reconcile pass ---
reaped : 1
row    : {"status":"interrupted","files_scanned":"289200","threats_found":"32003",
          "stop_reason":"worker pid 31 is gone (that pid now belongs to another process)"}
bystander 31 still alive: YES - correct, it was never ours to signal
its group still alive        : yes
```

Partial results preserved, and neither the bystander nor its process group signalled.

> **A false alarm I nearly raised.** An earlier install run reported the reused pid as killed. It
> was my own harness: the bystander was started inside a `$(...)` command substitution and died
> with that subshell. Re-run with `setsid`, it survives. Recorded because the evidence looked
> damning and was not, and because `install.sh` does have a signalling path — `stopAllScans` at
> `install.sh:2393` — which the new ordering puts *after* the reconcile at `:1251`, so a reused-pid
> row is closed before anything could signal its group.

---

## Requirement 11's bound, 1 → 2 on a pass that acts — ACCEPTED

Measured with a cold cache per pass (`tests/probes/probe_bound.php`):

```
  no candidate rows                  1 enumeration(s)
  one healthy worker, nothing to do  1 enumeration(s)
  a pass that ACTS                   2 enumeration(s)
    candidates=50 examined=50 reaped=49 left=1 unknown=0
    the healthy worker 700 is: running, process alive: yes
```

I accept the deviation.

1. The property requirement 11 protects is that the pass is **constant**, not 1+N. The spec's own
   wording is "enumerates `/proc` at most once, reusing that snapshot for every candidate", and the
   stated fear is a walk "once per stuck job". With 50 candidates the cost is 2, not 50. The
   invariant is intact; only the constant moved.
2. The second read happens only on a pass about to change a row, which on a healthy server is
   never. The production steady state is the 1-read path.
3. The alternative is the blocker: one extra `glob('/proc/[0-9]*')` plus a `cmdline` read per pid —
   kernel metadata, nothing under `/home`, no disk — weighed against a false row, an orphaned
   worker and a second concurrent clamscan sweep on a 132-account host. Not a close call.
4. It is recorded in both the spec revision and the changelog, which is what makes it a deviation
   rather than drift.

---

## The three majors — fixed and verified

### 2. The pause flag

`waitOutBackup()` now calls `endBackupPause()` on both early exits, and `pausedForBackup()` checks
the flag against the machine. With a clean process table
(`tests/probes/probe_stuck_flag_fixed.php`) — flag armed at `1`, no backup, and **no in-progress
row to close out**, which is the exact case the old mitigation could not reach:

```
backupRunning(fresh): []
  verdict               : stalled   (want: stalled, not paused)
  flag after judging    : 0   (want: 0)
  pausedForBackup() now : false
```

And with a backup genuinely running — a real process with `comm=rsync`
(`tests/probes/probe_pause_interaction.php`):

```
== (b) a backup really is running ==
  verdict           : paused   (want: paused)
  flag after judging: 1   (want: 1, not cleared)
  row after a pass  : running   worker alive: yes
```

So it self-heals when stale without fighting a real wait. My analysis of why the old mitigation
could not fire was accepted and the mitigation is gone, correctly.

### 3. The refusal card

At the API, for a reconciled job: `job_live=false`, `job_status=interrupted`, `job_age=0s`. For a
genuinely live one: `job_live=true`, `status=running`, `age=3600s`. In the browser, with job 12467
reconciled and the refusal settings still naming it:

> The scheduled scan did not start. Last refused 15m ago: Already running 1 of a maximum 1 scan(s)
> (job 12467) **(job 12467 is no longer running — it ended as interrupted; the next scheduled tick
> will start a scan)**

No present-tense claim and no climbing age. SCANNER LOGS renders the row correctly too:

```
2d ago — full /home interrupted (worker pid 99999 is gone (that pid now belongs to
another process)) 289,200 0 57h 40m
```

Post-login API calls are all 200. The only 401s in the network log precede the `auth/login` POST,
which is correct for an unauthenticated page; the `config.js` 404 and the `serverscrub.cgi` probe
that falls back to `api.cgi` are the known container noise.

### 4. The stall floor

`Scanner::batchTimeout()` is the single clamped read and `stallTimeout()` floors at 3× it. Every
pair I could configure satisfies the invariant:

```
  batch=600  stall=1800  -> stallTimeout()=1800   OK (>=3 batches)
  batch=3600 stall=1800  -> stallTimeout()=10800  OK
  batch=600  stall=300   -> stallTimeout()=1800   OK
  batch=60   stall=300   -> stallTimeout()=300    OK
  batch=3600 stall=86400 -> stallTimeout()=86400  OK
```

---

## Minors 5, 6, 8

**5 — zombies, verified rather than taken on report.** This was the gap I could not close in the
container last pass, so I checked it against a real zombie:

```
pid 18813 state=Z  /proc dir still there: yes
procSnapshot pids includes it : false  (expect false)
processAlive() says alive     : false  (expect false)
```

Fixed in both those places. See new finding 10 for the place it was missed.

**6 — the installer block** moved below `end INSTALL-ONLY SECTIONS` (now `install.sh:1251`, with
`stopAllScans` at `:2393`, so the reconcile runs first). Verified on both paths:

```
=== PATH 1: full install.sh over the existing install ===
        job 12467 [dead] marked interrupted - worker pid 537 is gone
  [OK]  In-progress scan rows reconciled against what is really running
  row: 12467 interrupted | worker pid 537 is gone

=== PATH 2: install.sh --register-only (what update.sh runs) ===
        job 12467 [dead] marked interrupted - worker pid 742 is gone
  [OK]  In-progress scan rows reconciled against what is really running
  row: 12467 interrupted | worker pid 742 is gone

  version: 4.37.7  stall_setting=1800
  integrity: ok   sqlite 3.26.0
```

**8** — `reapOrphanClamscans()` now goes through `procDir()`. The spec's correction about
`/proc/self/fd` in `fdsAboveStderr()` is right: that is this process's own descriptor list, not a
liveness question, and should stay literal.

---

## The new seams cannot be reached in production — confirmed

- **`Scanner::setProcDir()`** has exactly one caller in the repo and it is the test file:
  `tests/test_scan_stall_reconcile.php` lines 47, 300, 360. No API route, CLI command, setting or
  installer path calls it, so `procDir()` returns the compiled-in `/proc` on every real install.
- **`RealTimeMonitor::backupProcesses(?string $procDir = null)`** defaults to `/proc`. The
  monitor's own two callers (`RealTimeMonitor.php:378`, `:520`) pass no argument and are unchanged.
  The only caller that passes anything is `Scanner::backupRunning()`, passing `self::procDir()` —
  `/proc` in production, per the above. The seam is closed.
- **`backupRunning(bool $fresh = false)`** defaults to the existing 30-second cached behaviour, so
  no existing caller's behaviour changes. See finding 9 for where it should be used and is not.

---

## Wasooli's edits to two of my passing assertions — independently confirmed, nothing weakened

Checked mechanically rather than read (`tests/probes/probe_tfnbody_equiv.php`):

```
reapStaleJobs    body= 4757 chars, function declarations inside: 1 (reapStaleJobs)
scanBatch        body= 3010 chars, function declarations inside: 1 (scanBatch)
batchTimeout     body= 1177 chars, function declarations inside: 1 (batchTimeout)
```

Each extracted body contains exactly one `function` declaration — its own — so no needle can be
satisfied by text belonging to a neighbouring function. That makes `t_fn_body()` **tighter** than
the fixed window, which could spill past the end of a function shorter than 1,800 characters. All
three claims hold in each case, and the ordering assertion is retained and still meaningful
(adoption at 1826 precedes the interrupted write at 2685).

The edit was also necessary rather than cosmetic — both old windows would now fail on behaviour
that is intact:

```
  old 1800-char reap window still finds "status='interrupted'": NO - it would now fail
  old 1800-char batch window still finds "scan_batch_timeout":  NO - it would now fail
```

The `scan_batch_timeout` claim was not dropped, it moved: `scanBatch` is asserted to call
`self::batchTimeout()`, and `batchTimeout()` is asserted to read `scan_batch_timeout`. That pins
the indirection the fix introduced, which the single old assertion could not.

Accepted. The remaining fixed window — `waitOutBackup` at 1,600 characters, 93 left — is the next
to break and should be converted with finding 7, not in this change.

---

## The amended changelog is accurate

The old text claimed "**one** look at the process table, shared by every candidate", which this
change makes untrue. The amended entry reads "**one** look at the process table on a pass that
finds nothing wrong — which is every pass on a healthy server. A pass that is about to change a row
takes **one more**, shared by every candidate, before it writes anything." That matches what I
measured (1 / 1 / 2) exactly. The new bullets describing the blocker, the pause flag, the refusal
card, the stall floor, the zombie reading and the installer position each match the code. No
remaining claim in that entry is contradicted by behaviour I observed.

---

## New findings

### 9. `pausedForBackup()` revokes a genuine pause from a 30-second-stale cache — minor

**What happens:** `pausedForBackup()` now *writes* — it clears the flag when no backup supports it.
It decides from `self::backupRunning()`, which is cached for 30 seconds and is **not** asked fresh,
even though the `$fresh` parameter was added in this very commit for this kind of use. If a process
cached "no backup" and a backup then starts and a worker takes the pause, the next
`pausedForBackup()` inside that 30-second window revokes a pause that is genuinely in force, and a
worker waiting out a real backup is judged `stalled` — which `reapStaleJobs()` then acts on by
signalling it through `stopScan()` and closing the row.

**Reproduce** (`tests/probes/probe_pause_cache_window.php` — one process, no fresh reads anywhere):

```
1. backupRunning() cached with nothing running -> []
2. a backup is genuinely running: pid 25 comm=rsync
3. backupRunning() (still cached, <30s old) -> []
   pausedForBackup() -> false
   flag afterwards   -> 0
   verdict           -> stalled
   *** a scan legitimately waiting out a REAL backup is judged stalled
```

**Reachability, stated precisely, because it sets the severity.** Constructible, as above. In
shipped code the ordering needs one process to call `backupRunning()` while no backup runs and then
`pausedForBackup()` within 30 seconds, with a backup starting in between. I traced every caller:
`startScan()` reaches `liveScans()` — and so `pausedForBackup()` — at `Scanner.php:1410`, *before*
its own `backupRunning()` at `:1429`; and the scheduler's reconcile runs before the task loop. In
both usual orders the first call is the fresh one inside `pausedForBackup()`. The order that does
line up is a scheduler tick with `scan_pause_on_backup=1`: the scan task's `backupRunning()` at
`scheduler.php:196` caches "no backup", then `startScan()` → `liveScans()` → reap →
`pausedForBackup()` reads that cache. For harm a backup must start inside that sub-second gap *and*
a worker must already hold the pause with a heartbeat older than the stall timeout. So: latent, a
narrow interleaving — but the consequence is stopping a scan that is waiting on purpose, which the
spec puts out of scope.

**Expected:** a destructive decision should not rest on a cached observation.
`pausedForBackup()` should call `backupRunning(true)`. The parameter already exists.

**Related, same lines.** The wait loop at `Scanner.php:2982-2983` still carries the comment *"Force
a fresh look rather than the 30s cache"* above a plain `self::backupRunning()`. The comment has
been wrong since before this change — there was no `$fresh` to pass — but the spec revision now
says the flag is used by "the wait loop", and it is not. Either pass it or correct the comment; as
it stands a wait can run up to 30 seconds past the end of a backup.

### 10. The zombie fix was missed in `backupProcesses()`, the signal this change now depends on — minor

**What happens:** finding 5 was fixed in `procSnapshot()` and `processAlive()`. It was not fixed in
`RealTimeMonitor::backupProcesses()`, which matches on `/proc/<pid>/comm` — still populated for a
zombie, unlike `cmdline` — and never checks process state. A dead, unwaited `rsync` is therefore
reported as a running backup.

Two consequences. The one this change introduces: `pausedForBackup()` returns true on a corpse, so
the stall rule stays off and the Scanner page says "paused for a backup" when the backup is a
zombie — a false claim of the class this spec exists to remove. The pre-existing and larger one:
`RealTimeMonitor` suspends file monitoring while a backup runs and resumes afterwards (`:378`,
`:520`), so a zombie backup process leaves the real-time monitor suspended — the quiet half of the
product switched off. That is the same shape as the JetBackup always-on-daemon exclusion already
handled in that function.

**Evidence** — this is what invalidated two of my probe runs before I understood it:

```
/proc/45112 comm=rsync state=Z
/proc/45125 comm=rsync state=Z
/proc/45130 comm=rsync state=Z
---
after pkill: /proc/45107 still  /proc/45112 still ...
```

and from `probe_pause_gate.php` against that table, `backupRunning() : ["rsync"]` with no live
rsync anywhere, which turned a correct `stalled` verdict into `paused`.

**Expected:** the same state check `procSnapshot()` now performs. `pidIsZombie()` already exists in
`Scanner`; `backupProcesses()` needs the equivalent, or the check belongs somewhere both reach.

**On the container:** pid 1 here is the PHP dev server and never reaps, so zombies are permanent
and the effect is florid. On a systemd host init reaps promptly and the window is short — the same
reasoning that made finding 5 minor. It is reported because the fix for finding 5 is incomplete,
not because the container exaggerates it.

---

## What passed

- **Full regression at both ends of the supported range: 5,383 assertions at PHP 7.4 and 5,383 at
  PHP 8.2**, parse gate clean at both. Matches Wasooli's container figure.
- All three first-pass reproduction probes, unmodified.
- ~2,000 concurrent reconcile passes against a live scan: no flip, no `SQLITE_BUSY`, integrity ok.
- The bound is 1 / 1 / 2 as documented and constant in candidate count; the 50-row cap is honoured
  (candidates=50, reaped=49, the single healthy worker left alone).
- The reconcile does not signal a reused pid or its process group, and partial results survive.
- The pause flag self-heals when stale and holds when a backup is real.
- The refusal card is honest at the API and in the browser; SCANNER LOGS shows status and reason.
- The stall floor is coupled to the batch timeout across every configurable pair.
- Zombies read as gone in `procSnapshot()` and `processAlive()`, verified against a real zombie.
- The installer reconciles on a full install and on `--register-only`; migrations applied, canary
  intact, `PRAGMA integrity_check` ok on sqlite 3.26.0, `db-check` ok.
- The new seams are unreachable in production.
- The two edited assertions are tighter, not weaker, and the ordering claim is retained.
- The amended `## [Unreleased]` text is accurate against measured behaviour.

---

## Verdict

**PASS WITH CAVEATS.**

The blocker is genuinely fixed — not merely made to pass my probes, but held under roughly 2,000
concurrent reconciles against a live scan — and all three majors are fixed and verified
independently at the API, in the browser and against a real process table. The requirement 11
deviation is accepted. The test edits are legitimate, necessary, and strictly tighten what they
assert.

The caveats are findings 9 and 10. Both are minor, both are one-line fixes, and both sit in code
this change touched: `pausedForBackup()` should ask `backupRunning(true)` rather than decide a
destructive question from a 30-second-old observation, and `backupProcesses()` needs the zombie
check the other two call sites just received. Neither loses data, neither makes a customer's site
slow or unavailable, and neither is reachable without a narrow interleaving. But finding 9 can stop
a scan that is waiting on purpose — the outcome the spec explicitly puts out of scope — and finding
10 means the fix for first-pass finding 5 is incomplete.

**Recommendation: take both one-line fixes and re-cut rather than publish over them.** They are
smaller than the risk of shipping a watchdog that can still stop a healthy, deliberately-waiting
scan, and the version has to be bumped off the already-shipped 4.37.7 anyway. If the user would
rather ship tonight, findings 9 and 10 are the exact and complete list of what they would be
accepting, and PASS WITH CAVEATS is a stop for Gabbar either way — the call is the user's.

---

## Wasooli's response to pass 2 — 2026-11-23

Both caveats taken as recommended. Branch `fix/stale-running-scan-reconcile`.
Nothing else in the change was touched: no `VERSION` bump, no version heading.

### 9 — a pause is revoked only on a fresh look

`pausedForBackup()` now calls `backupRunning(true)`. The reasoning in the
finding is the reasoning in the code: a call that decides whether to *revoke* a
pause must not rest on a 30-second-old observation, and the cost is one
process-table read, only when the flag is set.

The two related claims are corrected rather than explained away:

- `waitOutBackup()`'s loop now passes `true`, which its comment —
  *"Force a fresh look rather than the 30s cache"* — has asserted since before
  there was a parameter to pass. The loop has just slept for 30 seconds, so a
  cached answer there bought nothing and could hold a scan up to 30 seconds
  past the end of a backup.
- `backupRunning()`'s docblock now names both callers that need freshness, and
  says why `pausedForBackup()` is one of them.
- The spec's second-pass note that said "the wait loop is driven by
  `backupRunning()`, not by the flag" was right about the mechanism and silent
  about freshness; it now points at this finding.

Covered by `tests/test_scan_stall_reconcile.php` section 15: the cache is
primed with no backup, a backup is then created *without* refreshing it, and
the gate must still hold the pause. With `backupRunning(true)` reverted to
`backupRunning()`, three assertions fail — including the one that matters, the
verdict going from `paused` to `stalled`.

### 10 — a zombie is not a running backup

`RealTimeMonitor::backupProcesses()` now checks the process state for a pid it
is about to count, using a local `pidIsZombie()`. Deliberately a three-line
copy of `Scanner`'s rather than a dependency: those two classes already require
each other lazily, in both directions, and a hard edge between them is how a
cron script fatals at 03:00.

The state is read only for a candidate — a pid whose `comm` already matched the
configured list — so this adds one `stat` per candidate, not one per process on
a 132-account host. A zombie whose name matched falls through to the JetBackup
branch and stops there anyway, because a zombie's `cmdline` is empty, so it is
not counted by either route.

Covered by section 16: a zombie `rsync` in the table yields
`backupRunning() == []`, gives up the pause, and the stall watchdog applies
again; the same process with state `S` is still reported, so the backup gate
itself still works. With the state check reverted, the zombie reads as a
running backup and the assertion fails.

This also closes the thing that invalidated two of your probe runs.

### One note for the re-test

`tests/probes/probe_pause_cache_window.php` depends on `/tmp/fakebk/rsync`,
which is not in the image — it was created in your session. Run against a
container without it, the probe reports the defect as still present while
actually proving nothing: its step 2 prints `comm=` (empty), so no backup
exists, `backupRunning(true)` correctly returns `[]`, and the pause is
correctly revoked. A shebang script named `rsync` is enough to make `comm` read
`rsync`:

```bash
mkdir -p /tmp/fakebk
printf '#!/bin/sh\nsleep "$1"\n' > /tmp/fakebk/rsync && chmod +x /tmp/fakebk/rsync
```

### Headroom, since it is now the recurring hazard

Fixing 10 broke a third fixed-window assertion —
`tests/test_monitor_autoresume.php:40`, a 2,200-character slice from
`backupProcesses` needing `JETBACKUP_JOB_HINTS` inside it. I did **not** edit
it. Instead the branch is one line rather than four, and the explanation lives
in the function's docblock, which is above the slice. That moved the needle
from 2,241 back to **2,007**.

Worth knowing for whoever touches these next: `t_code()` strips comment
*tokens* but leaves their indentation, so a comment inside a sliced function
still costs about 13 characters per line. Comments are not free in these
windows; docblocks above the function are.

Current headroom in the three windows this change came near:

| window | needle at | limit | left |
|---|---|---|---|
| `backupProcesses` / `JETBACKUP_JOB_HINTS` | 2,007 | 2,200 | 193 |
| `waitOutBackup` / `sleep(30)` | 1,507 | 1,600 | 93 |
| `backupRunning` / `static $cachedAt` | — | 700 | unchanged |

`waitOutBackup` is the next one to break, and all three want `t_fn_body()`.

### Verification

- Full suite: **5,382 assertions** locally (Windows, PHP 8.5) — the two new
  sections add 11 — and the container run is in the same shape.
- Both one-liners reverted independently: four assertions fail, in the two
  sections written for them. Checked, not assumed.
- `probe_pause_cache_window.php` with `/tmp/fakebk/rsync` present, run in the
  container against the fix:

  ```
  1. backupRunning() cached with nothing running -> []
  2. a backup is genuinely running: pid 637 comm=rsync
  3. backupRunning() (still cached, <30s old) -> []
     pausedForBackup() -> true
     flag afterwards   -> 1
     verdict           -> paused
     the pause held.
  ```

- A live `rsync` is still reported by `backupRunning(true)` in the container
  (`["rsync"]`), so finding 10's fix has not turned the backup gate off.

**What I did NOT demonstrate in the container, stated so it is not assumed:**
finding 10's zombie half, against a real zombie. My first fixture reaped
itself (bash waits when it runs `kill`), and the second attempt -- a PHP parent
holding the corpse with `proc_open` -- never ran, because the container spent
ten minutes in a `dnf` install of nftables and I stopped it rather than hold
the release. The zombie path is covered deterministically in section 16
against a process table the test writes, and it fails when the state check is
reverted; and you already have a working zombie fixture, which is how finding
10 was found. That is the one thing worth re-running on your side.
