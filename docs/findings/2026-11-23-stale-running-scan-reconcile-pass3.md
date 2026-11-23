# Test run — 2026-11-23 (third pass, confirmation)

**Build:** `fix/stale-running-scan-reconcile` @ `5fb5fd2`. `VERSION` untouched at 4.37.7, entry
under `## [Unreleased]`, no version heading — correct, that is Gabbar's.
**Environment:** AlmaLinux 8 in `docker/compose.yml`; PHP 7.4.33 and PHP 8.2 both rebuilt and both
suites run; sqlite 3.26.0; python 3.6.8; real `/proc`; `--mode standalone`
**Verdict: PASS**

Scope: confirm findings 9 and 10 from
`docs/findings/2026-11-23-stale-running-scan-reconcile-pass2.md`, close the one gap Wasooli
declared open, and re-run the regression at both ends of the supported range. Everything from the
first two passes stays as verified there; nothing in this commit touches it, and I re-ran the
safety probes to confirm that rather than assume it.

The product diff is four lines of behaviour and a lot of explanation:
`pausedForBackup()` → `backupRunning(true)`; the wait loop → `backupRunning(true)`;
`backupProcesses()` → `isset($names[$comm]) && !self::pidIsZombie($dir)`; plus a local three-line
`pidIsZombie()`. The `Database.php` change is comment-only.

---

## Finding 9 — fixed, and the probe now discriminates

`tests/probes/probe_pause_cache_window.php`, with `/tmp/fakebk/rsync` present:

```
1. backupRunning() cached with nothing running -> []
2. a backup is genuinely running: pid 711 comm=rsync
3. backupRunning() (still cached, <30s old) -> []
   pausedForBackup() -> true
   flag afterwards   -> 1
   verdict           -> paused
   the pause held.
```

Line 3 is the part that matters: the stale cache is **still there and still says `[]`**, and the
pause is held anyway. So this proves the fresh read is being taken, not merely that the cache
happened to be warm — which is the failure mode the coordinator warned about and which would have
made a green result meaningless.

I agree with extending it to `waitOutBackup()`'s loop. The comment asserted a fresh look before
there was a parameter to pass, and the loop has just slept 30 seconds, so the cache could only ever
cost accuracy. `backupRunning()`'s docblock now names both callers that need freshness, and the
spec note that wrongly implied the loop was already fresh points at the finding instead of
restating the error.

**One observation, not a finding.** The documented bound ("one look at the process table on a
healthy pass, one more on a pass that acts") counts `Scanner::procSnapshot()` only.
`backupProcesses()` does its own walk, and `pausedForBackup()` is reached from `judgeJob()` once
per candidate. I measured whether that scales (`tests/probes/probe_pause_walk_cost.php`):

```
flag SET, a real backup, one identity-confirmed paused worker:
  1 candidate                                2 ms  procSnapshot=1  candidates=1 reaped=0 left=1
  50 candidates (49 of them to be reaped)  191 ms  procSnapshot=2  candidates=50 reaped=49 left=1

flag CLEAR (the healthy steady state):
  1 candidate, flag clear                 2324 ms  procSnapshot=2  candidates=1 reaped=1 left=0
```

It does not scale with candidate count. The pause check sits behind `$mine === $id`, so it is
reached only by a row whose recorded pid *is* its own live worker — bounded by `maxConcurrent`
(1 here), not by the 50-row candidate cap. With the flag clear — every pass on a healthy server —
`pausedForBackup()` returns before any walk, so the extra cost is zero. The 2,324 ms on the last
line is not a walk either: it is `stopScan()`'s deliberate 10 × 200 ms wait, because clearing the
flag correctly turned that worker's verdict into `stalled`. Worth a clause in the bound's wording
at some point; not worth holding a release.

---

## Finding 10 — fixed, and the gap is closed

Wasooli was straight about this rather than letting it be assumed: the zombie half rested on the
suite and had not been shown against a real zombie in the container, because the first fixture
reaped itself and the retry ran out of time. That was the one thing asked of me, so here it is.

**Why the obvious fixture fails, and what works.** Do not rely on pid 1 failing to reap — in this
image pid 1 is `bash entrypoint.sh` during the install, which *does* reap inherited orphans, and
only becomes `php -S` once serving. A `setsid`-and-kill fixture is therefore a coin toss depending
on how far through the install the container is; mine vanished entirely on the first attempt. The
reliable construction is to keep the **parent** alive and never wait: `proc_open()` the child, let
it exit, and never call `proc_close()` or `proc_get_status()` — both of which reap it. The child is
then a zombie for as long as the script runs, whatever pid 1 does. The fixture must also be a copy
of a **binary** (`comm` is the executable name, so a `#!/bin/sh` script named something else reads
as that name — I confirmed a script called `rsync-sh` reports `comm=rsync-sh`).

`tests/probes/probe_zombie_backup.php`, on real `/proc`:

```
pid 1 here       = php -S 0.0.0.0:8777 ...

== a REAL zombie whose comm is still rsync ==
  state                  : Z   (want Z)
  /proc/696 present      : yes
  comm                   : "rsync"   <- the name a corpse keeps
  cmdline                : ""        <- and the thing it loses

  backupProcesses(/proc) : []   (want [] -- a corpse is not a backup)
  backupRunning(fresh)   : []   (want [])

== so the stall watchdog is not stood down by a corpse ==
  a worker silent for 55h, flag left at 1 by a worker that was killed
  verdict                : stalled   (want stalled, NOT paused)
  flag after judging     : 0   (want 0)

== and a LIVE rsync is still detected -- the fix must not blind the gate ==
  live pid 700 state=S   (zombie 696 is still state Z alongside it)
  backupProcesses(/proc) : ["rsync"]   (want ["rsync"])
  verdict                : paused   (want paused)
  flag                   : 1   (want 1)
  the waiting worker is still alive: yes
```

Both directions, and the second is the one that makes the first mean something: with a live `rsync`
and the zombie present **at the same time**, the gate fires on the live one and the waiting worker
is left alone. So the state check did not blind the backup gate, which is the regression a careless
version of this fix would have introduced.

The three-line `pidIsZombie()` copy rather than a cross-class dependency is the right call.
`Scanner` and `RealTimeMonitor` already `require_once` each other lazily in both directions; a hard
edge between them is how a cron entry point fatals, and this product has shipped that defect before.
Three lines of duplicated `/proc/<pid>/stat` parsing is the cheaper risk, and both copies carry a
comment naming the other.

Reading the state only for a pid about to be *counted* is also right: one `stat` per candidate, not
one per process on a 132-account host, on a walk that runs from cron every fifteen minutes for the
life of the server.

---

## The broken slice Wasooli did not edit — confirmed, and the resolution is the better one

`tests/test_monitor_autoresume.php:40` reads a 2,200-character window from `backupProcesses`.
Fixing finding 10 inside that function would have pushed its needle out. Wasooli did not touch the
test: the branch became one line and the explanation went into a docblock *above* the slice start.
Measured (`tests/probes/probe_slice_headroom.php`):

```
-- test_monitor_autoresume.php:40  substr(backupProcesses, 2200) --
   rt_backup_procs            at 268
   ALWAYS_ON_BACKUP_DAEMONS   at 884
   JETBACKUP_JOB_HINTS        at 1997
   comm                       at 1149
   pidIsZombie                at 1432
```

Every needle is inside the window, the furthest at 1997 of 2,200. That matches the reported 2,007
within measurement noise. This is the resolution I would have asked for — the fix was shaped to fit
the existing assertion rather than the assertion rewritten to fit the fix, which is the opposite of
what I had to scrutinise last pass.

**The `t_code()` mechanism is real**, and worth recording because it will catch someone again:

```
   raw file     : 38920 chars
   after t_code : 25449 chars
   lines that are now whitespace-only: 109, carrying 96 chars of surviving indentation
```

`t_code()` strips comment tokens but leaves the line and its indentation, so a comment *inside* a
sliced function still costs roughly its indentation width per line, while a docblock *above* the
slice start costs nothing. That is exactly why moving the explanation up worked.

**And the next one to break, confirmed:**

```
-- test_scan_concurrency.php:388  substr(waitOutBackup, 1600) --
   sleep(30)                  at 1495
   scan_backup_max_wait       at 645
   scan_paused_for_backup     at 1406
   window 1600; furthest needle ends at 1504; headroom 96
```

96 characters (reported as 93 — same number, different measurement point). Together with
`test_monitor_autoresume.php:40` and `:142`, these are the remaining fixed-character windows in
this area. They should be converted to `t_fn_body()` with first-pass finding 7, as a change of
their own. Not a release gate, and deliberately not done here.

---

## Nothing else regressed

Re-run on `5fb5fd2`, because these two fixes touch the gate that `judgeJob()` consults:

- **The bound is unchanged:** 1 enumeration idle, 1 on a healthy pass, 2 on a pass that acts;
  50-row cap honoured (`candidates=50 reaped=49 left=1`) and the one healthy worker left `running`
  with its process alive.
- **The no-signal property holds:** a row whose recorded pid and pgid are a live non-worker is
  closed with `worker pid 736 is gone (that pid now belongs to another process)`, `files_scanned`
  289,200 and `threats_found` 32,003 preserved, and the bystander **and its process group** left
  running.
- **The stuck-flag self-heal holds:** flag at `1`, no backup, no row to close out → verdict
  `stalled`, flag cleared to `0`.

**Suite: 5,393 assertions at PHP 7.4 and 5,393 at PHP 8.2**, parse gate clean at both. (The
coordinator's 5,382 is the local figure; the container has always run higher, as in both earlier
passes.) Sections 15 and 16 of `tests/test_scan_stall_reconcile.php` run and cover both fixes
including the discrimination case — *"a live rsync is still reported, so the backup gate itself
still works"*.

I did not independently verify the claim that reverting either one-liner fails four assertions,
because doing so means editing product code, which is not mine to touch. I verified the behaviour
directly against a real backup and a real zombie instead, which is the stronger check.

---

## The spec note and changelog are accurate

Both describe the two fixes correctly, and the spec's second revision states plainly that the
zombie half had **not** been re-demonstrated against a real zombie rather than implying it had.
That is the thing that let me go and close it, and it is the behaviour I want from a hand-off.
Checked: the correction to the earlier note about the wait loop being "driven by `backupRunning()`"
now points at the finding instead of repeating the error.

---

## Not tested — unchanged, and still true of the release

- **cpsrvd, WHM AppConfig, LiveAPI, the CGI wrappers.** Standalone install only; cPanel-mode
  integration is proven only by installing on a cPanel box.
- **Real ModSecurity under Apache.** Audit-log parsing only; rule evaluation and `SecRuleEngine`
  actually blocking are not exercised.
- **Real Exim.** `exim -bp` stubbed.
- **ClamAV.** Stubbed, EICAR only — every sweep timing in these three reports is a floor.
- **Scale.** 8 seeded accounts, not 132.
- **Production.** Nothing run against `host.lws-s1.com`. The spec's open question 1 commands are
  still unexecuted, so which of the two mechanisms fired on the real server is still read out of
  the code. After this release the row's own `stop_reason` answers it without anyone being asked,
  which is the right outcome but is not the same as knowing now.
- **Open question 2 stands:** there is still no cap on scan duration, deliberately. A full `/home`
  scan on that server ran 57h41m against a daily schedule; requirement 12 makes the overlap
  visible rather than resolving it. That is a policy decision someone still has to make.

---

## Verdict

**PASS.**

Findings 9 and 10 are fixed, and both are verified by behaviour rather than by source reading —
finding 9 with my own probe in a state that proves the stale cache was present and ignored, finding
10 against a genuine zombie (state `Z`, `comm=rsync`, empty `cmdline`) with a live `rsync` beside
it to show the gate still fires. The gap Wasooli declared open is closed. Nothing from the first
two passes regressed: the bound, the no-signal guarantee and the pause self-heal all still hold on
this commit. 5,393 assertions pass at both ends of the supported PHP range, on sqlite 3.26.0.

Every finding raised across all three passes — one blocker, three majors, six minors — is either
fixed and verified, or explicitly deferred with my agreement: first-pass finding 7 (the remaining
fixed-character test windows, now three of them, with 96 characters of headroom on the tightest)
is the only outstanding item, it is test-only, and it belongs in a change of its own.

`VERSION` is still 4.37.7 with no version heading, which is correct — but it does mean the tree
currently identifies itself as an already-shipped release, so the bump off 4.37.7 has to happen as
part of publishing. That is Gabbar's step, not a defect here; I flag it only so it is not assumed
done.

**Clear to release**, as a Z bump off 4.37.7 — no new status, no new page, one additive column and
one new setting — with the untested surfaces above stated to the operator rather than left implied.
