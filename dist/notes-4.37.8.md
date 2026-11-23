# ServerScrub 4.37.8

[4.37.8] - 2026-11-23

### Fixed

- **A scan whose worker was gone kept the daily schedule from running for two
  days, and the panel reported it as "running" throughout.** From a live
  server: a scheduled full `/home` scan sat at `status='running'` for 57 hours
  with 289,200 files recorded, and the daily sweep did not start once in that
  time. Reported as "Scanner logs still show its running, thats ridiculous."

  Reconciliation was built, shipped and being called from five places. It was
  returning **zero**, because liveness was decided by
  `is_dir('/proc/' . $pid)` — which asks whether *some* process holds that
  number, never whether it is this job's scan worker. On a host with 132
  accounts the pid space wraps in hours, so the dead worker's pid had been
  reused by a php-fpm child or a cron and the row read alive for ever. Every
  fifteen minutes the scheduler then found a scan "already running", declined
  to stack a second one — correctly — left the task due, and logged one line
  nobody was tailing. The same row also blocked `update.sh`'s post-update
  resume.

  A worker is now judged alive only when `/proc/<pid>/cmdline` names
  `backend/cron/scan.php` **and this job's id** — the way `scanWorkerPids()`
  has always identified one, which `jobWorkerAlive()` only ever reached for
  when the pid was *absent*. The job id is matched as a whole number too:
  `--job-id=124` was a prefix match for the worker of job 1247, which could
  adopt one job's worker onto another job's row.

- **A scan worker that was alive but had stopped working was never
  reconciled.** `recordProgress()` wrote two counters per batch and no
  timestamp, so nothing could tell a scan that was scanning from one wedged in
  uninterruptible IO. The only stall detection in the product was in the
  browser, which could print a hint and take no action.

  `scan_jobs` gains a `progress_at` heartbeat, written by the same statement
  that already wrote the counters — same cadence, no extra write. A job whose
  worker is alive and identity-confirmed but has reported nothing for
  `scan_stall_timeout` (default 1800s, clamped 300–86400) is stopped through
  the existing `stopScan()` path and the row closed out. A row that cannot be
  made true by killing is still made honest: if the process survives, the
  reason says so. A scan asleep on purpose for a backup is **not** stalled and
  is left alone, however old its heartbeat.

- **Nothing reconciled on a tick of its own.** The pass now runs at the start
  of every scheduler tick, before the task loop and independently of
  `scan_schedule` — a server whose schedule is `off` is exactly the one where a
  stuck row would never be looked at again, because reconciliation only
  happened as a side effect of a scan being due. `GET scanner/jobs` reconciles
  before it lists, so the Scanner page an operator is staring at can no longer
  be the one place guaranteed to keep showing a dead scan. The pass also runs
  once from `install.sh --register-only`, so the row already stuck on a server
  is closed out by installing the release rather than by an operator running a
  command.

  Bounded, because this is a 132-account server: at most 50 candidate rows per
  pass, and **one** look at the process table on a pass that finds nothing
  wrong — which is every pass on a healthy server. A pass that is about to
  change a row takes **one more**, shared by every candidate, before it writes
  anything. Nothing under `/home` is touched and no directory is walked.

- **No reconcile acts on evidence older than the job it is judging.** Found in
  review, on the first scheduled tick: the snapshot of the process table is
  cached for seconds and shared across a process, and the scheduler is one
  process that runs for minutes. It reconciled at the top of a tick, the scan
  task started the daily scan, and a later task in the same tick reconciled
  again from the cached snapshot — which predated the worker. The row was
  rewritten to `interrupted`, `worker pid 36488 is gone`, while pid 36488 was
  running that exact job.

  Three faults at once, and all three are the thing this release exists to
  prevent: a false claim that a worker is gone; a worker orphaned with no row
  able to find or stop it; and `liveScans()` reading zero, which defeated the
  one-scan-at-a-time cap and let a **second** clamscan sweep start on a server
  where each one loads the whole signature database into its own memory. It
  also reinstated the original bug in a new form — the daily scan starts, is
  orphaned, never finishes.

  Three rules now stop it. The 120-second startup grace covers a job that
  **has** recorded a pid, not only one that has not (the row exists before the
  process does). A judgement from a process-table read taken before the job
  settled returns `unknown`, not `dead`. And a pass re-reads both the rows and
  `/proc` before it acts, so a heartbeat that moved in between, or a worker the
  first read missed, is seen.

- **A backup pause left behind by a worker no longer switches the stall rule
  off for ever.** `waitOutBackup()` wrote `scan_paused_for_backup=1` and
  cleared it only when the backup finished: a scan cancelled while waiting, or
  one that gave up after `scan_backup_max_wait` (four hours), left it set. From
  then on every worker was judged "paused" however long it had been silent, and
  the panel reported a backup that had been over for hours. It is now given
  back on every exit from the wait, and the flag is checked against the machine
  before it is believed — a pause nothing is running is cleared on sight.

  That check is made on a **fresh** reading of the process table, not the
  30-second cached one. Revoking a pause is a destructive decision: a cached
  "no backup" was enough to throw away a pause that was genuinely in force, and
  the reconcile would then have stopped a scan that was deliberately waiting.
  The wait loop itself now asks freshly too — its comment has claimed that
  since before there was a way to ask, so a wait could run up to 30 seconds
  past the end of a backup.

- **A dead `rsync` is no longer reported as a running backup.**
  `/proc/<pid>/comm` survives into the zombie state — unlike `cmdline`, which
  empties — and the backup probe matched on the name alone. So an exited,
  unwaited backup process stood the whole gate up: the Scanner page claimed a
  backup, the stall watchdog stood down, and the real-time monitor, which
  suspends itself while a backup runs, stayed suspended with a corpse holding
  the pid. The state is now checked for any process about to be counted as a
  backup — one stat read per candidate, not one per process on the server.

- **The refusal card no longer claims a job is in progress after the product
  has closed it out.** It was built from four stored settings and computed the
  blocking job's age without asking whether that job was still running, so the
  Scanner page said "in progress for 2d 9h", with the age still climbing, for a
  job that had just been marked `interrupted` — and for one that did not exist
  at all. The age is only sent when the job really is in progress; otherwise
  the card says what became of it.

- **`scan_stall_timeout` is now floored at three batch timeouts.** The two
  settings were clamped independently (`scan_batch_timeout` 60–3600, the stall
  300–86400), and progress is only recorded when a batch *completes*, so a
  legal pair — a 3600s batch against the default 1800s stall, or the documented
  minimum 300s stall against the default 600s batch — had the watchdog stopping
  a scan that was working through one slow archive. The defaults were safe; the
  combination was not. One definition of the batch limit now feeds both.

- **A zombie worker is read as gone, which it is.** Liveness was
  `is_dir('/proc/<pid>')`, true for a process that has exited and not yet been
  waited on. Two false statements came out of that: `stopScan()` reporting that
  a worker "would not die" when it had died correctly, and a reconcile blaming
  "another process" for a pid that was still the same worker, unreaped — and
  that second sentence is the one that is supposed to identify pid reuse for
  whoever reads the row next.

- **A full `install.sh` over an existing install reconciles too.** The pass sat
  above the install-only section, where on a full install the CLI it calls does
  not exist yet — the old code directory has been removed and the new one is
  copied further down — so the guard was false and the whole step was skipped
  in silence, on one of the two paths its own comment claimed. It now runs
  after the files are in place, on both paths, and says so when it cannot run.

- **A reconciled scan now says what happened to it.** It ends at
  `interrupted` — the status the UI already renders red — with `finished_at`
  and a specific `stop_reason`: `worker pid <n> is gone (that pid now belongs
  to another process)`, `no pid recorded within 120s of starting`, or `no
  progress for <n>m (last file at <time>); worker <n> stopped`. It also raises
  a warning security event, so it appears in Recent events on the dashboard
  rather than only in a log file. `serverscrub scan-reap` reports its decision
  per job, including the jobs it deliberately left alone and the ones it could
  not judge — "Stale jobs cleared: 0" was true and useless on the server that
  needed it. Partial results are kept: `files_scanned`, `threats_found` and
  the `threats` rows stand, and a reconciled job is never reported as `done`.

- **Where liveness cannot be established, it is reported as unknown.** On a
  host with no readable process table, a pid that exists cannot be confirmed as
  this scan, so the row is left exactly as it was and the pass says it could
  not judge — a wrong "dead" verdict would kill scans that are working. A pid
  that provably does not exist anywhere is still closed out; that claim can
  still be verified.

- **Two days of silent 15-minute refusals are now visible on the Scanner
  page.** Declining to start a second scan is the correct outcome and was
  invisible outside one cron log line. The scheduler records the refusal, and
  the page says what is in the way and how long it has been running — which is
  the part of this incident that made it undiagnosable.

### Known limitations in this release

Stated rather than left to assume. All of this was verified in a container on
AlmaLinux 8 against PHP 7.4 and 8.2, a real `/proc` and a real sqlite — but a
container is not your server.

- **Nothing in this release was run against production.** Which of the two
  mechanisms — a reused pid or a silent heartbeat — actually stalled the 57-hour
  job on the live server is still read out of the code, not observed. After this
  release the row's own `stop_reason` answers it the next time it happens.
- **There is still no cap on how long a scan may run, deliberately.** A full
  `/home` scan on that server took 57h41m against a *daily* schedule. This
  release makes the resulting overlap visible on the Scanner page instead of
  silent; it does not decide what should happen. That policy call is still
  open.
- **Only the standalone install path was exercised.** cpsrvd, WHM AppConfig,
  LiveAPI and the CGI wrappers are proven by installing on a cPanel box, and
  that has not been done for this build.
- **Scale was 8 seeded accounts, not 132.** The resource bounds (one process
  table read on a healthy pass, two on a pass that acts, 50 candidate rows per
  pass, nothing under `/home` walked) were measured, not estimated — but at
  that size.
- **ModSecurity, Exim and ClamAV were stubbed.** Audit-log parsing, `exim -bp`
  and EICAR only. Every sweep timing recorded for this work is therefore a
  floor, not a worst case.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
