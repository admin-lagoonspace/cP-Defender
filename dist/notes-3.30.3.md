# Sentinel Gate 3.30.3

[3.30.3] - 2026-09-28

### Fixed
- **Nothing limited how many scans ran at once.** Reported from a live server:
  six `clamscan` processes together, each holding 650MB-1.3GB of RSS and taking
  roughly half the CPU.

  `Scanner::startScan()` inserted a job and spawned a detached worker with no
  check for one already in progress, and every route into it -- the UI button,
  the CLI, the scheduler -- did exactly that. Concurrency is not a tuning
  question for this program: every `clamscan` process loads the entire ClamAV
  signature database into its own memory, so six scans meant six copies of the
  same database and six processes competing for the same disks. One scan that
  finishes sooner is strictly better.

  There is now a single-flight guard in `startScan()`, and an exclusive
  `flock()` in the worker that covers what the guard cannot see: a cron entry
  firing during a manual scan, duplicate cron entries left by an upgrade, or
  the script run by hand. A worker that loses the race records `skipped` and
  exits 0, because declining to stack a second scan is the correct outcome and
  not something to page anybody about.

- **The scheduler started one scan per configured path, in parallel.** It
  called `startScan()` in a loop, and each call spawns a detached worker
  immediately -- so three scan paths meant three scans and three `clamscan`
  processes every scheduled run, by design. It now starts one job covering
  every path, and the worker walks them in turn, honouring a stop request
  between paths as well as between batches.

- **A killed worker left its job at `running` for ever**, since a process that
  is killed never reaches the code that sets a final status. Enough of those
  and the database claims several scans are in progress when none are. Stale
  jobs are now reaped and recorded as `interrupted` -- never as `done`, which
  would report an abandoned scan as a completed one.

- **A single `clamscan` invocation had no time limit.** One was found holding
  13 minutes of CPU and 1.3GB of RSS on one file, blocking its worker for all
  of it. Each batch is now bounded by `timeout(1)` (`scan_batch_timeout`,
  600s); threats reported before the cut-off are kept, and only the rest of
  that batch is lost.

- New `scanner/reap` route and `sentinel scan-reap` command to clear dead jobs
  and kill `clamscan` processes their workers left behind. Orphans are matched
  by process group against a dead worker, never by process name: cPanel runs
  its own `clamscan` for mail, and a name-based reaper would kill that too.

### Security
- **Stopping a scan could have signalled the web server.** `posix_setsid()`
  fails when the process is already a group leader, and 3.30.1 fell back to
  whatever `posix_getpgid(0)` returned -- the process group of whatever
  launched the worker, which is cpsrvd or php-fpm. `stopScan()` signals that
  group, so stopping a scan would have sent `SIGTERM` to every process in it.
  The group is now recorded only when the worker genuinely leads it; otherwise
  nothing is stored and only the worker pid is signalled.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
