# Sentinel Gate 3.31.1

[3.31.1] - 2026-09-28

### Fixed
- **"Paused — jetbackup" over a server with no backup running.** The detector
  added in 3.30.0 matched `jetbackupd` by name and `/jetapps/` in the command
  line. JetBackup runs a *permanent* daemon, and every JetBackup process lives
  under `/usr/local/jetapps` whether or not a backup is happening — so on any
  server with JetBackup installed the monitor suspended itself immediately and
  never resumed. Real-time scanning was permanently off on exactly the servers
  the feature was written for, and the process responsible was an idle daemon
  at 0% CPU, invisible in a CPU-sorted `top`.

  Matching now asks "does this mean a backup is running", not "is this part of
  the backup software". The always-on daemons are excluded explicitly
  (`rt_backup_exclude`), and a JetBackup match requires a command line naming a
  queue or job rather than an install path. `rsync` is unchanged: it only runs
  while it is transferring.

  The same defect was in `RealTimeMonitor::backupProcesses()`, the PHP probe
  added in 3.31.0 — which means auto-resume could never have fired either, as
  the probe always believed a backup was in progress.

- **A pause now records what matched.** The pid and command line are stored and
  shown in the UI, so "Paused — jetbackup" can be checked rather than argued
  with.

- **A suspension could outlive the daemon that set it.** The flags live in the
  database and only the daemon writes them; one killed while suspended never
  reaches its resume path, and its replacement starts with no suspension in
  memory so it never clears them either. The daemon now clears a leftover
  suspension at startup, and the status API refuses to report a suspension when
  the daemon is not running or when the flag has outlived the configured
  maximum.

- **The Real-Time Monitor page never refreshed itself.** It loaded once when
  opened and then showed that snapshot until Refresh was pressed — so a state
  that changes on its own, which is the entire point of pausing and
  auto-resuming, was routinely wrong on screen. The page and the dashboard
  widget now poll every 15 seconds while visible, and stop when they are not,
  when a start/stop is mid-flight, or when the tab is in the background.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
