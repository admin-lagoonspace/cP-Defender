# Sentinel Gate 3.20.0

[3.20.0] - 2026-08-27

Module audit, items 2 to 5. Minor rather than patch: modules that were never
run now run on a schedule, and the write paths became testable.

### Fixed
- **Real-Time Monitor showed "Active" beside empty counters.** `service_active`
  was actually `isServiceEnabled()` - enabled means "starts at boot", not
  "running now". `isRunning()` also trusted only the PID file, which the daemon
  writes itself into tmpfs, so a lost file made a running monitor look stopped.
  Systemd is consulted now, and enabled/active/installed are reported
  separately. A monitor that is running but has reported no activity for an hour
  is shown as "No activity" rather than green.
- **Bot Shield, CMS Guard, rootkit and file integrity were never run by
  anything.** The cron dispatcher had exactly three tasks: scan, sigs, iprep.
  Every one of those panels reads a database table, and nothing wrote to those
  tables unless a human pressed a button, so they showed zero for ever. All four
  are scheduled now.
- **Security Events had two writers in the whole product** - a failed login and
  one firewall path - so the page was empty even on a server actively finding
  malware. Malware detections and bot blocks now raise events.
- **The scan file count never moved.** `files_scanned` was written once, when
  the job finished, and the value was `countFiles()` re-walking the directory
  afterwards - a census of files present, not a count of files examined. A scan
  stopped part-way left 0 for ever. ClamAV is now run in batches with progress
  recorded after each, and the pattern engine reports as it walks.
- **The scan worker was launched with a bare `php`.** That relies on PATH; the
  API runs under cpsrvd, which is not a login shell. It uses PHP_BINARY now.
- **`Firewall` and `IPReputation` ended the request from inside a library** -
  printing their own JSON and calling `exit()` on an invalid address. That
  bypassed the router's envelope and would have killed a cron task mid-run. They
  throw now, and the router maps bad input to 400 instead of 500.

### Added
- `tests/test_monitor.php`, `test_scheduler.php`, `test_scanner_progress.php`,
  `test_write_paths.php` - 86 new assertions. The suite is 211.
- Command runners are injectable in `RealTimeMonitor`, `FirewallEngine` and
  `WAFInstaller`. The write paths all end in `nft`, `csf` or `apachectl`, none of
  which exist on a development machine, which is precisely why they were the
  last untested part of the product. The tests assert the decisions - which
  command would be issued, what happens when Apache rejects the config, whether
  state is persisted only on success - without pretending the tools are present.
- `scripts/check-calls.php` now checks `(new Foo())->bar()` as well as static
  calls. It immediately caught `(new FileIntegrity())->checkAll()`, a method
  that does not exist, in the new scheduler code.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
