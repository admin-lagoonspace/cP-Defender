# ServerScrub 4.29.9

[4.29.9] - 2026-11-03

### Fixed

- **Our own updater was cancelling every nightly scan.** `install.sh` calls
  `Scanner::stopAllScans()`, and `update.sh` runs `install.sh` on every
  update -- with no `--register-only` guard around that call. So each update
  killed whatever was scanning. On a server taking several releases in a day,
  the nightly `/home` sweep never completed once, and the scan log filled
  with `cancelled` rows that said nothing about who had cancelled them.

  Stopping is still correct: an upgrade replaces the code underneath a
  detached worker, and a worker running half-old code against a freshly
  migrated database is worse than a stopped one. **Losing the scan is not.**

  The installer now records what was running before it stops it, and the
  update starts those scans again when it finishes -- one per path, skipping
  anything already running, because several workers on one tree is how six
  clamscans came to be running at once.

- **Every stopped scan said only "cancelled".** A nightly sweep killed by our
  updater was indistinguishable from one an operator stopped deliberately,
  which is why a log that was almost entirely "cancelled" could not be read
  at all, and why this went unnoticed for months. `scan_jobs` carries a
  `stop_reason` now, written by `stopScan()`, and both scan logs show it
  beside the status.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
