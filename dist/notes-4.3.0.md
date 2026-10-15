# ServerScrub 4.3.0

[4.3.0] - 2026-10-15

### Added
- **Custom scan now picks accounts, with checkboxes.** It previously offered a
  free-text directory box; on a shared server an operator thinks in accounts,
  not paths. The list comes from `/var/cpanel/users` where cPanel is present
  and from the configured scan roots otherwise, and each entry says whether it
  has a `public_html`. Select all and Clear are there for the common cases. The
  request names accounts and the server resolves them against the real account
  list, so a path in the request body cannot send the scanner elsewhere.

### Fixed
- **The nightly scan never ran.** The scheduler marks a task as having run
  whenever its closure returns normally, and the scan task returns normally
  when it defers for a backup. On a server whose JetBackup window covers the
  02:00 scan time, every nightly scan was deferred *and* recorded as run, and a
  `daily` task is not due again for 24 hours -- so it was skipped every night,
  indefinitely. The deferral was right; counting it as a run was not. A task
  that returns `false` now stays due and is retried on the next tick. The same
  applies when a scan is already running at the scheduled time.
- **Quick, Full and Custom scanned exactly the same thing.** `scan_type` was
  written to the database and never read again, so all three walked the same
  tree and took the same time. Quick now scans every account's web root, where
  public code runs and where almost everything gets in; Full scans the
  configured roots entire; Custom scans the chosen accounts. Quick falls back
  to a full scan where no web root exists and says so, rather than silently
  scanning everything under the word "quick".
- **A running scan can now be stopped from any page load.** The Stop button
  lived inside a progress card that appeared only for a scan the current
  browser tab had started, so a scan launched by cron, by another admin, or
  before a page reload could not be stopped from the interface at all. The
  Scanner page now adopts whatever scan is in progress and follows it.
- A custom scan with nothing selected is refused, in the interface and in the
  API, instead of falling back to scanning the whole server.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
