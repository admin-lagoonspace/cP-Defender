# ServerScrub 4.28.0

[4.28.0] - 2026-11-02

### Added

- **A scan log on the root side, which did not exist.** The WHM Scanner page
  showed the scan running at that instant and the threats it had found, and
  nothing whatever about any scan before it. "Did last night's sweep finish?"
  had no answer short of opening the database. There is now a Scanner logs
  table on that page, with a **Started by** column naming the account that
  asked, or Scheduled scan / WHM / Command line. Root is the one place the
  actual account name is both safe and useful to show.

### Fixed

- **A scan you had just started was missing from your own scan log.** The
  customer-facing table was rendered entirely out of `report.json`, which the
  privileged side rebuilds hourly. You could press "Scan my account", watch the
  Home card count files in real time, open Scanner logs — and find no row for
  the scan you were at that moment running, for up to an hour. The live job is
  now merged in from `scan-status.json`, matched by job id so it is updated in
  place rather than appearing twice once the rebuild catches up.

- **And the log now moves while the scan does.** It is a polled region like the
  Home card, so files and status climb without the reader pressing anything.
  Only the region actually on screen is fetched.

- **Scans started by anyone else reach your log within seconds too.** The
  resident watcher rebuilds the per-user reports when the set of running scans
  changes — at the edges of a scan, not every pass. A server-wide sweep of
  `/home` covers every account and belongs in every account's log; previously
  it took up to an hour to appear there.

- **A finished scan was grey.** The status colour was checked against
  `completed`, a status this product has never written; the status it writes is
  `done`. Every row looked equally unremarkable, including the good ones.

- **A running scan showed no elapsed time** in either log, because duration was
  measured against `finished_at`, which a running scan does not have. The one
  row anybody is watching was the one row with a dash in the Took column.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
