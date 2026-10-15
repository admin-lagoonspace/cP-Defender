# ServerScrub 4.4.0

[4.4.0] - 2026-10-15

### Added
- **`serverscrub schedule`** lists every scheduled task with its schedule, when
  it last ran, and whether it is overdue. There was previously no way to answer
  "is my nightly scan actually running?": the scheduler writes to stdout and
  cron redirects that into `logs/cron.log`, one file holding every task's
  output interleaved. The report is built from the scheduler's own task table,
  so it cannot drift from what is really scheduled.

### Fixed
- **The installer could install a version older than the one just published.**
  `get.sh` reads `latest.json` through raw.githubusercontent.com, which serves
  via a CDN with a short TTL, so for a few minutes after a release it kept
  returning the previous manifest and the installer believed it. Reported
  directly: 4.3.0 was published and the server ended up on 4.2.0. Manifest
  reads are now cache-busted. The archive deliberately is not -- its sha256 in
  the manifest is what guards it, and busting that would defeat mirroring.
- `dist/latest.json` is tracked but was never staged by `publish.sh`, so it sat
  at 4.1.5 while three releases shipped. A tracked manifest that lies is a trap
  for anyone pointing a mirror at `dist/`.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
