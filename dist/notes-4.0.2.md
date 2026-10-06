# ServerScrub 4.0.2

[4.0.2] - 2026-10-06

### Fixed
- **The firewall page was never the problem.** Three previous attempts looked
  only at firewall code. The cost was on the licence gate, which runs on
  **every** API request: with a licence key whose cached local key has gone
  stale, `License::status()` called the licence server with a 12-second
  timeout — and a failure was recorded nowhere, so the next request tried
  again, and the next. The firewall page fires three requests and cpsrvd
  serialises them, which is why it was the worst page rather than the only slow
  one.

  A failed check now backs off for 15 minutes, and a check that happens while
  someone is waiting for a page gets a 3-second timeout instead of 12. The
  scheduler and the Refresh button still get a full, unthrottled check, so a
  licence that comes back is picked up promptly.

  Measured: first request 535ms, every request after it **0–1ms**. Each one
  previously paid the full timeout.

### Changed
- **The firewall page loads in stages, behind a blocking overlay.** The three
  calls were awaited together, so the slowest decided when *any* panel
  appeared and the page sat blank until the last landed. Now the counts render
  first, then the rules table, then the blocked list — each drawn as its data
  arrives. The overlay is up for the whole sequence, so the page cannot be
  clicked into a queue of overlapping work while it fills in.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
