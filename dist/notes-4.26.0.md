# ServerScrub 4.26.0

[4.26.0] - 2026-11-02

### Added

- **Customers can watch their scan, and stop it.** Reported with a screenshot:
  press "Scan my account", and the card says *Queued* — and goes on saying it
  while the scan runs and finishes. There was no progress, no finish, and no
  way to cancel.

  It could not have shown anything else. The page is rendered from
  `report.json`, which is rebuilt hourly, so the card was displaying an answer
  from before the click. Three separate things were missing:

  - **Progress had nowhere to come from.** The page runs as the customer and
    the database is `0700 root` — deliberately, because a page every hosting
    customer can load must not reach the whole server's security data. So the
    privileged side now publishes the one job they are entitled to see into
    their own home, as `~/.serverscrub/scan-status.json`, written every batch
    by the scan worker and on every way a scan can end (done, error, cancelled,
    skipped, and interrupted when a worker dies). A file in their own home is
    the only channel that does not widen anything.

  - **Cancelling is a root action.** The button cannot perform it. A request
    not yet picked up is cancelled by deleting it, which the page does itself —
    instant, and the common case. A scan already running belongs to a root
    process, so the page leaves the ask and the privileged side checks it
    against the job row before acting. The test is `requested_by`, not the scan
    path: a customer may stop the scan they started and nothing else — not the
    scheduled sweep, not an operator's scan, not another customer's, all of
    which read their files too.

  - **The page never re-read itself.** The card now states whether anything is
    moving, and a small poller re-fetches just that card every five seconds
    while it is. It stops when the card says to, pauses in a background tab,
    and holds one timer. Every control remains a real form submit, so the page
    is still correct with scripting off — it just stops moving on its own.

  The card now distinguishes queued, scanning (with files checked, threats so
  far and elapsed time), stopping, clean, threats found, cancelled, not
  started, and stopped-responding. All nine states were rendered and read back.

### Changed

- **The scheduler no longer picks up scan requests.** `user-scans.php` has
  owned that since 4.25.0, every minute. While both did it there were two
  processes holding two different locks reading the same request file, so one
  request could be started twice — the second refused by `scan_max_concurrent`
  and logged as a failure nobody could explain.

- `UserReport`'s safe-write path is now `writeInHome()`, shared by the report
  and the live status. It is the only genuinely dangerous code in that class —
  root writing into a directory a hostile user can rearrange between one call
  and the next — and a second copy of those checks would have been the one to
  fall behind.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
