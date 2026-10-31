# ServerScrub 4.25.0

[4.25.0] - 2026-10-31

### Changed

- **Customer scans start within a minute, and the limit is two per twelve
  hours.** Three separate things used to make a customer wait, and only one of
  them was the actual limit:

  - a **cooldown** between scans, which forced an even spacing nobody asked
    for — somebody who scanned, found something, cleaned it and wanted to
    confirm was made to wait the full gap;
  - a **per-tick cap**, which queued accounts behind each other and reported
    "2 accounts ahead of you";
  - the **15-minute scheduler**, which meant pressing the button and watching
    nothing happen for a quarter of an hour — long enough to press it again
    and then open a ticket.

  The cooldown and the cap are gone. The allowance is now a rolling window:
  **two scans per twelve hours per account** (`user_scan_per_window`,
  `user_scan_window_hours`). A new cron, `backend/cron/user-scans.php`, picks
  requests up **every minute** and does nothing else.

  Removing our cap did not uncap ClamAV. `Scanner::startScan()` already
  enforces `scan_max_concurrent` and refuses while a backup is running, so a
  minute interval cannot pile work onto a busy server — the worst a flood of
  requests can do is get refused quickly, with the reason recorded. Requests
  are still served oldest first, because the scanner can still refuse and the
  account that has waited longest should get the slot when one frees.

  The window is stored as a **list of start times**, not a counter, so the
  page can say when the next scan becomes available. The wait is measured from
  the **oldest** start in the window — measuring from the newest would hold an
  account out for a further twelve hours after its second scan. A timestamp in
  the future is discarded: it would never expire, and would lock the account
  out permanently the first time a clock moved.

  The page now says what is left — "You have 1 of 2 scans left for the next 12
  hours" — rather than only refusing when the allowance is spent.

- **The page says so when the pickup has stalled.** "It usually starts within a
  minute" is a promise, and if that cron is not running it is a lie the
  customer cannot see through. If the server has not checked for requests in
  over five minutes, the page says so and suggests raising it with their host.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
