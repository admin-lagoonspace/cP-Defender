# ServerScrub 4.26.1

[4.26.1] - 2026-11-02

### Fixed

- **"Cancel does nothing."** It did work — the page deletes the request file,
  which it owns and can remove instantly — but the card went on saying
  *Queued* afterwards, and would have until the next hourly report. Queued was
  decided as `$requested || !empty($sr['pending'])`, and `$sr` comes out of
  `report.json`, which is rebuilt **hourly**. The card was reading an hour-old
  "pending" and putting the screen straight back the way it was. The fresh
  request file *was* read — two lines further down, and then not used for this.
  Queued is now decided from that file and nothing else.

- **A card that said a scan was fine and then that it was stuck**, in
  consecutive sentences: "It usually starts within a minute" followed by "the
  server has not checked for scan requests since 8h ago". The reassurance is
  now suppressed when the pickup is stale, and the warning leads: *Your scan
  has not started, and will not start on its own* — with what to do about it,
  and that it is the provider's side rather than the customer's.

- **A server whose minute cron is not running picked requests up never.**
  4.26.0 removed the scheduler's pickup to stop a double start. That was the
  wrong fix: it left the minute cron as the only route, so a cron file that
  never got written, a PHP path that moved, or a tidied `/etc/cron.d` meant
  nothing ever looked at a request. Reported from a live server whose pickup
  had not run for eight hours — the button worked, the card said *Queued*, and
  nothing was ever going to happen.

  The scheduler picks requests up again, every 15 minutes, as a floor under
  the minute cron. The double start is fixed properly instead: the lock moved
  into `UserScanRequest::process()`, so every caller shares one lock rather
  than each script holding its own, which excluded only other copies of
  itself. The fallback is unconditional and sits outside the task table — it
  is a customer waiting, not an operator's nightly job, and must not be
  pushed out by setting some schedule to weekly.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
