# ServerScrub 4.27.0

[4.27.0] - 2026-11-02

### Added

- **Customer scans start in about five seconds, not "within a minute".** A
  cron is the wrong mechanism for something a person is sitting in front of: a
  minute is its floor, and whether it runs at all depends on a file in
  `/etc/cron.d` an administrator can tidy away — which is exactly what was
  found on a live server. `user-scans.php --watch` now runs as a systemd
  service (`serverscrub-scans`) and looks every five seconds. The cron entry
  remains for hosts without systemd and the scheduler remains as a floor under
  both; all three take the same lock, so running all three is harmless.

  The licence is checked on every pass rather than once at startup. Checking
  at startup meant an unlicensed box exited immediately and systemd restarted
  it every five seconds forever, and a licence renewed later was never
  noticed. The process recycles hourly rather than being trusted to run for
  weeks, handles `SIGTERM` so a stop cannot kill a pass half-way through, and
  survives a failed pass — an exiting watcher is the failure this whole
  mechanism exists to prevent.

- **The scan log says what started each scan.** Every row read "full" with no
  way to tell the nightly server sweep from the account owner's own request.
  Jobs now record their trigger — the account name, or the reserved markers
  `@schedule`, `@operator`, `@cli`. The `@` prefix cannot collide with a
  cPanel username, so a marker can never be mistaken for an account and an
  account cannot name itself `@schedule` to borrow its privileges.

  The raw name never reaches the page. A scan of `/home` appears in **every**
  customer's log, and the name on such a row is not theirs to see, so anything
  that is not this account is described by role: *Nightly scan*, *Your hosting
  provider*. Rows from before this was recorded show "—" rather than guessing
  "schedule", which would be wrong for every scan an operator started by hand.

### Fixed

- **A false alarm on the scan card.** It warned after five minutes that the
  scan "will not start on its own" — untrue on a server running the 15-minute
  floor, and shown for ten minutes out of every fifteen. There are three
  pickups with three different cadences, and one threshold cannot describe
  them. Under 90 seconds it promises seconds; up to twenty minutes it says
  requests are being picked up every fifteen and yours will start shortly;
  past twenty minutes — two whole scheduler cycles missed — it raises the
  alarm.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
