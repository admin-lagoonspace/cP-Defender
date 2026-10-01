# Sentinel Gate 3.36.0

[3.36.0] - 2026-10-01

### Added
- **Brute-force detection, which the dashboard had been charting since it was
  written.** The attack timeline queries `security_events` for
  `type='brute_force'`; nothing had ever written one, so the line sat flat at
  zero on servers that were certainly being attacked. `rate_limit_ssh` was
  seeded as a setting and read by nothing at all.

  `BruteForce` reads authentication logs — SSH (`/var/log/secure`,
  `auth.log`), cPanel's `login_log`, Exim/Dovecot and pure-ftpd — counts
  failures per source address, and acts when one crosses a threshold inside a
  window. Reading is incremental: an auth log on a server under attack grows
  quickly, and re-reading it from the top every few minutes is how a detector
  becomes the load problem it was meant to report on.

- **A Brute Force page** in the sidebar: counts for 24 hours and 7 days, a
  14-day chart, the offending addresses with the usernames they tried, and
  which log sources were actually found — because "nothing is attacking you"
  and "we are reading nothing" otherwise look identical.

- **Settings that do something**: detection on/off, automatic blocking on/off,
  failures before blocking, the window they are counted in, how long a block
  lasts, retention, and an allow list. Minutes in the interface, seconds in the
  setting.

- **Counts on the dashboard** beside the timeline, with a link through to the
  new page.

- Automatic blocking goes through the existing firewall. Loopback, private
  ranges and allow-listed addresses are never blocked: locking the operator out
  of the server while defending it is not a trade worth making. One event per
  offender per window, not one per failed password, so a single attack cannot
  bury everything else on the dashboard.

### Fixed
- **A found-while-building defect worth recording.** PDO's SQLite driver binds
  every parameter as TEXT. A *column* comparison is unaffected, because SQLite
  applies the column's INTEGER affinity to the text operand — but `COUNT(*)` is
  an expression with no affinity, so `HAVING COUNT(*) >= ?` is false for every
  count. The detector collected failures correctly and then silently never
  crossed its own threshold. The comparison now casts, and a test proves both
  halves rather than trusting the explanation.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
