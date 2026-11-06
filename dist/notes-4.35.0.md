# ServerScrub 4.35.0

[4.35.0] - 2026-11-06

### Fixed

- **The PHP side opened SQLite with no `busy_timeout`.** The Python monitor
  set ten seconds; PHP set none. Six writers share that file -- the
  scheduler, the API under cpsrvd, the CLI, the customer pages, the user-scan
  picker and the monitor -- and a PHP writer meeting a held lock failed
  instantly with `SQLITE_BUSY` rather than waiting the milliseconds the other
  writer needed. Every one was a lost write that nothing retried. Now ten
  seconds, matching the daemon.
- **One-time migrations were not atomic.** The shape was: check for the
  marker, do the work, write the marker -- three statements, no transaction,
  in code that runs on *every* connection. Three processes opening the
  database inside the same window each found no marker and each independently
  did the whole thing, which for 4.33.0 meant three concurrent rewrites of
  148,551 rows. They now run under `BEGIN IMMEDIATE` with the marker written
  inside the same transaction, and the marker is re-checked after the lock is
  taken.
- **The WAL was unbounded.** A mass UPDATE grew it without limit until
  something checkpointed. `wal_autocheckpoint=1000`.

### Added

- **`serverscrub db-check`** — SQLite's `integrity_check`, exiting non-zero
  with the rebuild steps printed when it fails.
- **A nightly integrity check** at 04:30 raising a `database_corruption`
  security event. The first anyone knew of a damaged database was every
  command answering "database disk image is malformed"; a miscounted freelist
  and a doubly-referenced page do not appear at the moment they are noticed.

### Changed

- **The WAF triage's probe pattern was far too strict**, and it showed on real
  data: anchoring `.env` on a preceding slash missed `/config.env`,
  `/secrets.env` and `/ses.env`, and the optional-suffix form missed
  `/.env.supabase`. Rules whose every URI was an env-file probe scored 0% and
  came back as "check a few before arming" -- 33 of them on a live server,
  which leaves the operator reading the exact list the tool was meant to read
  for them. It now also recognises known shell filenames, `proc/self/environ`,
  traversal encodings and backup-file extensions.
- **Loopback and private addresses are excluded from the attacker list.**
  `127.0.0.1` appeared on a live server with 862 hits across 39 rules and 84
  sites -- not an attacker but the real client address being lost to a reverse
  proxy. The report now says what share of events are unattributable and warns
  that nothing in that group should be blocked.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
