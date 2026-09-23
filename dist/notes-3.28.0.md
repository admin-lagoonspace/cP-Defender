# Sentinel Gate 3.28.0

[3.28.0] - 2026-09-23

Six reported faults and four requested features, from one production session.

### Fixed
- **The Log Analyzer showed a blank window.** The sidebar has carried a
  `data-page="logs"` entry since the navigation was written, but no matching
  page section ever existed and `showPage()` had no case for it, so clicking it
  hid whatever was open and rendered nothing. It had never been built. There is
  now a Log Analyzer page with per-day selection, level filtering, search and
  download, backed by two new routes. A test asserts that every sidebar entry
  has a page and every page is reachable from the sidebar, so a nav item
  pointing at nothing cannot ship again.
- **Scanner settings had no save control.** The schedule, run time, day and
  scan type could all be changed, and the only save button sat in a different
  card further up the page. The Scanner card now has its own, which re-reads
  the settings afterwards and states when the next scan will run.
- **IP reputation never checked the server's own addresses.** The scheduled job
  re-checks addresses that have *attacked* the server -- a different question --
  and the UI only pre-filled the first server IP into a manual lookup box. A
  server IP landing on a blocklist, which is what quietly breaks outbound mail,
  was checked by nothing at all. Every address the host sends from is now listed
  with its own verdict, checkable on demand and swept by the daily job, which
  raises a security event when one is listed.
- **File integrity monitoring detected changes and then reported none.**
  Detection was correct the whole time; the return values were not.
  `createBaseline()` never returned the `hashed` count the UI displayed, so
  every baseline said "0 files hashed", and `runCheck()` returned *arrays* of
  affected files under keys the UI added together as if they were numbers --
  and the scheduler logged a `changed` key that did not exist, so a scheduled
  check reported "0 change(s)" however much tampering it found. Both now return
  scalar counts alongside the detail. `tests/test_integrity.php` baselines a
  real tree, edits, adds and deletes files, and asserts each is reported.
- **CMS Guard could not justify its own verdict.** The minimum versions were
  hard-coded -- WordPress 6.4, a 2023 release -- so sites well behind current
  were reported as up to date, and the table showed a version and a bare "!"
  with no indication of what it was compared against. Thresholds are now
  settings with current defaults, each row carries the version it was judged by
  and a risk level, and the list is ordered worst-first.
- **The firewall page was slow for three avoidable reasons.** `iptables -L
  INPUT` ran without `-n`, so it resolved every address in the ruleset back to
  a hostname one DNS lookup at a time; `csf -l` was executed and its output
  discarded without ever being read; and `csf --version` was forked on every
  call. The first is the one that turns a page load into tens of seconds on a
  server with a few hundred blocks.

### Added
- **Bulk resolve for security events**, with a select-all checkbox and a bar
  that stays visible with its buttons disabled until rows are ticked. Resolving
  a single event previously returned success unconditionally, including for an
  id that matched no row; it now reports what actually changed. Resolving is
  also admin-gated, which it was not.
- **The quarantine location is visible and editable in Settings**, with a
  read/write test that actually writes and reads back rather than trusting
  `is_writable()`, and a move that relocates existing files. Quarantined files
  are evidence and are moved, never deleted. The settings page no longer names
  the old root-partition path as fact.
- **A rootkit scan schedule**, which the scheduler has honoured since it was
  written -- nothing in the UI could set it, so it ran on its weekly default.
  The intervals offered are only those `isDue()` implements: an option outside
  that set saves cleanly and then never fires.
- **Confirmation that cPanel users and resellers follow the server version.**
  The WHM UI copy is refreshed from the installed frontend on every
  registration, an update re-runs registration, and the cPanel user entry point
  redirects to the live install rather than holding its own copy. Asserted by
  test rather than assumed.

### Security
- Security event fields -- type, source IP and target -- were interpolated into
  the events table unescaped. They come from the requests of whoever attacked
  the server, so this rendered attacker-controlled markup into the page of the
  operator reviewing that attack. The same applied to CMS install paths, which
  a hosting customer chooses. Both are escaped.
- The events table declared seven columns and rendered six: the Description
  cell was missing entirely, so every cell after it was shifted one column left
  and the Status column rendered empty.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
