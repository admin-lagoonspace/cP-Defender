# ServerScrub 4.37.7

[4.37.7] - 2026-11-20

### Fixed

- **The containment fix in 4.37.4 never ran. The updater left the monitor
  stopped.** This is the root cause of "malware detected in realtime is left
  Active on the server" surviving three releases that claimed to fix it.

  `update.sh` stops the daemon near the top of the script so the files
  underneath it can be replaced, and started it again about 400 lines later.
  **"Fixing permissions" sits between the two** -- the section that could walk
  a path read out of the database without bound, and that hung on a live
  server. The walk hung, the operator killed the update, and the monitor was
  left stopped while the panel happily reported the new version. Real-time
  protection was simply off, and the only evidence was that a log line the new
  code writes on every containment decision never appeared once.

  The restart now happens as soon as the files are in place and the migrations
  have run -- all the daemon was ever waiting for -- which puts it *before*
  everything that can hang. An **EXIT trap** guarantees it regardless: an
  update that dies, hangs and is killed, or rolls back still leaves the
  monitor running. A security daemon that is down is the one outcome an
  updater must never produce. It will not, however, start a monitor that was
  deliberately stopped before the update.

  It also now uses `systemctl restart`, not `start`. **`start` is a no-op on a
  unit that is already active**, so wherever the stop had not taken effect the
  pre-update process kept running the old code while the update reported
  success. And the update checks `is-active` afterwards rather than trusting
  the restart command's exit status, because a unit that starts and dies
  immediately still exits 0.

  The daemon logs its **version** on startup. "Which code is this process
  running?" had no answer, which is why diagnosing this took an argument from
  a missing log line.

  A comment in `update.sh` claiming install.sh restarts the monitor on
  `--register-only` has been removed: it does not, that block is inside
  `if ! $REGISTER_ONLY`, and the false comment is what let the gap survive.

- **Findings already sitting at Active are now contained retroactively.**
  Changing the code path only changed what happens to the *next* detection.
  Every finding the old gate declined was still on disk, still executable and
  still listed as Active -- and those are the ones an operator is looking at.

  New `serverscrub contain-active` walks them and applies the policy, critical
  first, with `--dry-run` and a bound. It does not reimplement anything: every
  row goes through `Scanner::applyThreatPolicy`, so the mass-detection bound,
  report-only feeds, the auto-quarantine switch and the severity mapping apply
  exactly as they would to a fresh finding. A row whose file has gone is
  reported as missing rather than flipped to "deleted", which would credit the
  run with removing something it never touched.

  It runs automatically on upgrade from `install.sh --register-only` -- the
  new copy, not one release late -- so nobody has to know the command exists.

- **The Detected Threats table now pages: 50 / 100 / 200 / 500 / All.** The
  previous release paginated the wrong table. The Malware Scanner page holds
  two -- the scan history log, and Detected Threats, the list of findings an
  operator actually works in -- and only the first was fixed. The second ran
  `ORDER BY detected_at DESC LIMIT 200` with no offset and no total, so a
  server with months of findings showed its newest 200 with no way to reach
  the rest and no sign a rest existed. The only control on the card was a
  status filter whose first option is "All", which looks like a page size and
  is not one.

  Same controls, order and wording as the scan log and the WAF events table.
  The total is counted under the same filter as the rows, "All" is bounded at
  5,000 with a flag when it truncates, and changing either the page size or
  the status filter returns to the first page.

### Verified

Exercised in the repo's docker cPanel environment rather than asserted
against source text: a live monitor quarantining a MEDIUM detection and
deleting a CRITICAL one; `contain-active` containing two stuck findings and
leaving a vanished file alone; the sweep running inside a real
`install.sh --register-only`; and the paging driven in a browser against the
real API across 137 findings -- first page, last page, past-the-end, All, and
size changes resetting to page one. The `systemctl` behaviour is covered by
tests and ordering rather than a live run: the container has no systemd.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
