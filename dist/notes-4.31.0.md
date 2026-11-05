# ServerScrub 4.31.0

[4.31.0] - 2026-11-05

### Added

- **Two third-party signature feeds, in report-only mode.** Linux Malware
  Detect (rfxn) and PHP-malware-finder, fetched into the ClamAV database
  directory on the existing weekly signature task. ClamAV loads `.ndb`,
  `.hdb` and YARA from there natively, so nothing is patched and nothing is
  forked -- a fork would mean owning a C codebase and losing upstream
  security fixes for a feature ClamAV already has.

  Both chosen for this workload: LMD is written by a hosting operator for
  shared-hosting PHP malware, and PHP-malware-finder is YARA aimed at
  webshells. ClamAV is weak on precisely that ground.

  **A feed cannot touch a customer's file until it is promoted.** These rules
  were written by other people for other environments; one that is merely
  noisy on a workstation takes a working website down here, across every
  account at once, and the first anyone hears of it is the customer. A
  detection from an unpromoted feed is recorded, displayed, and nothing else
  -- even with auto-quarantine on and a critical severity.

  The download is capped at 32 MB, fetched over verified TLS, written aside
  and renamed in, and rejected if it turns out to be an HTML error page: a
  captive portal's response written into the ClamAV database directory stops
  clamscan starting at all, which is worse than being out of date.

- **Disabling a file is now an answer, not just a step.** It was only ever a
  moment before quarantine or deletion. It is the right action for anything
  short of certainty: the file stops executing immediately, nothing is
  destroyed, and a false positive costs one `chmod` to undo rather than a
  restore from backup. `threats.prev_mode` records what was taken away, so
  `reEnable()` puts the file back exactly as it was found rather than
  guessing 0644.

  It is honest about being weaker than quarantine: the account still owns the
  file and can put the bit back, so it contains an accident better than it
  contains an attacker who still has a shell. For a confirmed compromise,
  quarantine moves the file somewhere the account cannot reach.

  It also refuses to lie. If the permissions cannot actually be removed, the
  action fails and the threat stays open -- reporting a file as neutralised
  when nothing changed would leave a live webshell marked handled, and nobody
  looks at those again. Windows proved that path on the first run of the
  test, since `chmod` there only toggles a read-only bit.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
