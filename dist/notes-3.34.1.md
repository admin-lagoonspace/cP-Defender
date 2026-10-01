# Sentinel Gate 3.34.1

[3.34.1] - 2026-10-01

### Fixed
- **The newest WAF event was never stored.** The parser only flushed an entry
  when it met the *next* one, so the most recent was always left pending — and
  because the read offset still advanced to the end of the file, it was never
  seen again either. On a quiet server that is every event. Entries are now
  committed when their `-Z--` terminator is read, and the offset only advances
  past entries that are complete, so one still being written is read in full
  next time rather than half-parsed and skipped.

- **The IP column, third attempt — this time tested against the real thing.**
  Both previous fixes were positional and each missed a real layout:

  - The original looked for an address immediately after the timestamp's
    closing bracket, which is where the unique id sits. It matched nothing.
  - 3.34.0 assumed the unique id was always present. Servers without
    `mod_unique_id` have no such token, and it missed all of them.

  Addresses are now found by tokenising the line and taking those that validate
  as IPs, which is true of both layouts and of IPv6. More importantly,
  `tests/test_waf_parse.php` now writes audit logs in each layout, runs the
  real ingester over them, and checks what reaches the database — the only kind
  of assertion that would have caught either bug.

### Added
- `sentinel waf-parse-test [n]` and `waf/parse-test`: show the raw section-A
  lines from this server's log beside what the parser extracted. After getting
  this wrong twice from assumptions about the format, the fix is to be able to
  look.
- `sentinel waf-reingest [--clear]` and `waf/reingest`: read the audit log
  again from the beginning. Events already stored keep whatever was parsed when
  they were ingested, so a parser fix does nothing for them on its own — the
  offset has long since moved past. `--clear` removes the existing rows first,
  because re-reading without it stores a second copy of everything older than
  the 60-second dedup window.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
