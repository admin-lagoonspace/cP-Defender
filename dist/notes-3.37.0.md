# Sentinel Gate 3.37.0

[3.37.0] - 2026-10-03

### Added
- **What happens to an infected file now depends on how bad it is.**

  | Severity | Action |
  |---|---|
  | high / critical | disabled, then deleted outright |
  | medium | disabled, quarantined, deleted after 5 days |
  | low | disabled, quarantined, deleted after 7 days |

  All three detection paths previously ran the same three lines — "if
  auto-quarantine is on, quarantine it" — so a webshell and a suspicious
  comment were treated identically. They now share one decision in
  `applyThreatPolicy()`.

- **Files are made inert before anything else happens.** Between detection and
  the move, a file is still executable by the web server; every permission bit
  is removed first. If the move or delete then fails, the original mode is put
  back — leaving a customer with an unreadable file *and* the malware still
  present would be the worst of both outcomes.

- **Quarantine is swept on a schedule.** Each file goes when its own deadline
  passes, and anything still present beyond the retention period goes
  regardless — which is what clears files quarantined before deadlines existed
  at all.

### Changed
- **Quarantine retention is 7 days, down from 30.** The seed is
  `INSERT OR IGNORE` and cannot change an existing row, so there is an explicit
  one-time migration. It only ever *shortens* the setting, so an operator who
  deliberately chose less than 7 keeps it, and it is marked so a later
  deliberate change is not overruled by the next upgrade.

### Security
- **A high-severity detection is deleted with no copy kept, so a false positive
  destroys a customer's file permanently.** That is the behaviour that was
  asked for and it is what ships, but it is the sharpest edge in this product,
  so: the path, size and SHA-256 are recorded in the threat row, the log and a
  security event *before* the file is removed, and a note is left in its place
  saying what was taken and that recovery means going to backups. None of that
  restores the file — it means an operator can see exactly what happened.
  `policy_high_action` can be set to `quarantine` to give high severity the
  same grace period as the rest, without turning protection off.
- Per-severity periods are capped by the global retention, so a deadline can
  never promise a grace period the sweep will not honour.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
