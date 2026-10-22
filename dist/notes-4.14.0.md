# ServerScrub 4.14.0

[4.14.0] - 2026-10-22

### Added

- **"Not malware" is now a verdict, not an exclusion.** Marking a finding as
  not malware records the file's **sha256** and stops reporting it â€” while the
  file is still scanned on every pass. Change one byte and it is flagged again
  at full severity.

  This matters because the alternative on offer was a path exclusion. Silencing
  the five findings against `/opt/ai-bolit/` â€” Imunify360's own scanner, which
  genuinely contains `eval(base64_decode(...))` because a malware scanner
  carries the patterns it hunts for â€” would also have hidden anything an
  attacker dropped in that directory afterwards. On a shared host that is a
  permanent blind spot bought to tidy a table.

  | | Exclusion | Not-malware verdict |
  |---|---|---|
  | File still scanned | no | **yes, every pass** |
  | If the contents change | still hidden | **reported again** |
  | Keyed on | path / glob | **path + sha256** |

  Exclusions remain for operators who really do want a path skipped. They are
  just no longer what the button does.

- **A "Marked not malware" panel** on the Scanner page listing every verdict,
  who recorded it and why. Each row shows its state: *Active*, *Lapsed* (the
  file changed, so it is being reported again) or *Gone*. A lapsed verdict is
  indistinguishable from a live one in a plain list of paths, and an operator
  who cannot tell them apart cannot audit this at all. Any verdict can be
  withdrawn in one click.

### Fixed

- **Both "Not malware" buttons did nothing when clicked.** Each opened with
  `prompt()` or `confirm()`. This plugin renders inside cPanel's iframe, and an
  iframe without `allow-modals` makes both return `null` **instantly and
  silently** â€” which the handler read as "cancelled" and returned on. No error,
  no console output, nothing. The function existed, the route existed, the
  button was enabled, and it was dead. Replaced with an in-app dialog, which
  also gives somewhere to record *why* the file is safe.

- **Realtime detections recorded no hash and no size**, which is why every
  realtime row in the UI read **0 B** â€” and why there was nothing for a verdict
  to be keyed on. The daemon now streams a sha256 (not read-whole: some of
  these files are gigabytes) and stores the size.

- Suppressed realtime findings no longer write a `THREAT` line to the log or an
  entry to the security timeline. A cleared file that still announced itself is
  exactly what made the feature look broken.

### Changed

- All six detection writers â€” five in `Scanner.php`, one in the Python daemon â€”
  now go through a single gate (`ThreatStore::record()`), so "respect the
  operator's verdict" is enforced in one place rather than copy-pasted into six.
  `scripts/check-threat-gate.py` fails the build if a seventh appears. This
  codebase has been bitten twice by a rule duplicated across call sites: three
  divergent file lists in `update.sh` shipped an empty cPanel menu for two
  releases, and a hardcoded id list left a bulk button dead on arrival.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
