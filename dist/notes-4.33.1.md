# ServerScrub 4.33.1

[4.33.1] - 2026-11-06

### Fixed

- **The WAF had two mode controls that wrote different files, and one of them
  did nothing.** The page header's "Apply Mode" called `WAF::setMode()`, which
  rewrote the *vendor* config (`modsec_vendor_configs/modsecurity.conf`). The
  WAF Engine card's selector called `WAFInstaller::setMode()`, which writes
  `serverscrub-waf.conf` -- the file we own, included after the vendor's, and
  therefore the one whose `SecRuleEngine` decides. Editing the vendor file
  changed nothing a request would ever notice, so pressing Apply Mode left the
  card below it still reading "detectiononly". Both controls now go through
  one implementation, which writes the file that counts, runs `apachectl -t`
  before reloading, and reports a failure as a failure.
- **`WAF::setMode()` could not fail.** The edit sat behind `is_readable`, so
  on a server where that path does not exist -- most of them, since cPanel
  keeps ModSecurity's config elsewhere -- the whole block was skipped and the
  method returned `success: true` regardless. No write check, no syntax check,
  no check that the reload worked.
- **The Mode tile was the hard-coded string `'On'`.** It read nothing, so it
  said "On" beside an engine running in detection only, and would have said
  "On" with ModSecurity not installed at all.
- **The status read the mode from the wrong file.** Our own config is read
  first now, because it overrides the vendor's. An unreadable config reports
  `unknown`, never `On`.
- **Applying a mode refreshed only the engine card**, leaving the header
  selector and the Mode tile showing their previous values -- which is how a
  change that did not take looked exactly like one that did. Both are re-read
  from the server now, and the header selector is set from the engine's
  reported mode.
- **The header's options read as a heading, not a choice** ("Enforcement
  Mode"). Worded as the card's are, since they are now the same control.

### Added

- **`serverscrub waf mode [on|detectiononly|off]`.** Reads back from the
  config Apache actually loads after writing, exits non-zero if the config
  still disagrees, and prints the mode on its own when given no argument.
  Added because reporting the *requested* value is precisely the mistake the
  panel made, and a control that cannot be trusted needs a path that shows its
  working.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
