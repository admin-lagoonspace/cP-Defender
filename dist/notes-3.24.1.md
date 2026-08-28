# Sentinel Gate 3.24.1

[3.24.1] - 2026-08-28

### Added
- **A Save button in the Real-Time Monitor section.** The limits were committed
  only by the page-level "Save Changes" at the top of Settings, so editing a
  value here meant leaving the section to commit it, with no confirmation that
  these particular values had landed.

  It reports the outcome in place, and reads the stored values back from the
  server afterwards rather than echoing what was typed - a value outside the
  accepted range is clamped, so showing the typed number would misreport what is
  actually in force.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
