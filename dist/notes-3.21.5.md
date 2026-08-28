# Sentinel Gate 3.21.5

[3.21.5] - 2026-08-28

### Fixed
- **`sentinel license secret` accepted the example text from its own
  instructions.** The documented invocation was
  `sentinel license secret 'YOUR-WHMCS-ADDON-SECRET'`, and that literal string
  was pasted - which is exactly what a copy-pasteable example invites.

  The result was worse than setting nothing: the install reported
  `secret_configured: yes` while holding a value the licence server has never
  seen, so the diagnosis shifted from "no secret" to "secret mismatch" and sent
  the operator looking for a discrepancy between two values when only one of
  them was ever real.

  The documented placeholders are refused now, with a message saying where the
  real value lives and how to generate one. Values under 8 characters are
  refused too, since a licensing salt is not three letters.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
