# Sentinel Gate 3.21.4

[3.21.4] - 2026-08-28

### Fixed
- **One condition was reported two different ways.** The unconfigured-secret
  guard added in 3.21.1 was only in `activate()`. `status()` therefore still
  contacted the licence server and reported *"the response was signed with a
  different secret than this server is configured with"* - describing an unset
  secret as a mismatch, and sending the operator to compare two values when one
  of them does not exist. Confirmed on a live server reporting
  `secret_configured: false` alongside the mismatch message.

  The guard now lives in `evaluate()`, the path every licence operation goes
  through, so status, activation and refresh give the same explanation and none
  of them contacts the licence server when no reply could be verified.
- Both messages name `sentinel license secret <value>` and say the value comes
  from WHMCS, rather than naming a file to hand-edit.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
