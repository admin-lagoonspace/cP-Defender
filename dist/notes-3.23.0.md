# Sentinel Gate 3.23.0

[3.23.0] - 2026-08-28

Licensing now works against the WHMCS Licensing Addon v3.1.

### Fixed
- **Activation failed on a correctly licensed server.** `diagnose-hash` against
  the live server showed the addon signs with `md5(check_token)` - an **empty**
  secret - and its configuration stores no secret at all. Every release from
  3.21.1 treated that normal state as a misconfiguration, refused to activate,
  and directed the operator to find a value in WHMCS that does not exist.

  The client verifies against the empty secret now. An explicit
  `SG_LICENSE_SECRET` is still honoured for a licence server that does use one.

### Changed
- **The verification secret and the local-key salt are now separate values**,
  which they always should have been. They serve different purposes: one must
  match the licence server, the other only has to be stable and secret on this
  machine.

  Using one value for both was wrong in both directions, and actively harmful
  once that value turned out to be empty - anyone who knew the scheme could mint
  an "Active" local key for any server. The local salt is now 32 random bytes
  generated per installation, stored locally and never transmitted.
- Cached local keys from earlier versions no longer validate and are re-checked
  against the licence server once. No action is needed.
- The "licensing secret is not set" warning is gone from the licence panel: on
  this addon that is the correct state, so the warning would have shown on every
  properly configured server.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
