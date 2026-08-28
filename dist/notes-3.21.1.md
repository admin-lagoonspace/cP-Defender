# Sentinel Gate 3.21.1

[3.21.1] - 2026-08-28

### Fixed
- **A correct licence key was rejected as invalid on a server whose licensing
  secret was never set.** Activation reported "License response failed
  verification", which reads as a problem with the key. It is not: the response
  hash is `md5(secret . check_token)`, exactly as the WHMCS licensing addon
  computes it, so while `SG_LICENSE_SECRET` is still its shipped placeholder no
  reply from the licence server can ever verify and every key is refused.

  `secretConfigured()` had existed since licensing was added and **nothing ever
  called it**, so an unconfigured server was indistinguishable from a bad key.
  Activation now checks before contacting the licence server and reports
  `Unconfigured` with the file and setting to fix, stating plainly that the key
  is not the problem.
- A genuine hash mismatch on a *configured* server now says the response was
  signed with a different secret than this server holds - a configuration
  mismatch between the plugin and the WHMCS addon - rather than implying the key
  is bad.
- `status()` carries `secret_configured` on every result, and the licence panel
  warns before a key is entered rather than after it has been rejected.

### Notes
- The verification maths is unchanged and now pinned by a test. If it ever
  drifts, activation fails on correctly configured servers, which is a worse
  failure than the one fixed here.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
