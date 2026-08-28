# Sentinel Gate 3.22.0

[3.22.0] - 2026-08-28

### Added
- **`sentinel license probe`** - sends exactly what the real licence check sends
  and shows exactly what comes back, including the raw response.

  Several genuinely different failures all surface as "Invalid", and no message
  can distinguish them from the client side alone: the addon not being installed
  at the configured URL, the key being unknown to WHMCS, and the shared secret
  not matching. probe() reports which one it is, and prints the licence status
  the server actually returned. The secret is never included in the output, so
  the result can be pasted into a support conversation as-is.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
