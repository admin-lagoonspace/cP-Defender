# Sentinel Gate 3.22.2

[3.22.2] - 2026-08-28

### Added
- **`sentinel license diagnose-hash`** - identifies how the licence server
  actually signs its replies, by testing candidate formulas against a real
  response.

### Notes
- The WHMCS Licensing Addon v3.1 stores **no secret** in its configuration.
  Confirmed against a live install: `tbladdonmodules` holds only `version`,
  `access`, `clientverifytool`, `maxreissues` and `logprune`. The premise behind
  every licensing message since 3.21.1 - that a shared secret exists and must be
  copied across - was therefore wrong, and no amount of searching the WHMCS UI
  would ever have produced one.

  The client's verification formula, `md5(secret + check_token)`, comes from
  WHMCS's published sample client. Since this addon has no secret to configure,
  either that sample does not apply to v3.1 or the value is derived elsewhere.
  Guessing further is not worth another release, so this command determines it
  from the wire instead.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
