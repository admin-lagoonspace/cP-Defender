# ServerScrub 4.22.1

[4.22.1] - 2026-10-30

### Security

- **A reseller's WHM API token granted root inside this product.** The WHM
  plugin is registered `acls=any`, so every reseller on the server can open
  it. Signing in with a password correctly gave a reseller the `user` role and
  settings were refused. Signing in with a **WHM API token** gave them `root`
  — the top of the hierarchy — because `validateWhmToken()` only asks WHM
  whether the token works at all, and the endpoint it calls,
  `/json-api/version`, answers for every WHM account including resellers.

  So two routes into one panel disagreed about who you are, and the token
  route was the generous one. A reseller could change server-wide settings:
  scan paths, quarantine behaviour, `user_scan_max_per_run`, anything.

  Both cPanel branches now decide the role from the username, by the same
  rule. `validateWhmToken()` says plainly at the function that it establishes
  identity and nothing else, because the next caller will otherwise read its
  `true` as "this is an administrator" exactly as the last one did.

### Added

- **`Auth::deny()` can be tested.** It exits, which is right in production and
  meant the refusal path was untestable — a test asserting "a reseller is
  denied" cannot assert anything after the process has gone. Under `SG_TEST`
  it now throws instead. That constant is defined only by `tests/bootstrap.php`
  and `tests/` is excluded from the release zip, so the seam cannot exist on a
  server.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
