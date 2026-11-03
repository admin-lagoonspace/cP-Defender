# ServerScrub 4.29.2

[4.29.2] - 2026-11-03

### Fixed

- **The install self-test failed on a healthy install, and told the operator
  to re-run install.sh.** `PASS: 47  FAIL: 2`, a verification failure, and
  advice that would have written exactly the same file again.

  Both failures were `test.sh` demanding `RewriteRule` and `SetHandler` in
  the generated Apache config regardless of install mode. Both live in the
  `<Directory>` block for the aliased API, which cPanel installs stopped
  emitting in 4.28.9 -- correctly, because there the dashboard runs under
  cpsrvd and nothing routes to an aliased PHP directory at all. The check was
  written when Apache served the app and was never revisited.

  A check that cannot be satisfied is worse than no check: it teaches the
  operator to ignore the suite. The Apache tests branch on the install mode
  now. cPanel is checked for the exact-path `AliasMatch` it actually gets,
  **and fails if a subtree alias reappears** -- that is what shadowed
  `/serverscrub/*` on every hosted site. Standalone still requires the
  rewrite rules it genuinely needs.

- The API `.htaccess` check had the same problem one severity down, warning
  about a file that is deliberately absent on cPanel.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
