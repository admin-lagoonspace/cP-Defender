# Sentinel Gate 3.19.10

[3.19.10] - 2026-08-27

Module audit, item 1 of 5: CMS Guard.

### Fixed
- **CMS Guard reported "0 websites" on a server hosting several WordPress
  sites.** Two independent bugs, either of which alone produced that number.

  Discovery only ever looked at `glob("/home/*/public_html")` - the primary
  document root of each account. On cPanel every addon domain and subdomain has
  its own document root, and WordPress is routinely installed in a subdirectory
  (`/public_html/blog`). Against a fake hosting tree the old logic finds 1 of 3
  installs; it now reads document roots from `/var/cpanel/userdata`, which is
  cPanel's own authoritative record of every domain, and searches up to three
  levels below each one. `wp-content`, `vendor`, `node_modules` and similar are
  skipped so a plugin's sample config cannot register as a phantom install.

  The panel also read `d.total` while the API returns `total_installs`, so the
  counter displayed 0 regardless of what was found. The demo fixture used
  `total`; the real shape had drifted and only the demo was ever exercised.

- **"No scan has run yet" was indistinguishable from "no CMS found".** Both
  showed 0, and the first is what every fresh install shows - which reads as a
  broken product rather than as a next step. `getStats()` now reports
  `last_scan_at` and `ever_scanned`, and the panel says which case it is.

### Added
- `tests/test_cmsguard.php` - builds a fake hosting tree (document-root install,
  subdirectory install, addon domain, CMS-free account, `/var/www/html`, and a
  document root known only to cPanel userdata) and asserts each is classified
  correctly. Includes a demo-versus-real shape check, which caught the `total`
  drift the moment it was written.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
