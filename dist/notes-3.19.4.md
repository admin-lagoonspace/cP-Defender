# Sentinel Gate 3.19.4

[3.19.4] â€” 2026-08-27

The backend reached a working state in 3.19.3 â€” `auth/auto-login` returns a valid
token and `auth/status` is clean. These are the faults its own error logs then
exposed.

### Fixed
- **Every scheduled task died with "Undefined constant SG_DB".** Three CLI entry
  points (the cron scheduler, the update checker, the firewall boot unit) loaded
  `mode.php` instead of `config.php`. `mode.php` records the install mode and
  paths but does not define `SG_DB`, so `Database::get()` threw on every run â€”
  meaning scheduled scans, signature updates and IP reputation checks were all
  failing silently. They now load `config.php`, which includes `mode.php` itself.
- **A PHP warning on every request.** `config.php` defines `SG_ROOT` and
  `SG_VERSION` and then includes `mode.php`, which redefined both. The defines in
  `mode.php` are now guarded, so it can be included from either direction.
- **`https://<host>/sentinel-gate/` served a dashboard that could never work.**
  On cPanel that Apache copy has no PHP handler and would run as the web user
  regardless, yet it looks identical to the real UI and fails every API call â€”
  an old bookmark lands on a login form that cannot succeed. It now redirects to
  the WHM plugin. The hostname is resolved client-side, so nothing is baked in.
- The plugin page is served `Cache-Control: no-store`, so an updated dashboard
  is never masked by a cached copy of the previous one.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
