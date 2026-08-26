# Sentinel Gate 3.19.0

[3.19.0] — 2026-08-26

Minor, not patch: this changes how the plugin is served on cPanel.

### Fixed
- **The dashboard loaded but nothing in it worked on cPanel.** Every API call
  returned `501 Not supported`, so each panel independently rendered "Server
  error" or stayed blank. The plugin CGI redirected to an Apache alias, and
  Apache only executes PHP in an aliased directory when a loaded module claims
  the handler — on EA4 that may be mod_php, mod_lsapi, PHP-FPM or suPHP. The
  installer guessed the handler from the CLI PHP binary, which is not
  necessarily an EasyApache build.
- **The API ran as the web user.** Even where the handler resolved, Apache would
  have executed it as `nobody`, which cannot run nft/iptables, quarantine a file
  or read `/proc` — the things this product exists to do.
- **A failed dashboard load left "Protected" on screen.** The markup ships that
  state pre-rendered and the failure path returned silently, so a server whose
  API answered 501 to every request displayed a green tick and a clean bill of
  health. It now shows "Status unknown / API unreachable" and blanks the tiles.
- Errors were both hidden and unlogged (`error_reporting(0)`), so a failure could
  only ever appear as "Server error" with no trace on the server. Errors are now
  logged to `logs/php-error.log`, never displayed, and a shutdown handler
  guarantees a JSON envelope even on a fatal.
- Route parsing searched for a literal `api` path segment and mis-parsed under
  any path without one.

### Changed
- On cPanel the UI and API are now served by **cpsrvd** from the WHM CGI
  directory, as CSF and other established WHM plugins do. cpsrvd runs them as
  root, is always present, and puts the UI and API on one origin. The Apache
  alias remains for standalone Linux, where it is the right mechanism.
- Routing travels in `?r=module/action`, which needs neither mod_rewrite nor
  PATH_INFO and therefore behaves identically under cpsrvd, Apache and the
  standalone router.
- The API client discovers its endpoint by probing candidates and caching the
  first that returns JSON, instead of assuming one relative path.

### Added
- The installer now **invokes the API and requires JSON back** before reporting
  success. The previous installer declared success without ever calling it.
- `make-release.sh` runs `php -l` over `backend/` and refuses to build on a parse
  error.

### Documentation
- The wiki claimed PHP 7.4+. The code uses `match()` and `str_contains()`, both
  PHP 8.0+, so it could never have run on 7.4. Corrected to 8.0+.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
