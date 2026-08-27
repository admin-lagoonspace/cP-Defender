# Sentinel Gate 3.19.1

[3.19.1] — 2026-08-27

### Fixed
- **Every authenticated request died under cpsrvd.** `Auth::requireAuth()` called
  `getallheaders()`, which exists under mod_php and PHP-FPM but not under the CGI
  SAPI that cpsrvd uses — an undefined-function fatal on each call. The header is
  now read from `$_SERVER` first (`HTTP_AUTHORIZATION`, then
  `REDIRECT_HTTP_AUTHORIZATION`), with `getallheaders()` used only where it
  exists. CGI also drops the Authorization header outright on many servers, which
  this covers too.
- **The WHM plugin asked for a username and password.** Arriving through WHM the
  request is already authenticated as root, and cpsrvd sets `REMOTE_USER`. That
  is now accepted, so no sign-in form appears inside WHM — as the wiki always
  said it would not.
- **`api.cgi` could emit its own shebang into the response body.** The CGI SAPI
  does not reliably strip a `#!` line, and when it does not, the body begins with
  the interpreter path followed by JSON — unparseable, and surfacing as the same
  generic "Server error". The endpoint is now a `/bin/sh` wrapper that hands
  php-cgi the target via `SCRIPT_FILENAME`, so the file parsed as PHP has no
  shebang, and status codes (401, 402) still come through.
- The installer's API self-test now requires the body to *begin* with `{` rather
  than merely contain a brace, since the failure it guards against is stray bytes
  in front of otherwise valid JSON.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
