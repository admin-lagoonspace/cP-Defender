# Sentinel Gate 3.19.5

[3.19.5] â€” 2026-08-27

### Fixed
- **The dashboard showed a login screen that could never succeed on cPanel.**
  cpsrvd refuses to execute any CGI in the WHM docroot that is not registered
  with AppConfig, answering with a 403 HTML page:

      WHM is configured to disallow execution of unregistered applications
      when logged in as root or a reseller with the "all" ACL

  Only `sentinel_gate.cgi` was registered, so the dashboard loaded while every
  request to the separate `api.cgi` was refused. `api.js` could not parse the
  403 HTML, every candidate endpoint failed, auto-login never completed, and the
  page fell back to its default state â€” the login form.

  This survived several releases because the shell bypasses cpsrvd entirely:
  invoking `api.cgi` from a root prompt worked perfectly, and did so right up
  until the browser was finally asked to make the same call.

  The registered CGI now serves both. A request carrying `?r=` is handled as the
  API; anything else returns the dashboard. Static assets are unaffected â€”
  cpsrvd serves css/js/images as files rather than as applications, which is why
  they always loaded.

  Registering a second application would also have worked but adds a second WHM
  menu entry, and `permit_unregistered_apps_as_root` would weaken the server to
  suit this plugin. Neither is acceptable when one entry point does the job.

- The stale `api.cgi` is removed on upgrade, and `./api.cgi` is kept in the
  client's candidate list only so a part-upgraded install still finds an
  endpoint.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
