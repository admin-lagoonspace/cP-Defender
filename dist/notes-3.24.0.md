# Sentinel Gate 3.24.0

[3.24.0] - 2026-08-28

### Fixed
- **A scan did nothing at all.** Under cpsrvd the API runs as `php-cgi`, so
  `PHP_BINARY` *is* `php-cgi` - and php-cgi refuses to run a script from the
  command line without `REDIRECT_STATUS`. The background worker exited on its
  first line, the job row stayed at zero, and the scan appeared to hang. This
  was introduced in 3.20.0, replacing "the bare `php` might not be on PATH" with
  "the interpreter is definitely the wrong SAPI". The worker now uses a binary
  confirmed to report `PHP_SAPI === 'cli'`, asked rather than guessed from the
  filename.
- **Failing requests were invisible.** `if (!res?.success) return;` appears
  throughout the UI: it renders nothing and logs nothing, so a failing endpoint
  looks exactly like a button that was never wired up. HTTP failures are now
  reported centrally, with the server's own explanation. 401 and 402 keep their
  existing handling.
- **Monitor start/stop said only "Action failed".** It now reports why - the
  daemon script missing, systemd refusing, the unit not installed - which is the
  part that makes it actionable.
- **The resource limits could not be edited without first selecting Custom**, and
  the fields were hidden until you did, so the section read as preset-only. The
  limits are always visible, always editable, and editing one switches the
  profile to Custom automatically, so a typed value is never discarded because
  the profile was left on a preset. Selecting a preset fills the fields with the
  numbers that preset stands for.

### Added
- `scripts/check-ui-handlers.php`, in preflight: every `onclick`/`onchange` in
  the markup must resolve to a function that exists. A handler pointing at a
  renamed or never-written function does nothing when clicked - no error, no
  request, nothing - and no other check in this project could see it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
