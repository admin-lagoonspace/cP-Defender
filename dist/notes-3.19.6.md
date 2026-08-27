# Sentinel Gate 3.19.6

[3.19.6] â€” 2026-08-27

The dashboard reaches the API now. These are the faults behind the panels that
loaded but stayed empty.

### Fixed
- **Every page that consults a licence went blank.** `License::log()` called
  `Logger::write()`, which is **private** â€” an `Error`, not a warning, so the
  leading `@` suppressed nothing. Worse, `log()` is called from the `catch` block
  in `status()`, so the fatal *replaced* whatever it was reporting. It now uses
  the public `Logger::info()`, wrapped so logging can never be the thing that
  breaks a request.
- **"Constant already defined" on every request.** `config.php` defined
  `SG_ROOT`/`SG_VERSION` and then included `mode.php`, which set them again.
  `mode.php` is now loaded first and every define in `config.php` is guarded, so
  the file is correct against any vintage of `mode.php` â€” which matters because
  `install.sh --register-only`, the path `update.sh` takes, does not rewrite it.
- **Scheduled tasks still died with "Undefined constant SG_DB".** Cron entries
  written before 3.19.4 load `mode.php` only, and `update.sh` does not rewrite
  cron, so fixing the installer was not enough on its own. `Database.php` now
  derives `SG_DB` from `SG_ROOT` when it is absent.
- The dashboard shows the server's actual error rather than directing the reader
  to a log file they then have to go and read.

### Added
- Preflight scans for calls to non-public methods across classes. `php -l`
  cannot see these â€” they are runtime `Error`s, not syntax errors â€” and this one
  cost a release. Verified by reintroducing the bug: the gate rejects it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
