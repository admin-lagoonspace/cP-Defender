# Sentinel Gate 3.19.7

[3.19.7] â€” 2026-08-27

Nothing in this project's pipeline had ever *run* the code it shipped. Every
gate checked it statically, so a method that did not exist was invisible until
the one request that used it reached a customer. That is the actual defect
behind the blank dashboard, the failing scanner, firewall, WAF and IP
reputation â€” one runtime `Error` each, in code that parsed perfectly.

### Fixed
- **`Database::getSetting()` does not exist â€” the method is `setting()`.** It was
  called from **11 sites** across `License.php` (7), `cron/scheduler.php` (2),
  `Scanner.php` and `WAFInstaller.php`. Because `License::status()` fatals and
  every feature route consults the licence, this single typo took down the
  dashboard, scanner, firewall, WAF and IP reputation together.
- `sys_getloadavg()` is called without a guard. It is absent on some hosts (and
  on Windows), which turned the whole dashboard payload into a 500.
- API errors now return the exception message, file and line. "Internal server
  error" with the cause hidden in a log file cost several diagnosis cycles that
  one line on screen would have ended.

### Added
- `scripts/check-calls.php` â€” verifies every `Foo::bar()` exists on `Foo` and is
  public, using `token_get_all()` rather than regex. A regex draft of this check
  missed 7 of the 11 call sites above, because its string-stripping ate real
  code; PHP's own lexer classifies strings, comments and heredocs exactly. An
  unreadable file aborts the run rather than reporting a pass.
- `scripts/smoke.php` â€” executes all 25 read-only API routes through the real
  router in a throwaway install and requires JSON from each. Only
  side-effect-free routes: nothing starts a scan, writes a firewall rule or
  touches the network. This is what would have caught every fault in this
  release, and in the three before it.
- Both run in preflight, so no release can be packaged without them passing.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
