# Sentinel Gate 3.21.3

[3.21.3] - 2026-08-28

### Added
- **`sentinel license secret <value>`** - sets the WHMCS licensing addon secret
  without hand-editing PHP. 3.21.1 correctly reported that the secret was unset,
  but the only remedy offered was editing `mode.php` over SSH. That file is
  required by `config.php`, so a stray quote there is a fatal on *every* request
  - a worse outcome than the licensing problem being fixed.

  The command edits only the one line, escapes the value properly (a secret is
  an arbitrary string; quotes and backslashes are legal), verifies the result
  parses with `php -l` *before* putting it in place, and keeps a backup. The
  value is never echoed back or logged: it is the salt that makes a cached local
  key unforgeable.
- The licence panel's warning now shows that command rather than telling the
  operator to edit a file.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
