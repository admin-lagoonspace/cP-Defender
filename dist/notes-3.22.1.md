# Sentinel Gate 3.22.1

[3.22.1] - 2026-08-28

### Added
- **`sentinel license try-secret <value>`** - tests a candidate secret against
  the live licence server without storing it. Finding the right value otherwise
  meant writing each guess into `mode.php` and re-running activation: editing
  live configuration to answer a question, and leaving the wrong value in place
  when the guess was wrong.

### Notes
- `probe` should have existed before any of the licensing fixes, not after
  seven releases of changing one variable at a time. Three genuinely different
  failures all surface as "Invalid" from the client side, and the tool that
  distinguishes them is worth more than any wording change to the messages that
  cannot.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
