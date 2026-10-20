# ServerScrub 4.11.1

[4.11.1] - 2026-10-20

### Fixed

- **The Spam Monitor invented its own numbers, and sent an operator hunting a
  backdoor that was never there.**

  `collect()` computed one hour bucket from `time()` and filed **every log line
  it read** into it. A first run starts at offset 0 and reads up to 8 MB of
  **history** — days of mail on a busy server — so all of it was recorded as
  having happened in the last sixty minutes.

  On a live server that produced:

  > **critical** — inditdel sent 5,036 messages to 5,036 recipients in the last
  > hour (threshold 500)
  > **medium** — 19,862 messages passed through the system account "mailnull"

  The real figure was **22 messages across 300,000 log lines** — a normal
  multi-site reseller account doing nothing wrong. The subjects were WordPress
  update notices and password-change confirmations.

  The cost of that false alarm: an evening spent looking for a backdoor, and a
  25-domain reseller account capped to 100 messages an hour, which broke its
  password resets, contact forms and order mail. All of it caused by a number
  this module made up.

  Each line is now dated from **its own timestamp**. An unreadable timestamp
  returns null so the caller decides, instead of the parser quietly guessing
  "now" — which was the whole mistake. Undated lines are counted and logged, so
  a log this module cannot date is reported rather than silently producing soft
  rates.

  A monitor that cannot say *when* something happened cannot say how fast it is
  happening, and a rate is the only thing this module reports.

- **Existing records are discarded on upgrade.** The rows written before this
  fix cannot be corrected — the hour they belonged to was never recorded — so
  they are deleted and the log offset is reset, rebuilding history with correct
  timestamps. Without this, an upgraded server would keep showing the false
  critical until it aged out.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
