# ServerScrub 4.37.4

[4.37.4] - 2026-11-19

### Fixed

- **Real-time detection identified malware and then left it running.** The
  monitor matched the file, wrote a threats row, logged a warning and raised a
  security event — and then did this, and only this:

  ```python
  if db_get(conn, 'auto_quarantine') == '1':
      quarantine(conn, path, tid)
  ```

  Two defects in two lines. It was a **plain move with no notion of
  severity**, so a critical finding the scanner would have deleted was merely
  relocated; and when the gate read anything other than `'1'` **nothing
  happened at all** — no quarantine, no disable, no flag, and no log line
  saying so. Live malware stayed executable on a server whose monitor had
  just named it. A detector that contains nothing is an alarm, not a defence.

  It also skipped the mass-detection bound, report-only signature feeds, the
  disable-before-acting step, and the owner/mode capture a restore needs —
  all of which already existed, in the scanner.

  Real-time detection now applies **the same policy as a scan**: critical and
  high are deleted (`policy_high_action` defaults to `delete`), everything
  else is quarantined with an expiry. It does not reimplement that policy in
  Python — a second copy would drift from the first the next time either
  changed. The daemon calls `serverscrub apply-policy <id>`, a new CLI command
  that invokes `Scanner::applyThreatPolicy()`, so all five detection paths now
  share one set of rules.

  If the policy cannot be reached — no PHP, a timeout — the daemon falls back
  to the containment it always had rather than leaving a known-malicious file
  alone, and says so in the log. When a file **is** left in place, that is now
  logged explicitly: the original defect was not merely inaction, it was
  silent inaction, with nothing to distinguish "contained" from "ignored".

  The monitor restarts as part of `update.sh`, so this takes effect on upgrade
  with no manual step.

- **The scanner log could not show more than its newest 50 rows.** The page
  requested a fixed `limit=50`, the API clamped `limit` to 200 and had no
  `offset` at all, and the footer read "last 50 scan(s)" — which looks like a
  total. A server with months of nightly sweeps showed fifty rows and gave no
  way to reach the rest, nor any sign that a rest existed.

  The log now pages: **50 per page by default, with 50 / 100 / 200 / 500 / All**,
  Previous and Next, and a count of the form "51–100 of 137" so the total is
  never in doubt. The choice is remembered for the session. "All" is bounded
  at 5,000 rows — a browser asked to lay out a hundred thousand rows stops
  responding — and the response flags when it had to truncate, rather than
  showing a prefix and calling it everything.

  Deliberately the same controls, in the same order, with the same wording as
  the WAF events table: two tables that page differently are two things to
  learn.

- **Raising the real-time watch ceiling did nothing until the monitor was
  restarted.** The watch list is built by walking the tree once at startup and
  nothing re-ran that walk, so a raised `rt_max_watches` added no watches,
  `rt_watch_capped` could only ever be set and never cleared, and the panel
  reported a count against a ceiling that was no longer binding — "20,000 /
  100,000" alongside "Watch limit reached", a state the kernel cannot be in.

  The daemon now re-walks on its reload tick when the ceiling moves, taking up
  the watches the lower ceiling refused and rewriting the count and the flag
  from what the kernel actually accepted. It also records **why** it capped,
  so the panel names the limit that is really binding: our own setting, which
  the page can raise, or the host's `fs.inotify.max_user_watches`, which it
  cannot. The old message named both in one breath, so whichever an operator
  fixed, the text still told them to fix the other.

  The effective-limit row is republished on every change too; it was written
  once at startup, so it described the settings the process booted with and
  nothing since.

- **Refresh on the Real-Time Monitor page did not refresh the controls.** It
  reloaded the status and left every field showing whatever it was last filled
  with, and the values loader had a one-shot guard that returned early — so
  pressing Refresh right after saving a limit was a no-op for exactly the
  fields that had just been edited. The button now forces a re-read; the
  periodic auto-refresh keeps the guard, so a timer tick still cannot
  overwrite a number being typed.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
