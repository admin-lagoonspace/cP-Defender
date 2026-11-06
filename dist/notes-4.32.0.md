# ServerScrub 4.32.0

[4.32.0] - 2026-11-06

### Fixed

- **The WordPress database sweep never scanned anything.** `sweep()` read its
  inventory with `$i['cms']` and `$i['path']`, but `CMSGuard::getInstalls()`
  returns rows from `cms_installs`, whose columns are `cms_type` and
  `install_path`. So the comparison was always `'' !== 'wordpress'` and every
  install on the server was skipped: the sweep examined none of hundreds of
  WordPress sites, recorded nothing, and the panel reported `Read 0 of 0
  installs - 0 new finding(s)` in green. Nothing threw, nothing was logged as
  an error, and every count printed was truthful -- only the premise was
  wrong. This is the module whose whole purpose is the half of a compromise
  that is not a file, and it was answering "clean" without having looked.
- **An empty sweep is no longer reported as a success.** A sweep that found no
  installs warns and says what to check, rather than toasting a result
  indistinguishable from a clean server.
- **A recorded install whose directory has gone is dropped** rather than
  counted in `installs` and never scanned.
- **`WPDatabaseScanner` did not require `CMSGuard`**, so the sweep would fatal
  in cron, where nothing else loads it.
- **The scanner-log Refresh button gave no feedback.** It worked -- but it was
  wired as a bare `onclick`, so there was no disabled state, no icon and no
  confirmation, and between two scans the table comes back identical. A click
  that repaints the same rows cannot be told apart from a click that did
  nothing. Now routed through `doRefresh()`, as 20 of the other 23 refresh
  controls already were; the bot-blocked and brute-force buttons had the same
  defect and are fixed too.

### Added

- **The real-time monitor watches directories created after it started.**
  inotify watches are per-directory and do not recurse, and the watch list was
  built once by walking the tree at startup -- so a directory created
  afterwards had no watch, and every file created inside it was invisible for
  the lifetime of the daemon. Creating a directory and dropping a payload in
  it is the ordinary shape of a web-shell drop, and a restart was the only
  thing that closed the gap. New trees are now watched recursively, bounded by
  `rt_max_watches`, and swept once on arrival: between the directory being
  created and the watch being added, files can land and inotify never delivers
  those events to anybody.
- **A loading icon on refresh.** `.btn-spin`, reusing the existing keyframes,
  in the button's own colour so it works on a ghost button in either theme,
  and static under `prefers-reduced-motion`.
- **Queued mail older than 72 hours is deleted automatically.** Exim retries
  until a message's retry data expires -- days -- so a message queued for
  three days is stuck, not waiting, and they accumulate until the queue is
  unreadable and an active relay is invisible in it. Runs hourly via a new
  `mailqueueprune` task, through the existing `MailGuard::deleteMessages()`.
  Settings: `mq_autodelete` (on), `mq_max_age_hours` (72),
  `mq_autodelete_cap` (500 per run, which is also exim's per-call ceiling
  here). The age is clamped to **at least 24 hours** whatever is configured:
  the field is in hours, and a `1` meant as "one day" would otherwise delete
  an hour-old queue mid-retry. Deletions are logged by id before they happen
  and raise a `mailqueue_pruned` security event.

### Notes

- The WordPress database scanner remains **report-only** by design, as asked:
  it opens read-only connections and records findings as `open` for an
  operator to judge. It issues no destructive SQL against a customer database.
  A test now enforces that.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
