# Sentinel Gate 3.30.1

[3.30.1] - 2026-09-23

### Fixed
- **The scanner's Stop button did not stop anything.** It cleared the progress
  poller, hid the progress card and announced "Scan stopped" — without telling
  the server. The scan carried on at full speed with clamscan running flat out.
  The button did not fail to stop something; it reported a stop that had never
  happened.

  Two things are worth separating here. The real-time monitor's Stop button
  stops the monitor daemon, which never runs clamscan — it uses its own pattern
  engine. clamscan belongs to a **scan**, and there was no way to stop a scan
  at all: once started it ran to completion whatever the operator did.

  Stopping now happens on both sides, because either alone is unreliable. The
  job is marked `cancelling`, which the batch loop checks between batches and
  exits cleanly with its partial results recorded; and the worker's process
  **group** is signalled, which reaches the clamscan it is currently blocked
  on. Signalling the worker alone would leave that clamscan to finish its
  batch, which on a large file takes a while — the reported symptom.

  The worker now detaches into its own session (`posix_setsid`) and records its
  pid and process group on the job row, so there is something to signal. A
  scan stopped part-way is recorded as `cancelled`, never as `done`: writing
  `done` over a partial scan tells the operator the tree was examined when most
  of it was not. Any clamscan still present after the signal is counted and
  reported rather than glossed over.

- **A failed systemd unit could not be cleared from the dashboard.**
  `systemctl stop` on a failed unit succeeds and leaves the state exactly where
  it was, so the service card showed "failed" indefinitely — and once systemd's
  start rate limit is reached it refuses to start the unit again until it is
  reset. Stopping now runs `systemctl reset-failed` when the unit is in that
  state, which is what leaves the service in a condition Start can act on.
- The `reset-failed` check read `$detail['state']`, a key `serviceDetail()`
  does not return; it returns `active`. The check would never have fired.
- The PID fallback in the monitor's stop path signalled only the process, not
  its group.

### Added
- `scanner/stop` and `scanner/running` routes, and `Scanner::stopScan()`,
  `runningJob()` and `isCancelled()`.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
