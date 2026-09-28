# Sentinel Gate 3.30.6

[3.30.6] - 2026-09-28

### Fixed
- **Killing a clamscan did nothing, because the worker immediately started
  another.** Reported as processes being "spawned immediately" however often
  they were killed. That is the worker doing exactly what it is built to do: it
  forks one `clamscan` per batch, so killing one ends that batch and the next
  begins. The worker is what has to die, and it has to die *first*.

  `Scanner::killRunawayScans()` does it in the only order that works: note each
  worker's `clamscan` children while the parent link still exists, kill the
  workers so nothing can spawn a replacement, then kill the children that were
  noted. Doing it the other way round is what makes `clamscan` look immortal.

- **A running scan could become invisible, and nothing could then stop it.**
  Two faults combined:

  `reapStaleJobs()` marked any job with no recorded `worker_pid` as
  `interrupted`. Workers started before 3.30.1 never recorded one, because the
  column did not exist then -- so after an upgrade a perfectly live scan was
  declared dead. Its row stopped showing as running, `liveScans()` could no
  longer see it, and `stopAllScans()` found nothing to stop.

  Meanwhile `isCancelled()` accepted only `cancelling` and `cancelled` as a
  reason to stop, so a worker whose job had just been marked `interrupted` read
  that as "carry on" -- and carried on scanning, forking a `clamscan` per batch,
  with no row anywhere accounting for it.

  Jobs with no recorded pid are now matched against the processes actually
  running (by `--job-id=` in the command line) and the live worker is adopted
  rather than declared dead. `isCancelled()` now treats any status that is not
  `running` or `pending` as a stop -- including a row that has been deleted
  outright.

- `Scanner::scanWorkerPids()` finds scan workers in `/proc` rather than trusting
  the database about what is executing, and `stopAllScans()` kills the ones no
  row accounts for. `sentinel scan-reap` and `scan-stop-all` now report what is
  actually running rather than what the table believes.

  Only `clamscan` processes parented by our own workers are ever killed. cPanel
  runs its own `clamscan` for mail, and nothing here matches on process name.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
