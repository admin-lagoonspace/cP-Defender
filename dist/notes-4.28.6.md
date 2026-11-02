# ServerScrub 4.28.6

[4.28.6] - 2026-11-02

### Fixed

- **"Paused - rsync" and "Active" sat on the same screen, both true, and the
  page never said which was which.** The Monitor Status card reports whether
  the daemon is SCANNING; the System Service card reports whether the PROCESS
  is up. During a backup the daemon deliberately keeps running and stops
  scanning, so both answers are correct -- and side by side with no
  explanation they read as the product contradicting itself.

  The behaviour is right and has not changed: the daemon sets a flag on itself
  and stays up. It must. A process that exited would need restarting, would
  lose its inotify watches, and would leave nothing running to notice the
  backup finish -- which is exactly why systemd still reports it healthy.

  What changed is that the words now carry their subject. The service badge
  says **Running**, or **Running - scanning paused**, and stays green, because
  the service is healthy and that is the point. The scanning badge says
  **Scanning** or **Scanning paused - rsync**. Nothing says a bare "Active"
  any more: "active" is the word that invited the two to be compared as if
  they were the same claim. The service card explains itself when paused,
  leading with "The service is running", why it stays up, and that scanning
  resumes on its own.

- **Three cards spelled those states out three times, in three vocabularies.**
  They now come from one `scanStateLabel()`, and the service badge from one
  `renderServiceBadge()` that reads both systemd's answer and the daemon's --
  rendering from systemd alone is what produced the bare "Active".

- **On the monitor page the service card had no way to know.**
  `loadMonitor()` never recorded the monitor state; only `loadMonitorStats()`
  did, and that does not run on the monitor page -- the one page showing both
  cards. It records it now, and re-renders the service badge, so whichever of
  the two parallel loaders lands last the pair ends up consistent.

- The dashboard alert says "Real-time scanning is paused while rsync runs --
  the service is still running", naming what is paused and what is not,
  instead of reading as an outage beside a panel reporting the unit healthy.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
