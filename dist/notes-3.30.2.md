# Sentinel Gate 3.30.2

[3.30.2] - 2026-09-23

### Fixed
- **The dashboard's Real-Time Monitor widget did the opposite of its label.**
  It was populated only by `toggleMonitor()`, so on a fresh dashboard it kept
  whatever the markup shipped with -- a green "Active" badge -- while the
  module-level `monitorRunning` stayed `false`. The button reads "Stop" in the
  HTML, so the first click called **start**. Reported as "I cannot turn it
  off"; it was turning it on.

  The dashboard now loads the monitor status when it refreshes, the widget
  ships as "Checking…" with the button disabled rather than asserting a state
  it has not read, and `toggleMonitor()` refuses to act before the first status
  load rather than acting on a guess.
- **The Scanner page never read the auto-quarantine setting.** The
  "auto-quarantine off" line was hard-coded in the markup and corrected only by
  `loadSettings()`, which runs on the Settings page. Opening the Scanner page
  directly showed the default whatever the toggle was set to, so the toggle
  looked like it did nothing. The setting itself was always honoured by the
  scanner; only the display was wrong. The page now reads it on load, and says
  "state unknown" if the read fails instead of asserting "off".
- **The firewall page could hang the whole dashboard.** `iptables -L` takes the
  xtables lock, and on a CSF server lfd rewrites rules continuously, so that
  call can sit waiting for a lock another process holds. cpsrvd serialises
  requests, so one stuck call stops every page responding -- not just the
  firewall one.

  Every shell command on that path is now bounded twice over: `-w 2` gives
  iptables a limited wait for the lock instead of an unlimited one, and
  `timeout(1)` bounds the command in case the binary ignores `-w`. The iptables
  count and the CSF status are cached for a minute, since neither changes
  between page refreshes and each costs a fork. The cheap database counts are
  read before anything forks, and a failing call can no longer reject the whole
  page load.
- A count that could not be taken was reported as `0` rules and the status line
  printed "iptables active" regardless -- both of which read as a working
  firewall with nothing in it. An unavailable count now says so.
- The Real-Time Monitor **page** badge showed a green "● Running" for a monitor
  that was up but scanning nothing, and for one deliberately paused for a
  backup. Both now have their own state, as they already did on the dashboard.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
