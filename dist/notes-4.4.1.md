# ServerScrub 4.4.1

[4.4.1] - 2026-10-15

### Fixed
- **Daily and weekly tasks now run at the time they are configured for.**
  `isDue()` required 23h55m to have elapsed since the *last run* before it
  would look at the clock at all, so a single late run pinned a task to that
  later time permanently: every run could drift later and none could drift
  back. On the server that reported this, a malware scan configured for 09:00
  was running at 20:30, `iprep` set for 03:00 ran at 04:18, and `rootkit` set
  for 00:00 ran at 04:19 -- with cron firing correctly the entire time. The
  time-of-day check alone already prevents a double-fire and lets a drifted
  task recover its proper hour.
- An unrecognised `*_schedule` value ran its task exactly once and then never
  again: the never-run shortcut came before the schedule was validated. A
  misconfigured schedule now simply does not fire.

### Changed
- The scheduling decision moved to `backend/lib/Schedule.php` so it can be
  tested. It never had been -- it lived inside a script that runs its tasks on
  include, so the only way to exercise it was to let it fire real scans.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
