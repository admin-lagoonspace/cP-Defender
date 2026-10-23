# ServerScrub 4.15.1

[4.15.1] - 2026-10-23

### Fixed

- **"New version available â€” v4.15.0" shown directly above "You are running
  v4.15.0".** Not a display glitch. The banner, the Update Now button, the
  sidebar dot, the auto-updater's go/no-go decision and the daily cron all read
  one field, and that field was a **stored boolean**.

  `update_available` is a function of `(latest, current)`. Persisting the
  *answer* meant it was computed against whatever version was installed at
  **check** time â€” and then the install was upgraded, which is the single event
  guaranteed to invalidate it. Upgrades run from a shell script that has no
  reason to touch this database, so there was no moment at which the flag could
  have been cleared.

  So every user saw this after **every** successful upgrade, and the
  auto-updater would have cheerfully tried to "upgrade" 4.15.0 to 4.15.0.

  It is now derived at read time by comparing the stored latest version against
  the running one, which is self-correcting whatever did the upgrading â€” the
  panel's own updater, `/home/upgrade.sh`, or an rsync by hand. The stale
  stored value is also repaired on read, so nothing reading the raw setting can
  disagree with the panel.

  A genuinely newer version is still announced; a manifest that is empty,
  malformed, `v`-prefixed or *older* than the installed build is not an update.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
