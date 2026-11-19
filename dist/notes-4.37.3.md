# ServerScrub 4.37.3

[4.37.3] - 2026-11-19

### Fixed
- **The WAF regeneration added in 4.37.1 would not have run on the update that
  shipped it.** An update runs the installed `update.sh`, which re-execs a copy
  of itself, never the newly downloaded one, so a step added there only runs
  one release later. The step now lives in `install.sh --register-only`, which
  the updater always runs from the freshly installed files. Servers coming
  from 4.37.0 therefore pick up the 4.37.1/4.37.2 WAF limits and the editor-save
  rule as part of this update. It runs only where a WAF config exists, keeps
  the current mode, and is validated by `apachectl` with automatic rollback.
  It was removed from `update.sh` so Apache is not reloaded twice.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
