# ServerScrub 4.15.2

[4.15.2] - 2026-10-23

### Fixed

- **Settings named the wrong quarantine directory.** Storage Management showed
  `/usr/local/serverscrub/quarantine`, which was a **hard-coded placeholder in
  the markup**. That is only the last-resort default: `config.php` prefers
  `/home/.serverscrub` or `/var/.serverscrub` whenever either is writable, so on
  a cPanel server quarantine lives under `/home` and the panel named the wrong
  partition on every such install.

  Not cosmetic — an operator reading it sizes the wrong filesystem. This product
  has already shipped one bug from the same assumption: an update rolled itself
  back after `chmod`-ing `${INSTALL_DIR}/quarantine` on a server whose
  quarantine was at `/home/.serverscrub/quarantine`.

  Both cards now show **In use now** — the real path, from the server — and the
  "blank = default" placeholder is the default that machine would actually use.

- **The whole Storage Management card was never loaded.** Files held, status,
  log sizes and every database row count read `--` until you pressed Refresh,
  which reads as "nothing is stored" rather than "this was never loaded".
  `loadStorageStats()` was reachable only from its own Refresh button and was
  missing from the Settings page loader.

### Changed

- `scripts/check-js-wiring.py` now follows a loader into its renderer. It
  existed to catch exactly this bug and missed it, because `loadStorageStats()`
  touches no element itself — it hands the payload to `populateStorageUI()`.
  It now follows a helper that has **exactly one caller in the file**, which
  distinguishes a loader's private renderer from a shared utility like
  `toast()`; page loaders and click handlers are excluded, since what those
  write to is not the calling loader's responsibility.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
