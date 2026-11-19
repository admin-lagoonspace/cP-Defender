# ServerScrub 4.37.1

[4.37.1] - 2026-11-19

### Fixed
- **WAF rejected page-builder saves over 128 KB with a 413.** The generated
  WAF config set `SecRequestBodyNoFilesLimit 131072` with
  `SecRequestBodyLimitAction Reject`, so Elementor and Gutenberg saves of any
  mid-sized page failed with "Server Error 413 (Request Entity Too Large)".
  Raising ModSecurity's limits in cPanel's own config had no effect, because
  ours loads later and wins. The limits are now 10 MB without files and
  128 MB in total (ea-nginx's own default), with an explicit 128 KB in-memory
  limit so larger bodies spool to disk rather than RAM.
- **WAF config changes never reached existing servers.** The config is
  generated, so a release that changed it only took effect after someone
  changed the WAF mode by hand. `update.sh` now re-renders it in its current
  mode through `reapplyConfig()`, validated by `apachectl` and rolled back if
  Apache rejects it; servers without the WAF set up are left alone.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
