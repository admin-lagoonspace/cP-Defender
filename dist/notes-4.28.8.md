# ServerScrub 4.28.8

[4.28.8] - 2026-11-03

### Fixed

- **The product was shadowing its own download URL.** `install.sh` writes
  `/etc/apache2/conf.d/serverscrub.conf` containing

      Alias /serverscrub  ${SG_WEB_DIR}

  and `conf.d` applies to EVERY vhost on the machine. So every URL beginning
  `/serverscrub/` is served out of the plugin's own directory and never
  reaches `public_html` -- which is why
  `serverscrub.com/serverscrub/code/latest.json` returned 404 for six
  releases while the file sat on disk with correct ownership and permissions,
  under a vhost with the correct DocumentRoot, reachable by a fingerprinted
  probe. Nothing about the file, the directory or the vhost was ever wrong.

  It only breaks on a machine that both runs ServerScrub and hosts the CDN,
  which is one machine: ours. That is why no customer ever hit it and why
  every check of the file, the permissions and the vhost came back clean.

  **The download path moves from `/serverscrub/code/` to `/releases/`** in
  `publish.sh`, `cdn-sync.sh`, `cdn-setup.sh`, `update.sh`, `upgrade.sh`,
  `get.sh`, `UpdateChecker.php` and `latest.json`. The reason is written
  beside the setting, and a test refuses any download URL beginning
  `/serverscrub` -- the mistake is invisible on any machine that does not
  host both, so it would otherwise be tidied straight back in.

  Existing installs lose nothing: that URL has 404d since the domain moved,
  and they fall back to the GitHub mirror exactly as they do today.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
