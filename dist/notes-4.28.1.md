# ServerScrub 4.28.1

[4.28.1] - 2026-11-02

### Fixed

- **CDN setup is a script now, not five commands in a release note.** Those
  commands hard-coded `/home/serversc/public_html/serverscrub/code`, which is
  the right docroot only if serverscrub.com is that account's MAIN domain. On
  an addon domain or a subdomain, `cdn-sync.sh` would publish into a directory
  no vhost serves, log "published", and exit 0 -- leaving the CDN at 404 and
  the operator holding a success message that said otherwise.

  `scripts/cdn-setup.sh` reads the docroot out of cPanel's own userdata and
  refuses to guess when it is not there; installs the 10-minute cron and reads
  it back; runs the first sync; and then fetches the public URL, and the build
  that URL's manifest names, before claiming anything is live. A manifest
  pointing at a zip that 404s is worse than a 404 manifest -- the updater
  announces an update and then fails to download it. `--check` re-runs the
  verification on its own and changes nothing.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
