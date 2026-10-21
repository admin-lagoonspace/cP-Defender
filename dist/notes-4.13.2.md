# ServerScrub 4.13.2

[4.13.2] - 2026-10-21

### Fixed

- **The "Release Notes" link 404'd.** It pointed at
  `https://defender.lws-s1.com/serverscrub/code/v<version>/CHANGELOG.md`, and
  that CDN has never been populated — every `defender.lws-s1.com` path returns
  404. The *download* survives this because `update.sh` walks both channels and
  falls back to the GitHub mirror; **a single link in the panel has no
  fallback**, so it simply broke.

  It now points at `dist/notes-<version>.md` on GitHub, which `publish.sh`
  commits — so the URL is live the moment a release is pushed, GitHub renders
  the markdown, and it shows that version's notes rather than the whole
  history.

  The link is also **hidden** when a manifest carries no notes URL. A link with
  nowhere to go looks like a feature and does nothing.

- **The updater claimed success on a half-applied update.** On a live server
  `VERSION` read 4.13.1 while `backend/config/config.php` still defined 4.10.0:
  the top-level files were copied by `cp` and the backend was never delivered
  by the `rsync`. The panel correctly reported **4.10.0**, because the API
  reads `SG_VERSION` — and the updater had already printed *"Update
  complete"*.

  `update.sh` now reads `SG_VERSION` back out of the installed `config.php`
  and compares it with the `VERSION` file **before** the success banner. On a
  mismatch it reports a partial update, names both versions, records the run
  as failed and exits non-zero.

  An updater that can leave those out of step and still claim success is worse
  than one that fails outright — the operator believes they are patched.

### Notes

- `tests/test_packaging.php` asserts both release generators agree on the
  notes URL and that neither points at the unpopulated CDN. They write the same
  manifest, so whichever ran last wins — the same reason their file lists have
  to match.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
