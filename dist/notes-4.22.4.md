# ServerScrub 4.22.4

[4.22.4] - 2026-10-30

### Fixed

- **No icon beside the cPanel menu entry.** The installer copied the WHM
  artwork — **256x256 and 87KB**. `install_plugin` accepted it, placed it
  correctly in `assets/application_icons/serverscrub.png`, reported "Plugin
  installed ok", and Jupiter drew nothing.

  Every icon Jupiter renders from that directory is **48x48** (cPGuard's is
  48x48 and 967 bytes). An oversized one is silently ignored rather than
  scaled, and nothing anywhere reports a problem — the file is present, the
  registration is valid, and the icon simply does not appear.

  A 48x48 copy now ships beside the page at `cpanel/serverscrub/serverscrub.png`
  and the installer prefers it, falling back to the WHM artwork if it is
  missing so a absent asset costs an icon rather than the whole registration.
  WHM keeps the large version: it serves the file directly from
  `addon_plugins` and is not size-constrained. Same artwork, two sizes, because
  the two panels resolve icons by completely different mechanisms.

- **The plugin page ignored cPanel's theme.** It carried its own
  `prefers-color-scheme: dark` block, so a customer whose operating system
  asked for dark got a dark panel inside cPanel's light one. A plugin does not
  get a vote on the control panel's theme. That block is gone, the page
  inherits cPanel's font rather than setting its own, and the remaining
  palette is taken from Jupiter's panels and buttons — so if cPanel gains a
  dark mode this page follows it for free.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
