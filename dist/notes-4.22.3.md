# ServerScrub 4.22.3

[4.22.3] - 2026-10-30

### Fixed

- **The cPanel plugin threw the customer out of cPanel.** Clicking the Security
  entry replaced the control panel with a bare page — no left-hand menu, no
  navigation, no way back except the browser's Back button. A plugin that
  takes the customer out of the panel does not look like part of it.

  The page emitted a complete HTML document of its own. It now renders through
  cPanel's LiveAPI (`$cpanel->header()` / `->footer()`), inside the normal
  frame, and is named `index.live.php` to match the convention cPGuard uses on
  the same server. The standalone document is kept as a fallback for when the
  LiveAPI class cannot be loaded — rendering without chrome beats rendering
  nothing.

  All of the page's CSS is now scoped to a `.sscrub` container. It previously
  defined its variables on `:root` and styled `body` and `*` directly, which
  was harmless in a document of its own and reaches cPanel's own markup inside
  the frame: `--bg`, `--fg` and `--line` are generic enough to collide with the
  theme's, and a bare `*` would reset `box-sizing` for the whole control panel.
  The container takes no background and inherits its colour, so it sits on
  whatever cPanel is using instead of painting a different shade in the middle
  of it.

  An upgraded server still has the old `index.php` beside the new file, and it
  would serve the old standalone page to anyone reaching that path directly.
  Registration now removes it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
