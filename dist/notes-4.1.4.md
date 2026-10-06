# ServerScrub 4.1.4

[4.1.4] - 2026-10-06

### Fixed
- **The sidebar still showed the old logo on an updated server.** The markup
  and the file were both correct — the browser was serving a cached
  `icon-64.png`. That filename held the old cropped shield in 4.0.0 and the new
  mark in 4.1.0: same name, different picture. A file whose *contents* change
  between releases is cached exactly as hard as one whose name never changes,
  and images were not being cache-busted at all.

  This is the second half of the same lesson as `charts.js` in 4.1.3. Images
  are now stamped alongside css and js.

- **Images built in JavaScript are stamped too.** Stamping the markup alone
  missed them: the loading mark and the dashboard cards each build their own
  `<img>`. `window.SG_ASSET_V` carries the release version and `assetUrl()`
  applies it, with a test that fails if any image is built without it.

  The product name stays to the right of the mark, unchanged.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
