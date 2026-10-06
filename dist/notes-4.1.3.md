# ServerScrub 4.1.3

[4.1.3] - 2026-10-06

### Fixed
- **The new dashboard's donut and both bar charts were blank.** The
  cache-busting step stamped a hand-kept list of three files — `app.css`,
  `api.js`, `app.js` — and **`charts.js` was not on it**. So after updating, a
  browser kept the pre-4.1.0 `charts.js`: `Charts` was defined and the older
  charts still drew, but `donut()` and `bars()` did not exist. The dashboard's
  guards correctly skipped those panels rather than throwing, so three sections
  were simply empty with nothing in the console to explain it.

  Everything else on the page — the headline cards, the comparison bars, the
  legend, the alerts — rendered from data, which is why the page looked half
  alive.

- **The release script now stamps every local `css/` and `js/` reference by
  pattern**, not by name. A guard that is a list of filenames is out of date
  the first time someone adds a file, which is exactly what happened here.

- `tests/test_asset_cache.php` fails if any local asset is unstamped or carries
  a stale version, and pins the chart methods the dashboard depends on.
  Verified against the shipped state: an unstamped `charts.js` fails two
  assertions, a stale stamp fails a third.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
