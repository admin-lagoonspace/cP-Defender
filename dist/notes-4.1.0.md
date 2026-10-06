# ServerScrub 4.1.0

[4.1.0] - 2026-10-06

### Added
- **The dashboard is rebuilt around period comparison.** Three headline
  figures — threats stopped, web attacks blocked, connections blocked — each
  showing this period, the change against the period before it, and the overall
  total. Below them an attacks-overview donut with this-period-against-last
  bars, an alerts panel, per-day charts for web attacks and for threats, and a
  summary list. The period is selectable (7 / 30 / 90 days).

  A number on its own says nothing about direction, which is why the comparison
  is the centre of the layout rather than a detail.

- **The product icon replaces every spinner.** The full lockup is the
  first-load splash; the icon with a caption underneath is the blocking
  overlay and the per-page loading state. A mark the user already associates
  with the product says *which* thing is working, where a generic ring could
  belong to anything on the page. It sits still for anyone who has asked for
  reduced motion.

- The new icon is now the browser tab icon, the touch icon, and the WHM and
  cPanel plugin icon.

### Fixed
- **Every chart guarded by `window.Charts` has been silently disabled.**
  `charts.js` declares `const Charts`, and a top-level `const` is not a
  property of `window` — so `window.Charts?.timeline` was always `undefined`
  and the guard meant to be defensive turned the chart off instead. The
  brute-force chart added in 3.36.0 had therefore **never drawn once**. Found
  by rendering the new dashboard in a browser rather than trusting it.

### Notes
- The summary reports only what the product actually measures. A metric we do
  not collect is left out rather than shown as zero: "Database infections: 0"
  on a product that never looks at a database is a claim, not a reading, and
  there is now a test that fails if one is added.
- Percentage change has awkward cases. A period with no predecessor reports
  "no earlier period" rather than a fabricated figure.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
