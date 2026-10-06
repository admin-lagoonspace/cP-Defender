# Sentinel Gate 3.37.1

[3.37.1] - 2026-10-06

### Added
- **Values printed on the attack timeline.** The chart showed the shape of a
  line and nothing else, so a peak could be seen but not read.

  Not on every point: thirty days across three series is ninety numbers on one
  small chart, which is less readable than none. Labels go on the regularly
  spaced points, the most recent one, and **each series' own peak** — never on
  a zero, because a flat run of "0 0 0 0 0" hides the numbers that matter.
  They carry thousands separators, since 97,400 beside 3,174 is otherwise hard
  to compare at a glance.

  Labels are placed around each other rather than at a fixed offset. Offsetting
  by series alone is not enough — two series at *adjacent* dates with similar
  values collide, which put "120" and "58" on top of one another in testing.
  Each label is now moved clear of the ones already placed, flipping below the
  point when there is no room above.

- **Every day has a hover value**, including the unlabelled ones: hovering a
  date shows all three series for it. That covers the rest of the chart without
  printing ninety numbers on it.

### Fixed
- **The timeline only ever showed its first render.** It replaced the `<svg>`
  with `outerHTML`, and the markup it generated carried no `id` — so from the
  second refresh onward `getElementById('timeline-chart')` found nothing and
  the update silently did nothing. `refreshDashboard()` is called from six
  places, so the chart on screen was whatever was true when the page was
  opened. It now replaces the contents and leaves the element alone.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
