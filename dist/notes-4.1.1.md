# ServerScrub 4.1.1

[4.1.1] - 2026-10-06

### Added
- **The navigation is pinned by a test.** The dashboard rebuild in 4.1.0 worked
  by inserting markup into the dashboard page, and a mis-placed insertion point
  is one of the easiest ways to damage a single-file UI: land inside the sidebar
  and nav entries vanish; land past the wrong closing tag and a whole page ends
  up nested in another. Neither fails a syntax check, and the only symptom is a
  menu entry that is quietly gone.

  `tests/test_navigation.php` now names all fifteen sidebar entries explicitly
  (a count still passes when one item is swapped for another), checks each has
  a page container and each page is reachable, keeps the three group headings,
  and asserts every piece of the new dashboard markup sits inside the dashboard
  page rather than in the nav or a neighbouring page.

  Verified against both accidents: removing one nav entry fails three
  assertions, and moving dashboard markup into the sidebar fails the
  containment check.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
