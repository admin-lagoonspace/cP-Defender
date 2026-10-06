# ServerScrub 4.1.2

[4.1.2] - 2026-10-06

### Fixed
- **The app would not load: the splash covered it permanently.** The call that
  removes the first-load splash was inserted into the wrong function in 4.1.0.
  It landed *after a `return`* in `reltime()`, where it could never run, so
  `openPage()` never dismissed anything. On any server with a session — which
  is every cPanel install — the first and only thing shown was the logo.

  Nothing errored. The app was running perfectly behind a cover that never
  lifted, which is why there was no clue on screen.

  The browser check at the time only exercised the *unauthenticated* path,
  where a separate timer happened to clear it. The broken path was the one
  nobody looked at.

- **The splash can no longer strand anyone.** It is now also removed when the
  window finishes loading, and on a timer, whether or not the render path
  remembered to. Verified by deleting the render-path call entirely: the app
  still becomes usable. A cover that can stick is worse than no cover.

- `tests/test_splash.php` reproduces the exact accident — a `dismissSplash()`
  placed after a `return` — and fails on it, as well as on the failsafes being
  removed or nested where they would never arm.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
