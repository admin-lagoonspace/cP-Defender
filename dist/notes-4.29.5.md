# ServerScrub 4.29.5

[4.29.5] - 2026-11-03

### Fixed

- **Per-user reports stopped being written entirely in 4.29.0.**
  `serverscrub.php user-reports` returned **0 written, 132 skipped** -- every
  account on the server.

  The per-scan findings query added in 4.29.0 used `inClause()` as if it
  returned `['sql' => ..., 'params' => ...]`. It returns `[placeholders,
  values]` positionally, and the placeholders are bare `?,?,?` with no
  `IN(...)` around them. So `build()` raised two "Undefined array key"
  warnings and then

      TypeError: array_merge(): Argument #1 must be of type array, null given

  `writeAll()` catches `Throwable` per account and counts it as a skip, so
  the failure was reported as 132 unusable home directories -- which is a
  completely different problem, and sent everyone looking in the wrong place.

  Every customer's `report.json` has therefore been frozen at whatever was
  last written before 4.29.0. The cPanel page kept serving that stale file,
  which is why the Threats link never appeared no matter what shipped: the
  page was correct, the data was three releases old.

- **The tests for that feature all read source code; none of them ran it.**
  A dozen assertions matched the source exactly as written and every one
  passed, because the source was exactly what I wrote. A call that cannot
  execute is invisible to a grep. There is now a test that inserts a scan and
  two findings, calls `build()`, and checks what comes back -- including that
  the other account's finding from the same `/home` sweep does not appear,
  and that the row's count matches the list. Reverting the fix fails five of
  its assertions; the string-matching ones still pass.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
