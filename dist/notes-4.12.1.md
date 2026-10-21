# ServerScrub 4.12.1

[4.12.1] - 2026-10-20

### Fixed

- **Real-Time Monitor never loaded when you opened it.** The page dispatch was
  a sixteen-arm `switch` and `monitor` was simply not one of the arms. Every
  other page had a case; that one did not. So the panel sat on "Loading…" and
  "Checking…" indefinitely and had to be refreshed by hand every single time.

  The Refresh button worked, because it calls the loader directly — which made
  it look like a refresh problem rather than a missing wire.

  It also needed **two** loaders, not one: `loadMonitor()` fetches the daemon's
  status but not the systemd unit, which is why the Service panel stayed on
  "Checking…" even after a manual refresh.

- **Only one page in the product showed that it was loading.** `API.withBusy()`
  existed and was called exactly once, from `loadFirewall()`. Every other page
  loaded in silence, so a slow endpoint was indistinguishable from a broken
  one.

  The dispatch is now a **table**, and every page goes through one call site
  that wraps the load in the busy overlay. A page added tomorrow gets the
  indicator automatically and cannot be missed. Each entry returns its promise,
  so the overlay lifts when the work actually finishes rather than flashing.

- **A failed load left the page claiming to be loading.** `loadMonitor()`
  returned silently when the API call failed, so an error and a page that was
  never wired looked identical — both just sat on the placeholder text the
  markup ships with. That is precisely how the missing dispatch went unnoticed.
  It now shows "Status unknown" and says the monitor API could not be reached.

### Notes

- `tests/test_navigation.php` asserts **every** `data-page` in the sidebar has
  a loader, and every loader corresponds to a real page. A missing arm in a
  long switch is invisible; a missing key in a table now fails the build.

- Six existing tests pinned the exact `case 'x':` text or took a fixed-length
  slice of a function. They failed on a correct refactor, for reasons unrelated
  to what they were checking — the same brittleness that made `test_update_space`
  fail when `cpanel/` was added to the packager. They now assert the property
  rather than the spelling.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
