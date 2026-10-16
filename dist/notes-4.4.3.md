# ServerScrub 4.4.3

[4.4.3] - 2026-10-16

### Fixed
- **Stopping a running scan is now obvious.** The control existed, but it was a
  ghost extra-small button at the far right of the progress row -- the least
  visible element on the page, for the one action an operator urgently wants
  while a scan is loading the server. The toolbar button, which is where they
  are actually looking, read "Scanning..." and was disabled. That button is now
  the stop control while a scan runs: red, enabled, and labelled **Stop Scan**.
  The control beside the progress bar is a full-size danger button.
- Five separate places set that button's label and disabled state by hand,
  which is how it came to disagree with itself. One function owns it now, and
  stopping or finishing a scan clears the followed job so the button reliably
  returns to starting one.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
