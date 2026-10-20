# ServerScrub 4.10.1

[4.10.1] - 2026-10-20

### Changed

- **Renamed "Outbound Mail" to "Spam Monitor"** in the left navigation, so the
  protection is obvious at a glance. Two words, matching every other entry
  (Bot Shield, CMS Guard, Brute Force). The page subtitle now leads with
  **"Outgoing mail"** and notes that incoming is handled separately — on a
  server also running MagicSpam, an operator must not have to guess which
  direction this one covers.

- **Settings are now editable from the page**: monitor on/off, messages per
  hour per account, queue depth, frozen-message threshold, history retention,
  and the bulk-sender exemption list.

  Values save through `MailGuard`'s own clamps and **the stored value is the
  effective value**. Writing a raw number and letting the getter clamp it on
  read would mean the panel displays a threshold that is not in force — an
  operator who sets 10/hour, sees 10/hour and never gets an alert has been
  misled by their own security tool. Anything adjusted is reported back in
  words and the form is refilled from the server. Each field shows its
  accepted range before a value is rejected, not after.

### Fixed

- **The exemption list could silently exempt an account nobody named.** It
  split on whitespace as well as commas, so `bad name!` became `bad` plus
  `name!` — the second was rejected and the first, which looks like a perfectly
  valid account, was quietly added. An exemption stops all rate reporting for
  that account, so this disabled the alerts the module exists for with nothing
  appearing to go wrong. It now splits on commas and newlines only, and rejects
  an invalid entry whole.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
