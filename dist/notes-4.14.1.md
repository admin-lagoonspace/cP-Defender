# ServerScrub 4.14.1

[4.14.1] - 2026-10-22

### Fixed

- **Marking findings not-malware left every counter reading the old number.**
  The rows correctly flipped to *Not malware*, and a red **5** went on sitting
  beside the filter while the sidebar badge also said **5**. From the panel that
  is indistinguishable from the action having silently failed — which is the
  complaint the feature was built to fix in the first place.

  Two separate causes:

  - The red count was `data.length` — **rows on screen**, resolved ones
    included. It is now the number of findings still `active`, computed by the
    server with the same query the dashboard and sidebar already use, so there
    is one definition of "outstanding" rather than a second invented in
    JavaScript. It also turns grey at zero: red means something needs you, and
    a cleared scanner that stays red still reads as a compromised one.

  - The sidebar badge is written by `refreshDashboard()`, which only runs when
    the Dashboard page is opened. It therefore went stale after **every** threat
    action — quarantine and delete overstated it too, not just this feature.
    `loadThreats()` now updates it from the response it already has, costing no
    extra request (it is polled while a scan runs).

  The findings themselves stay listed, which is deliberate: the record of what
  was flagged and who judged otherwise is the audit trail.

### Added

- A **Not malware** option in the Scanner's status filter. Once a row stops
  being red it is otherwise very hard to find again, and reviewing what has been
  cleared is the whole basis of auditing this.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
