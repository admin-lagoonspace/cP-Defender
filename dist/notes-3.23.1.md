# Sentinel Gate 3.23.1

[3.23.1] - 2026-08-28

### Fixed
- **A licence with no renewal date displayed the customer's name as its expiry.**
  The expiry fell back to `registeredname` when `nextduedate` was absent, which
  is not a date and not something to show in that field.
- A "Free Account" licence returns `nextduedate` as `0000-00-00`. That was shown
  verbatim; it now reads "No expiry".

Both are display-only - validity has always come from the licence status, not
from these dates.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
