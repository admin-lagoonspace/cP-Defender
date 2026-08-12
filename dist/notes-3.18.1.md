# Sentinel Gate 3.18.1

[3.18.1] — 2026-08-08

### Added
- `scripts/check-version-bump.sh` — compares the bump in `VERSION` against the
  commit subjects since the last tag and fails the release when they disagree.
  `publish.sh` runs it in strict mode.

### Note
- The versioning convention was already stated at the top of this file and was
  still not followed. 3.14.0, 3.16.0 and 3.17.0 all bumped the minor for work
  that was a fix or UI on an already-shipped feature — 3.16.0's own commit
  subject begins `fix:`. A rule that lives only in a document gets ignored, so
  it is now enforced by the release script. Verified by replaying 3.16.0
  through the checker, which correctly rejects it.
- This release is itself a patch: tooling and docs, no new product capability.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
