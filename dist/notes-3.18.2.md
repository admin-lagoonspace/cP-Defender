# Sentinel Gate 3.18.2

[3.18.2] — 2026-08-11

### Fixed
- Release notes published to the CDN are now the notes for that one version.
  Every `v<version>/CHANGELOG.md` was a verbatim copy of this whole file, so a
  user opening the notes for the release they just installed got the entire
  project history instead of what changed. `scripts/extract-notes.sh` pulls the
  single section; `make-release.sh` writes it to `dist/notes-<version>.md` and
  into the version folder.
- `cdn-sync.sh` no longer falls back to the repo-root `CHANGELOG.md` when the
  per-version notes are missing — that fallback was what produced the full-history
  copies in the first place. It now reports missing notes and publishes none.
- The `notes` URL in `latest.json` points at the version's own notes rather than
  the full changelog on GitHub.

`CHANGELOG.md` in the repository remains the complete history; only what ships
per release changed.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
