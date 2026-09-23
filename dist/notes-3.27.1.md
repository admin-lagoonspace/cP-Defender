# Sentinel Gate 3.27.1

[3.27.1] - 2026-09-23

### Fixed
- **Updating was impossible on the server that most needed the update.**
  `update.sh` copied `${INSTALL_DIR}/quarantine` and `logs` into
  `/var/backups/sentinel-gate` on every run - duplicating, on the same root
  partition, the very directory that had filled it. The update replaces only
  `backend/`, `frontend/` and `whm/`, so neither was ever at risk and neither
  needed copying. The backup now holds the database, `mode.php` and custom
  signatures: the things an update can actually destroy.
- **Nothing ever pruned those backups**, so every update since installation was
  still on disk. The most recent three are kept (`SG_KEEP_BACKUPS` to change it).
- **The update now checks for free space before touching anything**, and refuses
  with the sizes of quarantine and backups plus the commands that free them,
  rather than failing part-way through.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
