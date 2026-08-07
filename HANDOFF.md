# Sentinel Gate — Work Handoff (resume in Claude Code)

**Repo:** `admin-lagoonspace/cP-Defender` (GitHub, **public**) · working copy `C:\Users\rohan\OneDrive\code\cP-Defender`
**Target version this cycle:** `3.5.0` (bumped in files, **not built/committed yet**)
**Last committed:** `a6ab948` — v3.4.1 (local commit; **not pushed**)
**Product:** cPanel/WHM + standalone Linux server security suite (malware scan, firewall, WAF, rootkit, real-time monitor). PHP backend + vanilla JS frontend + Python monitor daemon.

---

## ⚠️ First thing to do in Claude Code

The prior session (Cowork) **lost shell access to the repo mount partway through**, so these steps could NOT be run. Do them first:

```bash
cd /path/to/cP-Defender
bash -n install.sh update.sh uninstall.sh scripts/make-release.sh   # syntax check
bash tests/run-tests.sh                                             # mock suite (expect ~117 pass)
python3 -m py_compile backend/daemon/monitor.py
```

If all green:

```bash
bash scripts/make-release.sh          # builds dist/sentinel-gate-3.5.0.zip + dist/latest.json
git add -A && git commit -m "feat: v3.5.0 — manifest+checksum updater, --register-only, public channel"
# then publish so servers can pull the update:
#   commit dist/sentinel-gate-3.5.0.zip and latest.json to the repo root/dist, and push
git push
```

Author identity for commits (repo convention): `admin-lagoonspace <admin@lagoonspace.com>`.

---

## What changed this cycle (uncommitted, on disk)

### 1. Clean install / uninstall (was v3.4.1)
- **uninstall.sh** now removes everything by default, no prompts:
  - web service unit has a hardcoded fallback path (was only removed if manifest existed)
  - deletes `/tmp/sentinel-gate`, `/var/backups/sentinel-gate`, leftover `/tmp/sg-update.*`
  - persists iptables rule removal to `/etc/iptables/rules.v4` (port was reopening on reboot)
  - safety check: only `rm -rf` the source dir if it contains `install.sh` + `VERSION`
- **install.sh** pre-install cleanup: stops services, wipes stale `backend/`/`frontend/` (so files deleted between versions don't linger), sweeps pre-3.2 legacy CGI/AppConfig artifacts; non-interactive guard on the failed-verification rollback prompt.
- **monitor.py** CPU throttle restored (the v3.3.7 rewrite dropped it while the Settings UI/DB kept `cpu_limit_percent`). `get_cpu_limit` / `cpu_to_nice` / `cpu_to_scan_sleep` / `apply_cpu_priority` / `get_poll_interval` now wired into `main()` and the inotify loop.
- **tests/mock-env/stubs/zip & unzip** made cross-platform (Linux/macOS fallbacks; were Git-Bash-only).

### 2. Upgrade path via public channel (this cycle, v3.5.0)
- **Decision:** repo is public, so updates are served straight from it — no separate releases repo, no credentials on customer servers.
- **update.sh** rewritten:
  - fetches `latest.json` from `https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main/latest.json`
  - manifest carries `version` / `url` / `sha256` / `notes` (URL is explicit → kills the old `v`-prefix vs no-prefix filename mismatch)
  - **verifies SHA256 before extracting**; refuses to install on mismatch
  - overlay via rsync `--delete`, preserves data (database, logs, quarantine, mode.php, custom.sig) — **in-place overlay, never uninstall-first** (uninstall wipes data by default)
  - version compare is suffix-tolerant (handles `-rc1`, falls back to `sort -V`)
  - after overlay, calls `install.sh --register-only`
  - env overrides: `SG_RELEASES_REPO`, `SG_RELEASES_BRANCH`, `SG_MANIFEST_URL`
- **install.sh `--register-only`**: re-runs only WHM/cPanel (or standalone service) registration against an existing install — auto-detects mode from `mode.php`, no prompts, skips dirs/files/DB/services, never offers uninstall. install.sh now also copies itself into the install dir so this works post-overlay.
- **scripts/make-release.sh** (new): builds zip, computes SHA256, writes `latest.json` consistently.

---

## Still TODO (in priority order)

1. **Run validation + build + commit** (commands above). This is the only thing blocking a shippable 3.5.0.
2. **Publish the release**: put `sentinel-gate-3.5.0.zip` under `dist/` and `latest.json` at repo root, push. Until `latest.json` is live, `update.sh` has nothing to pull (it fails with a clear diagnostic).
3. **git history secret scan** — could not run (needed shell). Working tree is clean (no keys/tokens/.env/.pem). Run:
   ```bash
   git log -p | grep -niE 'AKIA|ghp_|github_pat_|BEGIN .*PRIVATE KEY|password\s*=\s*.[^ ]'
   ```
4. **JWT secret weakness** (design, now public-relevant): `backend/config/config.php` derives the JWT signing key from `hash('sha256', gethostname() . 'sentinel_gate_secret_2024')`. Since source is public, anyone who knows a server's hostname can reproduce its token-signing key → possible session forgery. Fix: generate a random secret at install time, store per-server (mode.php or DB), fall back to the old scheme only if unset. `install.sh` DB-init block also hardcodes the same salt — update both.
5. **Optional: signature verification** beyond SHA256 (minisign/GPG) — SHA256 covers corruption/MITM of the zip but not a compromised repo. Deferred; user aware.
6. **Palette mismatch** (cosmetic, tracked separately): new logo is emerald/graphite, dashboard UI still cyan/indigo (older) — v3.4.0 did a UI redesign to violet/emerald; confirm logo vs UI are consistent.

---

## Environment gotchas (bit us in Cowork; may not apply in Claude Code)

- **OneDrive-synced repo.** Host-side edits can lag the shell view; if a file looks truncated on disk right after an edit, re-write it via the shell and let it settle.
- Git in the sandbox left stale `.git/*.lock` files that couldn't be removed there. If git complains about a lock, delete `.git/index.lock` / `.git/HEAD.lock`.
- The Cowork sandbox mount fully detached mid-session (all paths permission-denied). Native Claude Code shouldn't have this problem.

---

## Versioning rule (project convention — apply on every build)

`X.Y.Z`, max 99/segment. Bug fix → bump Z. New feature/functional change → bump Y (reset Z). Major rework → bump X. Update version in **all** of: `VERSION`, `backend/config/config.php` (`SG_VERSION`), `whm/sentinel.conf` (`version`), `frontend/index.html` (sidebar label), and the zip filename. (This cycle = new feature → 3.4.1 → **3.5.0**.)

## Key files
- `install.sh` / `uninstall.sh` / `update.sh` — lifecycle (bash, run as root)
- `scripts/make-release.sh` — release builder
- `backend/lib/*.php` — Scanner, Firewall, WAF, RootkitScanner, IPReputation, Auth, Database, etc.
- `backend/daemon/monitor.py` — real-time inotify/polling monitor
- `backend/api/index.php` — REST API router; `backend/standalone-router.php` — standalone web entry
- `frontend/` — dashboard (index.html + js/app.js, api.js, charts.js)
- `whm/` — AppConfig conf, systemd units, ConfigObj Driver (SentinelGate.pm)
- `tests/run-tests.sh` — mock test suite (no Docker/WSL needed)
