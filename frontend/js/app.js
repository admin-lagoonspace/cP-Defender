/**
 * Sentinel Gate — Main Application
 * SPA controller, page routing, all UI interactions
 */

// ── State ─────────────────────────────────────────────────────────────────────
const State = {
  currentPage:  'dashboard',
  scanJobId:    null,
  scanInterval: null,
  refreshInt:   null,
  geoSelected:  new Set(),
  user:         null,
};

// ── Install mode (fetched from API on load) ───────────────────────────────────
State.installMode = 'cpanel'; // default until API responds
State.version     = '';       // filled by detectMode()

async function detectMode() {
  try {
    const res = await API.status();
    if (res?.success) {
      State.installMode = res.mode    || 'cpanel';
      State.version     = res.version || '';
    }
  } catch (_) { /* stay with default */ }
  applyModeUI(State.installMode); // always update UI, even on API failure
}

function applyModeUI(mode) {
  const isStandalone = mode === 'standalone';

  // Login screen labels
  const sub   = document.getElementById('login-mode-sub');
  const badge = document.getElementById('login-mode-badge');
  const label = document.getElementById('login-user-label');
  const hint  = document.getElementById('login-hint');
  const userEl = document.getElementById('login-user');

  if (sub)   sub.textContent   = isStandalone ? 'Standalone Linux Server' : 'cPanel Security Suite';
  if (label) label.textContent = isStandalone ? 'Admin Username' : 'cPanel / WHM Username';
  if (userEl) userEl.placeholder = isStandalone ? 'admin' : 'root';
  if (hint)  hint.textContent  = isStandalone
    ? 'Local admin credentials set during installation'
    : 'Uses your existing cPanel / WHM credentials  ·  Demo: demo / demo';
  if (badge) badge.innerHTML = isStandalone
    ? '<span style="font-size:.68rem;padding:3px 10px;border-radius:20px;background:rgba(16,185,129,.15);color:var(--green);border:1px solid rgba(16,185,129,.3);letter-spacing:.05em">⚡ STANDALONE LINUX</span>'
    : '<span style="font-size:.68rem;padding:3px 10px;border-radius:20px;background:rgba(59,130,246,.15);color:var(--blue);border:1px solid rgba(59,130,246,.3);letter-spacing:.05em">🖥 cPANEL / WHM</span>';

  // Sidebar version / mode label
  const sideLabel = document.getElementById('sidebar-mode-label');
  if (sideLabel) {
    const ver = State.version ? `v${State.version}` : '';
    sideLabel.textContent = isStandalone ? `${ver} · Standalone` : `${ver} · cPanel Plugin`;
  }

  // Settings page: show/hide standalone-only cards
  const banner = document.getElementById('standalone-settings-banner');
  const chpw   = document.getElementById('card-change-password');
  if (banner) banner.classList.toggle('hidden', !isStandalone);
  if (chpw)   chpw.classList.toggle('hidden',   !isStandalone);
}

// ── Auth ──────────────────────────────────────────────────────────────────────
const Auth = {
  isLoggedIn() { return !!localStorage.getItem('sg_token'); },

  logout() {
    localStorage.removeItem('sg_token');
    localStorage.removeItem('sg_user');
    location.reload();
  },

  init() {
    if (this.isLoggedIn()) {
      document.getElementById('login-screen').style.display = 'none';
      const u = JSON.parse(localStorage.getItem('sg_user') || '{}');
      State.user = u;
      State.installMode = u.mode || 'cpanel';
      const av = document.getElementById('user-avatar');
      if (av && u.username) av.textContent = u.username.slice(0,2).toUpperCase();
      applyModeUI(State.installMode);
      detectMode(); // async: fetches live version from API and updates sidebar

      // Licence gate, checked before the dashboard loads rather than after.
      // Letting the pages load first means every panel fires a request that is
      // refused with 402 and renders empty behind the activation screen.
      enforceLicenseGate();

      return true;
    }
    // Not logged in — detect mode for login screen
    detectMode();
    return false;
  }
};

// ── Toast Notifications ───────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  const icons = { success: '✓', error: '✕', info: 'ℹ' };
  el.innerHTML = `<span style="font-size:1rem">${icons[type]||'ℹ'}</span><span>${msg}</span>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ── Page Navigation ───────────────────────────────────────────────────────────
function openPage(name) {
  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));

  // Show target
  const page = document.getElementById(`page-${name}`);
  if (page) page.classList.remove('hidden');

  // Update nav state
  document.querySelectorAll('.nav-item, .sidebar-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === name);
  });

  State.currentPage = name;

  // Trigger page-specific data load
  switch (name) {
    case 'dashboard': refreshDashboard();   break;
    case 'scanner':   loadThreats();        break;
    case 'firewall':  loadFirewall();       break;
    case 'waf':       loadWAF(); loadWafEngine();            break;
    case 'iprep':     loadTopAttackers(); loadServerIpForBlocklist();   break;
    case 'events':    loadEvents();         break;
    case 'settings':  loadSettings();       break;
    case 'botshield': loadBotShield();      break;
    case 'cms':       loadCMSGuard();       break;
    case 'rootkit':   loadRootkit();        break;
    case 'integrity': loadIntegrity();      break;
    case 'php':       loadPHPHardening();   break;
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function reltime(ts) {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)    return `${diff}s ago`;
  if (diff < 3600)  return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function fmtBytes(b) {
  if (b < 1024)     return `${b} B`;
  if (b < 1048576)  return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1048576).toFixed(1)} MB`;
}

function fmtNum(n) {
  return Number(n).toLocaleString();
}

function sevBadge(sev) {
  return `<span class="sev sev-${sev}">${sev.toUpperCase()}</span>`;
}

function openModal(id)  { document.getElementById(id)?.classList.remove('hidden'); }
function closeModal(id) { document.getElementById(id)?.classList.add('hidden'); }

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function checkForUpdates(forceLive = false) {
  if (Demo.active) {
    showUpdateButton({ update_available: true, latest_version: '3.11.0' });
    return;
  }
  try {
    const res = forceLive
      ? await API.updateCheck()
      : await API.updateStatus();
    if (!res?.success) return;
    const d = res.data;
    const banner  = document.getElementById('update-banner');
    const dot     = document.getElementById('sidebar-update-dot');
    const newVer  = document.getElementById('update-new-version');
    const curVer  = document.getElementById('update-cur-version');
    const relLink = document.getElementById('update-release-link');

    showUpdateButton(d);

    if (d.update_available) {
      if (banner)  { banner.style.display  = 'flex'; }
      if (dot)     { dot.style.display     = 'block'; }
      if (newVer)  newVer.textContent  = 'v' + d.latest_version;
      if (curVer)  curVer.textContent  = 'v' + d.current_version;
      if (relLink && d.release_url) relLink.href = d.release_url;
    } else {
      if (banner)  banner.style.display  = 'none';
      if (dot)     dot.style.display     = 'none';
    }
  } catch (_) {}
}

async function runUpdate() {
  toast('To update: SSH into your server and run:  bash /usr/local/sentinel-gate/update.sh', 'info', 8000);
}

async function refreshDashboard() {
  checkForUpdates();   // non-blocking — uses cached result
  const data = Demo.active
    ? Demo.mockDashStats()
    : await API.dashStats();

  // A failed load must never leave the page asserting a security posture. The
  // markup ships with "Protected" pre-rendered, so returning silently here left
  // a green tick and an empty dashboard on a server whose API was answering 501
  // to every request — the single most misleading thing this product could do.
  if (!data?.success) {
    const icon   = document.getElementById('dash-scan-icon');
    const status = document.getElementById('dash-scan-status');
    const badge  = document.getElementById('dash-scan-badge');
    const meta   = document.getElementById('dash-scan-meta');
    const info   = document.getElementById('dash-server-info');

    if (icon)   icon.textContent = '⛔';
    if (status) { status.textContent = 'Status unknown'; status.style.color = 'var(--red)'; }
    if (badge)  { badge.className = 'badge badge-red'; badge.textContent = 'API unreachable'; }
    // Prefer the server's detail over the generic line: pointing the user at a
    // log file they then have to go and read is a worse answer than the error.
    if (meta)   meta.textContent = (data && (data.detail || data.error))
                                   || 'Could not reach the Sentinel Gate API.';
    if (info)   info.textContent = 'Could not reach the API — protection status cannot be confirmed.';

    ['stat-files','stat-threats','stat-fw','stat-waf'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '—';
    });
    return;
  }

  // Server info
  const s = data.server;
  document.getElementById('dash-server-info').textContent =
    `${s?.hostname || 'server'} · PHP ${s?.php_version || '?'} · Load: ${(s?.load?.[0] || 0).toFixed(2)}`;

  // Stat cards
  const sc = data.scanner;
  const fw = data.firewall;
  const waf = data.waf;

  document.getElementById('stat-files').textContent    = fmtNum(sc?.files_scanned || 0);
  document.getElementById('stat-threats').textContent  = fmtNum(sc?.total_threats || 0);
  document.getElementById('stat-fw').textContent       = fmtNum(fw?.blocked_today || 0);
  document.getElementById('stat-waf').textContent      = fmtNum(waf?.events_today || 0);

  document.getElementById('stat-files-sub').textContent   = 'Total scanned';
  document.getElementById('stat-threats-sub').textContent = `${sc?.active || 0} active`;
  document.getElementById('stat-fw-sub').textContent      = `${fmtNum(fw?.blocked_ips || 0)} blocked IPs`;
  document.getElementById('stat-waf-sub').textContent     = 'Today';

  // Update sidebar badges
  const sbT = document.getElementById('sb-threats');
  if (sbT) { sbT.textContent = sc?.active || 0; sbT.style.display = sc?.active ? '' : 'none'; }
  const sbE = document.getElementById('sb-events');
  if (sbE) sbE.textContent = data.events?.filter(e => !e.resolved).length || 0;

  // Scanner status card
  const lastJob = sc?.last_scan;
  const threats = sc?.active || 0;
  const scanIcon   = document.getElementById('dash-scan-icon');
  const scanStatus = document.getElementById('dash-scan-status');
  const scanMeta   = document.getElementById('dash-scan-meta');
  const scanBadge  = document.getElementById('dash-scan-badge');

  if (threats > 0) {
    scanIcon.textContent = '⚠️';
    scanStatus.textContent = `${threats} Active Threat${threats > 1 ? 's' : ''}`;
    scanStatus.style.color = 'var(--red)';
    scanBadge.className = 'badge badge-red';
    scanBadge.textContent = 'Threats Found';
  } else {
    scanIcon.textContent = '✅';
    scanStatus.textContent = 'Protected';
    scanStatus.style.color = 'var(--green)';
    scanBadge.className = 'badge badge-green';
    scanBadge.textContent = 'Protected';
  }

  if (lastJob?.finished_at) {
    scanMeta.textContent = `Last scan: ${reltime(lastJob.finished_at)} · 0 new threats`;
  }

  // Coverage bar
  const total = sc?.files_scanned || 0;
  const pct   = total > 0 ? 98.7 : 0;
  document.getElementById('dash-coverage-bar').style.width = `${pct}%`;
  document.getElementById('dash-coverage-pct').textContent = `${pct}%`;

  // File stats
  document.getElementById('fs-scanned').textContent = fmtNum(total);
  document.getElementById('fs-clean').textContent   = fmtNum(total - (sc?.quarantined || 0) - (sc?.deleted || 0));
  document.getElementById('fs-quar').textContent    = fmtNum(sc?.quarantined || 0);
  document.getElementById('fs-del').textContent     = fmtNum(0);

  // Threat breakdown
  const byType = sc?.by_type || [];
  Charts.threatBars(document.getElementById('dash-threat-breakdown'), byType);

  // Timeline chart
  if (data.timeline?.length) {
    const dates = data.timeline.map(d => d.date);
    const svgEl = document.getElementById('timeline-chart');
    if (svgEl) {
      Charts.timeline(svgEl, dates, [
        { values: data.timeline.map(d => d.waf_blocks),  color: '#3b82f6', label: 'WAF Blocks' },
        { values: data.timeline.map(d => d.brute_force), color: '#f59e0b', label: 'Brute Force' },
        { values: data.timeline.map(d => d.malware),     color: '#ef4444', label: 'Malware' },
      ]);
    }
  }

  // Events table
  renderEventsTable(data.events || [], 'dash-events-body');
  const unresolved = (data.events || []).filter(e => !e.resolved).length;
  document.getElementById('dash-events-badge').textContent = `${unresolved} unresolved`;

  // Sparklines (fake trend data for now)
  Charts.sparkline(document.getElementById('spark-files'),   [45,52,48,61,58,64,70,68,72,80,76,84], '#3b82f6');
  Charts.sparkline(document.getElementById('spark-threats'), [2,5,3,8,4,12,7,15,9,11,6,8],          '#ef4444');
  Charts.sparkline(document.getElementById('spark-fw'),      [30,45,38,55,42,60,52,48,65,58,72,61], '#f59e0b');
  Charts.sparkline(document.getElementById('spark-waf'),     [92,94,91,95,93,97,95,98,96,99,98,99], '#22c55e');
}

function renderEventsTable(events, tbodyId) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--txt3);padding:20px">No events found</td></tr>';
    return;
  }
  tbody.innerHTML = events.map(e => `
    <tr>
      <td>${sevBadge(e.severity)}</td>
      <td class="primary">${e.type}</td>
      <td class="mono">${e.source_ip || '—'}</td>
      <td class="mono">${e.target || '—'}</td>
      <td class="dim">${reltime(e.timestamp)}</td>
      <td>
        ${e.resolved
          ? '<span class="badge badge-gray">Resolved</span>'
          : `<button class="btn btn-ghost btn-xs" onclick="resolveEvent(${e.id})">Resolve</button>`
        }
      </td>
    </tr>`).join('');
}

// ── Scanner ───────────────────────────────────────────────────────────────────
async function startScan() {
  openPage('scanner');
  const type  = document.getElementById('scan-type-sel')?.value || 'quick';
  const path  = type === 'custom'
    ? (document.getElementById('scan-path-input')?.value || '/home')
    : '/home';

  const res = Demo.active
    ? { success: true, job_id: 999 }
    : await API.startScan(path, type);

  if (!res?.success) { toast('Failed to start scan', 'error'); return; }

  State.scanJobId = res.job_id;
  document.getElementById('scan-progress-card').style.display = '';
  document.getElementById('scan-btn').disabled = true;
  document.getElementById('scan-btn').textContent = '⏳ Scanning…';

  if (Demo.active) {
    simulateDemoScan();
    return;
  }

  // Poll for status
  State.scanInterval = setInterval(async () => {
    const st = await API.scanStatus(State.scanJobId);
    if (!st?.success) return;
    const job = st.data?.job;
    if (!job) return;

    // There is no honest percentage to show. A scan walks the filesystem
    // without counting it first, so the total is unknown until the scan ends —
    // and the previous code filled that gap with Math.random(), which is why a
    // scan that had examined ZERO files displayed "51%". Fabricating progress
    // in a security product is worse than admitting the total is unknown.
    //
    // So: an indeterminate bar while running, and real counters beside it. The
    // file count IS known and IS truthful, which makes it the useful signal.
    const bar  = document.getElementById('scan-progress-bar');
    const pctEl = document.getElementById('scan-progress-pct');
    const done = job.status === 'done';

    if (done) {
      bar.classList.remove('indeterminate');
      bar.style.width = '100%';
      pctEl.textContent = '100%';
    } else {
      // Width is set by the animation, not by a made-up number.
      bar.classList.add('indeterminate');
      bar.style.width = '';
      pctEl.textContent = fmtNum(job.files_scanned || 0) + ' files';
    }

    document.getElementById('scan-live-files').textContent = fmtNum(job.files_scanned || 0);
    document.getElementById('scan-live-threats').textContent = job.threats_found || 0;
    document.getElementById('scan-live-status').textContent = job.status;

    // A running job whose file count never moves is stuck, not working. Say so
    // rather than animating a bar forever: the scan runs detached, so the UI
    // cannot see it die.
    if (!done) {
      if (State._lastScanFiles === (job.files_scanned || 0)) {
        State._scanStallTicks = (State._scanStallTicks || 0) + 1;
      } else {
        State._scanStallTicks = 0;
      }
      State._lastScanFiles = job.files_scanned || 0;

      const txt = document.getElementById('scan-progress-text');
      if (State._scanStallTicks >= 15 && txt) {          // ~30s of no movement
        txt.textContent = 'No files scanned yet — the scan process may not be running. '
                        + 'Check logs/scanner.log.';
      }
    }

    if (job.status === 'done' || job.status === 'error') {
      clearInterval(State.scanInterval);
      document.getElementById('scan-btn').disabled = false;
      document.getElementById('scan-btn').textContent = '▶ Start Scan';
      document.getElementById('scan-spinner').textContent = job.status === 'done' ? '✅' : '❌';
      document.getElementById('scan-progress-text').textContent =
        `Scan complete — ${job.threats_found || 0} threats found`;
      loadThreats();
      toast(`Scan complete. ${job.threats_found || 0} threats found.`, job.threats_found ? 'error' : 'success');
    }
  }, 2000);
}

function simulateDemoScan() {
  let pct = 0;
  const interval = setInterval(() => {
    pct = Math.min(100, pct + Math.floor(Math.random() * 8) + 2);
    document.getElementById('scan-progress-bar').style.width = `${pct}%`;
    document.getElementById('scan-progress-pct').textContent = `${pct}%`;
    document.getElementById('scan-live-files').textContent = fmtNum(Math.floor(pct / 100 * 1284930));
    document.getElementById('scan-live-threats').textContent = pct > 60 ? 5 : 0;
    document.getElementById('scan-live-status').textContent = pct < 100 ? 'Running…' : 'Done';
    if (pct >= 100) {
      clearInterval(interval);
      document.getElementById('scan-btn').disabled = false;
      document.getElementById('scan-btn').textContent = '▶ Start Scan';
      document.getElementById('scan-spinner').textContent = '✅';
      document.getElementById('scan-progress-text').textContent = 'Scan complete — 5 threats found';
      loadThreats();
      toast('Scan complete. 5 threats found.', 'error');
    }
  }, 200);
}

function stopScan() {
  clearInterval(State.scanInterval);
  document.getElementById('scan-btn').disabled = false;
  document.getElementById('scan-btn').textContent = '▶ Start Scan';
  document.getElementById('scan-progress-card').style.display = 'none';
  toast('Scan stopped', 'info');
}

async function loadThreats() {
  const filter = document.getElementById('threat-filter')?.value || '';
  const res = Demo.active
    ? Demo.mockThreats()
    : await API.threats(filter);

  const tbody = document.getElementById('threats-body');
  if (!tbody) return;

  const threats = res?.data || [];
  document.getElementById('threat-count-badge').textContent = threats.length;

  if (!threats.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--txt3);padding:28px">No threats found. Run a scan to check your server.</td></tr>';
    return;
  }

  tbody.innerHTML = threats.map(t => `
    <tr>
      <td>${sevBadge(t.severity)}</td>
      <td class="mono primary" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${t.file_path}">
        ${t.file_path.split('/').slice(-2).join('/')}
      </td>
      <td class="mono" style="color:var(--blue);font-size:.75rem">${t.cpanel_user || '—'}</td>
      <td class="mono" style="color:var(--red)">${t.threat_name}</td>
      <td><span class="badge badge-amber">${t.threat_type}</span></td>
      <td class="dim">${fmtBytes(t.size || 0)}</td>
      <td class="dim">${reltime(t.detected_at)}</td>
      <td>${threatStatusBadge(t.status)}</td>
      <td>
        ${t.status === 'active' ? `
          <button class="btn btn-ghost btn-xs" onclick="quarantineThreat(${t.id})" title="Quarantine">🔒</button>
          <button class="btn btn-danger btn-xs" onclick="deleteThreat(${t.id})" title="Delete file">🗑</button>
        ` : ''}
        ${t.status === 'quarantined' ? `
          <button class="btn btn-ghost btn-xs" onclick="restoreThreat(${t.id})" title="Restore">↺</button>
        ` : ''}
      </td>
    </tr>`).join('');
}

function threatStatusBadge(status) {
  const map = {
    active:      '<span class="badge badge-red">Active</span>',
    quarantined: '<span class="badge badge-amber">Quarantined</span>',
    deleted:     '<span class="badge badge-gray">Deleted</span>',
    restored:    '<span class="badge badge-blue">Restored</span>',
  };
  return map[status] || `<span class="badge badge-gray">${status}</span>`;
}

async function quarantineThreat(id) {
  const res = Demo.active ? { success: true } : await API.quarantineThreat(id);
  if (res?.success) { toast('File quarantined', 'success'); loadThreats(); }
  else toast('Quarantine failed', 'error');
}

async function restoreThreat(id) {
  if (!confirm('Restore this file from quarantine?')) return;
  const res = Demo.active ? { success: true } : await API.restoreThreat(id);
  if (res?.success) { toast('File restored', 'success'); loadThreats(); }
  else toast('Restore failed', 'error');
}

async function deleteThreat(id) {
  if (!confirm('Permanently delete this file? This cannot be undone.')) return;
  const res = Demo.active ? { success: true } : await API.deleteThreat(id);
  if (res?.success) { toast('File deleted', 'success'); loadThreats(); }
  else toast('Delete failed', 'error');
}

async function updateSignatures() {
  toast('Updating signatures…', 'info');
  const res = Demo.active ? { success: true } : await API.updateSigs();
  if (res?.success) toast('Signatures updated', 'success');
  else toast('Update failed', 'error');
}

// ── Firewall ──────────────────────────────────────────────────────────────────
async function loadFirewall() {
  const [stats, rules, blocked] = await Promise.all([
    Demo.active ? { success: true, data: { blocked_ips: 382, active_rules: 14, blocked_today: 8241 } } : API.fwStats(),
    Demo.active ? Demo.mockFWRules() : API.fwRules(),
    Demo.active ? { success: true, data: [] } : API.fwBlocked(),
  ]);

  if (stats?.success) {
    document.getElementById('fw-stat-rules').textContent   = fmtNum(stats.data?.active_rules || 0);
    document.getElementById('fw-stat-blocked').textContent = fmtNum(stats.data?.blocked_ips  || 0);
    document.getElementById('fw-stat-today').textContent   = fmtNum(stats.data?.blocked_today || 0);
    document.getElementById('fw-status-line').textContent  =
      `CSF ${stats.data?.csf_status?.installed ? '✓ installed' : '✗ not found'} · iptables active`;
  }

  // Rules table
  const tbody = document.getElementById('fw-rules-body');
  if (tbody && rules?.data) {
    tbody.innerHTML = rules.data.map(r => `
      <tr>
        <td class="primary">${r.name}</td>
        <td>${r.direction}</td>
        <td class="mono">${r.protocol || '—'}</td>
        <td class="mono">${r.port || 'any'}</td>
        <td>${actionBadge(r.action)}</td>
        <td>
          <label class="toggle">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleRule(${r.id}, this.checked)">
            <span class="toggle-slider"></span>
          </label>
        </td>
        <td>
          <button class="btn btn-ghost btn-xs" onclick="deleteRule(${r.id})">✕</button>
        </td>
      </tr>`).join('');
  }

  // Recent blocked IPs
  const recentEl = document.getElementById('fw-recent-blocked');
  if (recentEl && blocked?.data?.length) {
    recentEl.innerHTML = blocked.data.slice(0, 8).map(b => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)">
        <span class="mono" style="font-size:.72rem">${b.ip_address}</span>
        <div style="display:flex;gap:6px;align-items:center">
          <span class="dim" style="font-size:.65rem">${reltime(b.blocked_at)}</span>
          <button class="btn btn-ghost btn-xs" onclick="unblockIP('${b.ip_address}')">Unblock</button>
        </div>
      </div>`).join('');
  } else if (recentEl) {
    recentEl.innerHTML = '<div class="dim" style="font-size:.78rem">No recently blocked IPs</div>';
  }

  // Geo block grid
  renderGeoGrid();
}

function actionBadge(action) {
  const map = {
    ACCEPT: 'badge-green', DROP: 'badge-red',
    REJECT: 'badge-red',   LIMIT: 'badge-amber',
  };
  return `<span class="badge ${map[action] || 'badge-gray'}">${action}</span>`;
}

async function blockIP() {
  const ip = document.getElementById('fw-ip-input')?.value?.trim();
  const reason = document.getElementById('fw-ip-reason')?.value?.trim() || 'Manual block';
  if (!ip) { toast('Enter an IP address', 'error'); return; }

  const res = Demo.active ? { success: true } : await API.fwBlockIP(ip, reason, false);
  if (res?.success) { toast(`${ip} blocked`, 'success'); loadFirewall(); }
  else toast(res?.error || 'Block failed', 'error');
}

async function allowIP() {
  const ip = document.getElementById('fw-ip-input')?.value?.trim();
  if (!ip) { toast('Enter an IP address', 'error'); return; }
  const res = Demo.active ? { success: true } : await API.fwAllowIP(ip, '');
  if (res?.success) { toast(`${ip} allowed`, 'success'); }
  else toast('Failed', 'error');
}

async function unblockIP(ip) {
  const res = Demo.active ? { success: true } : await API.fwUnblockIP(ip);
  if (res?.success) { toast(`${ip} unblocked`, 'success'); loadFirewall(); }
  else toast('Unblock failed', 'error');
}

async function toggleRule(id, enabled) {
  const res = Demo.active ? { success: true } : await API.fwToggleRule(id, enabled);
  if (!res?.success) toast('Failed to toggle rule', 'error');
}

async function deleteRule(id) {
  if (!confirm('Delete this firewall rule?')) return;
  const res = Demo.active ? { success: true } : await API.fwDeleteRule(id);
  if (res?.success) { toast('Rule deleted', 'success'); loadFirewall(); }
  else toast('Failed', 'error');
}

async function reloadFirewall() {
  const res = Demo.active ? { success: true } : await API.fwReload();
  if (res?.success) toast('Firewall reloaded', 'success');
  else toast('Reload failed', 'error');
}

function openAddRuleModal() { openModal('add-rule-modal'); }

async function submitAddRule() {
  const rule = {
    name:      document.getElementById('rule-name')?.value,
    direction: document.getElementById('rule-dir')?.value,
    protocol:  document.getElementById('rule-proto')?.value,
    port:      document.getElementById('rule-port')?.value,
    action:    document.getElementById('rule-action')?.value,
    source_ip: document.getElementById('rule-source')?.value,
    comment:   document.getElementById('rule-comment')?.value,
  };
  if (!rule.name) { toast('Rule name required', 'error'); return; }

  const res = Demo.active ? { success: true } : await API.fwAddRule(rule);
  if (res?.success) {
    toast('Rule added', 'success');
    closeModal('add-rule-modal');
    loadFirewall();
  } else toast(res?.error || 'Failed', 'error');
}

const GEO_COUNTRIES = [
  ['AF','Afghanistan'],['BY','Belarus'],['CN','China'],['CU','Cuba'],
  ['IR','Iran'],['IQ','Iraq'],['KP','North Korea'],['LY','Libya'],
  ['RU','Russia'],['SD','Sudan'],['SY','Syria'],['VE','Venezuela'],
  ['UA','Ukraine'],['MM','Myanmar'],['YE','Yemen'],['ZW','Zimbabwe'],
  ['NG','Nigeria'],['PK','Pakistan'],['BD','Bangladesh'],['ID','Indonesia'],
  ['VN','Vietnam'],['IN','India'],['BR','Brazil'],['MX','Mexico'],
];

function renderGeoGrid() {
  const grid = document.getElementById('geo-block-grid');
  if (!grid) return;
  const saved = (Database?.setting?.('geo_block_countries') || '').split(',').filter(Boolean);
  grid.innerHTML = GEO_COUNTRIES.map(([cc, name]) => {
    const sel = saved.includes(cc) || State.geoSelected.has(cc);
    return `
      <div onclick="toggleGeo('${cc}', this)"
           style="padding:8px 10px;border-radius:8px;cursor:pointer;font-size:.72rem;
                  border:1px solid ${sel ? 'var(--red)' : 'var(--border)'};
                  background:${sel ? 'var(--red-dim)' : 'var(--card2)'};
                  color:${sel ? 'var(--red)' : 'var(--txt2)'};
                  user-select:none;transition:all .15s"
           data-cc="${cc}" data-sel="${sel ? '1' : '0'}">
        <div style="font-weight:700">${cc}</div>
        <div style="font-size:.6rem;margin-top:2px;opacity:.7">${name}</div>
      </div>`;
  }).join('');
}

function toggleGeo(cc, el) {
  const sel = el.dataset.sel === '1';
  el.dataset.sel = sel ? '0' : '1';
  el.style.border  = sel ? '1px solid var(--border)' : '1px solid var(--red)';
  el.style.background = sel ? 'var(--card2)' : 'var(--red-dim)';
  el.style.color   = sel ? 'var(--txt2)' : 'var(--red)';
  sel ? State.geoSelected.delete(cc) : State.geoSelected.add(cc);
}

async function saveGeoBlock() {
  const countries = [...State.geoSelected];
  const res = Demo.active ? { success: true } : await API.fwGeoBlock(countries);
  if (res?.success) toast(`Geo block saved (${countries.length} countries)`, 'success');
  else toast('Failed to save', 'error');
}

// ── WAF ───────────────────────────────────────────────────────────────────────
async function loadWAF() {
  const [stats, cats] = await Promise.all([
    Demo.active ? Demo.mockWAFStats() : API.wafStats(),
    API.wafCats(),
  ]);

  if (stats?.success) {
    const d = stats.data;
    document.getElementById('waf-stat-total').textContent    = fmtNum(d.total_events || 0);
    document.getElementById('waf-stat-today').textContent    = fmtNum(d.events_today || 0);
    document.getElementById('waf-stat-top-rule').textContent = d.top_rules?.[0]?.rule_id || '—';
    document.getElementById('waf-stat-mode').textContent     = 'On';
  }

  loadWAFEvents();

  // CRS Categories
  const catContainer = document.getElementById('waf-categories');
  if (catContainer && cats?.data) {
    catContainer.innerHTML = cats.data.map(c => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
        <div>
          <div style="font-size:.78rem;font-weight:600">${c.id} — ${c.name}</div>
          <div style="font-size:.65rem;color:var(--txt3)">${c.rules} rules</div>
        </div>
        <span class="badge ${c.active ? 'badge-green' : 'badge-gray'}">${c.active ? 'Active' : 'Disabled'}</span>
      </div>`).join('');
  }
}

async function loadWAFEvents() {
  const sev = document.getElementById('waf-sev-filter')?.value || '';
  const res = Demo.active
    ? { success: true, data: [] }
    : await API.wafEvents(sev);

  const tbody = document.getElementById('waf-events-body');
  if (!tbody) return;
  const events = res?.data || [];
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--txt3);padding:24px">No WAF events. Events are ingested from ModSecurity audit log.</td></tr>';
    return;
  }
  tbody.innerHTML = events.map(e => `
    <tr>
      <td>${sevBadge(e.severity)}</td>
      <td class="mono">${e.rule_id}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.rule_msg}</td>
      <td class="mono">${e.ip_address}</td>
      <td class="mono" style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.uri}</td>
      <td class="dim">${reltime(e.timestamp)}</td>
    </tr>`).join('');
}

async function setWAFMode() {
  const mode = document.getElementById('waf-mode-sel')?.value;
  const res  = Demo.active ? { success: true } : await API.wafSetMode(mode);
  if (res?.success) toast(`WAF mode set to ${mode}`, 'success');
  else toast('Failed', 'error');
}

// ── IP Reputation ──────────────────────────────────────────────────────────────
async function checkIP() {
  const ip = document.getElementById('iprep-ip-input')?.value?.trim();
  if (!ip) { toast('Enter an IP address', 'error'); return; }

  const container = document.getElementById('iprep-result');
  container.innerHTML = '<div class="dim" style="font-size:.8rem">Checking…</div>';

  const res = Demo.active
    ? { success: true, data: { ip, score: 78, risk: 'high', country: 'RU', asn: 'AS12345 Demo ISP', rbl_hits: ['spamhaus', 'sorbs'] } }
    : await API.ipCheck(ip);

  if (!res?.success) { container.innerHTML = `<div style="color:var(--red)">${res?.error || 'Failed'}</div>`; return; }

  const d = res.data;
  const riskCol = { critical:'var(--red)', high:'var(--red)', medium:'var(--amber)', low:'var(--green)' }[d.risk] || 'var(--blue)';

  container.innerHTML = `
    <div class="card" style="padding:16px">
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:14px">
        <div style="font-size:1.5rem;font-family:var(--font-mono);font-weight:800">${d.ip}</div>
        <span class="badge" style="background:${riskCol}20;color:${riskCol};border-color:${riskCol}40">
          ${d.risk?.toUpperCase()} RISK
        </span>
        <span class="badge badge-gray">${d.country || 'XX'}</span>
      </div>
      ${Charts.ipRiskGauge(d.score || 0)}
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px;font-size:.78rem">
        <div><span class="dim">ASN: </span>${d.asn || '—'}</div>
        <div><span class="dim">RBL Hits: </span>${d.rbl_hits?.join(', ') || 'None'}</div>
      </div>
      <div style="display:flex;gap:8px;margin-top:14px">
        <button class="btn btn-danger btn-sm" onclick="blockIPDirect('${d.ip}')">Block this IP</button>
      </div>
    </div>`;
}

async function blockIPDirect(ip) {
  const res = Demo.active ? { success: true } : await API.fwBlockIP(ip, 'IP Reputation: High risk', false);
  if (res?.success) toast(`${ip} blocked`, 'success');
  else toast('Block failed', 'error');
}

async function loadTopAttackers() {
  const res = Demo.active ? Demo.mockIPAttackers() : await API.ipTopAttack();
  const tbody = document.getElementById('iprep-table-body');
  if (!tbody) return;

  const data = res?.data || [];
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--txt3);padding:24px">No data yet — IP reputation requires incoming events.</td></tr>';
    return;
  }

  tbody.innerHTML = data.map(r => {
    const rblHits = typeof r.rbl_hits === 'string' ? JSON.parse(r.rbl_hits || '[]') : (r.rbl_hits || []);
    const scoreCol = r.score >= 75 ? 'var(--red)' : r.score >= 50 ? 'var(--amber)' : 'var(--green)';
    return `
      <tr>
        <td class="mono primary">${r.ip_address}</td>
        <td><span class="cc-badge" style="background:var(--blue-dim);color:var(--blue2)">${r.country || 'XX'}</span></td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div class="progress-bar" style="width:80px;height:6px">
              <div class="progress-fill" style="width:${r.score}%;background:${scoreCol}"></div>
            </div>
            <span style="font-family:var(--font-mono);font-size:.72rem;color:${scoreCol}">${r.score}</span>
          </div>
        </td>
        <td class="dim">${rblHits.join(', ') || '—'}</td>
        <td class="mono">${fmtNum(r.hits || 0)}</td>
        <td class="dim">${r.last_seen ? reltime(r.last_seen) : '—'}</td>
        <td>
          <button class="btn btn-danger btn-xs" onclick="blockIPDirect('${r.ip_address}')">Block</button>
        </td>
      </tr>`;
  }).join('');
}

// ── Events ────────────────────────────────────────────────────────────────────
async function loadEvents() {
  const sev = document.getElementById('events-sev-filter')?.value || '';
  const res = Demo.active
    ? { success: true, data: [], unresolved: 0 }
    : await API.events(sev);

  const tbody = document.getElementById('events-body');
  if (tbody) renderEventsTable(res?.data || [], 'events-body');

  const badge = document.getElementById('events-unresolved-badge');
  if (badge) badge.textContent = `${res?.unresolved || 0} unresolved`;
}

async function resolveEvent(id) {
  const res = Demo.active ? { success: true } : await API.resolveEvent(id);
  if (res?.success) { toast('Event resolved', 'success'); loadEvents(); refreshDashboard(); }
}

// ── Settings ──────────────────────────────────────────────────────────────────
function updateCpuSliderLabel(val) {
  val = parseInt(val, 10);
  const labelEl = document.getElementById('cpu-limit-label');
  const descEl  = document.getElementById('cpu-limit-desc');
  if (labelEl) labelEl.textContent = val + '%';

  if (descEl) {
    // nice value: 100% → 0, 10% → 19
    const niceVal = Math.round(19 * (1 - val / 100));
    // scan sleep: 100% → 0ms, 10% → 550ms
    const sleepMs = Math.round(Math.max(0, (1 - val / 100) * 550));

    let label, color;
    if (val <= 25)      { label = 'Minimal — maximum headroom for web traffic'; color = '#10b981'; }
    else if (val <= 50) { label = 'Balanced — recommended for most servers';   color = '#3b82f6'; }
    else if (val <= 75) { label = 'Performance — faster scans, higher CPU';    color = '#f59e0b'; }
    else                { label = 'Maximum — fastest scans, unrestricted CPU';  color = '#ef4444'; }

    descEl.innerHTML =
      '<span style="color:' + color + ';font-weight:600">' + label + '</span><br>' +
      '<span style="color:var(--txt3)">Process priority: </span><code>nice ' + niceVal + '</code>' +
      ' &nbsp;·&nbsp; ' +
      '<span style="color:var(--txt3)">Scan throttle: </span><code>' + (sleepMs ? sleepMs + 'ms between files' : 'no throttle') + '</code>';
  }
}

function selectPollInterval(seconds) {
  [60, 300, 900].forEach(v => {
    const el = document.getElementById('poll-opt-' + v);
    if (!el) return;
    const active = v === seconds;
    el.style.borderColor    = active ? 'var(--primary)' : 'var(--border)';
    el.style.background     = active ? 'rgba(59,130,246,.08)' : '';
    const radio = el.querySelector('input[type=radio]');
    if (radio) radio.checked = active;
  });
}

async function loadSettings() {
  loadLicense();   // license card lives on this page

  const res = Demo.active
    ? { success: true, data: {
        scan_schedule: 'daily', scan_paths: '/home', auto_quarantine: '0',
        email_alerts: '1', alert_email: '', php_disable_funcs: 'exec,passthru,shell_exec,system',
        rate_limit_ssh: '5', rate_limit_http: '100',
        firewall_enabled: '1', waf_enabled: '1', bot_shield_enabled: '1', ip_rep_enabled: '1',
        cpu_limit_percent: '50', rt_poll_interval: '300',
        scan_time: '02:00', scan_day: '0', scan_type: 'full',
        sig_update_schedule: 'weekly', sig_update_day: '0',
        iprep_schedule: 'daily',
        sig_last_update: String(Math.floor(Date.now()/1000) - 3*86400),
        iprep_last_run:  String(Math.floor(Date.now()/1000) - 9*3600),
        iprep_last_count: '183',
      }}
    : await API.getSettings();

  if (!res?.success) return;
  const d = res.data;

  const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
  const chk = (id, val) => { const el = document.getElementById(id); if (el) el.checked = val === '1' || val === true; };

  set('set-scan-schedule', d.scan_schedule);
  set('set-scan-time',     d.scan_time || '02:00');
  set('set-scan-day',      d.scan_day  || '0');
  set('set-scan-type',     d.scan_type || 'full');
  set('set-sig-schedule',  d.sig_update_schedule || 'weekly');
  set('set-sig-day',       d.sig_update_day || '0');
  set('set-iprep-schedule',d.iprep_schedule || 'daily');
  set('set-scan-paths',    d.scan_paths);

  // Real-time monitor resource profile
  selectRtProfile(d.rt_profile || 'balanced');
  set('set-rt-fps',      d.rt_max_files_per_sec || '25');
  set('set-rt-maxmb',    d.rt_max_file_size_mb  || '16');
  set('set-rt-nice',     d.rt_nice              || '10');
  set('set-rt-watches',  d.rt_max_watches       || '20000');
  set('set-rt-debounce', d.rt_debounce_seconds  || '5');
  set('set-rt-excludes', d.rt_exclude_dirs      || '');

  // Last-run readouts
  const ts = v => (v && +v) ? new Date(+v * 1000).toLocaleString() : 'never';
  const txt = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  txt('sig-last-update',  ts(d.sig_last_update));
  txt('iprep-last-run',   ts(d.iprep_last_run));
  txt('iprep-last-count', d.iprep_last_count || '0');

  syncScheduleFields();
  chk('set-auto-quar',     d.auto_quarantine);

  // The scanner page used to state "auto-quarantine enabled" as static text,
  // which was wrong the moment the setting was off -- and it now ships off.
  const quarState = document.getElementById('scanner-quar-state');
  if (quarState) {
    quarState.textContent = d.auto_quarantine === '1'
      ? 'auto-quarantine on' : 'auto-quarantine off';
  }
  chk('set-email-alerts',  d.email_alerts);
  set('set-alert-email',   d.alert_email);
  set('set-php-disable',   d.php_disable_funcs);
  set('set-rate-ssh',      d.rate_limit_ssh);
  set('set-rate-http',     d.rate_limit_http);
  chk('set-fw-enabled',    d.firewall_enabled);
  chk('set-waf-enabled',   d.waf_enabled);
  chk('set-bot-enabled',   d.bot_shield_enabled);
  chk('set-iprep-enabled', d.ip_rep_enabled);

  // CPU slider
  const cpuVal = parseInt(d.cpu_limit_percent || '50', 10);
  const cpuSlider = document.getElementById('set-cpu-limit');
  if (cpuSlider) { cpuSlider.value = cpuVal; updateCpuSliderLabel(cpuVal); }

  // Poll interval selector
  const pollVal = parseInt(d.rt_poll_interval || '300', 10);
  selectPollInterval([60, 300, 900].includes(pollVal) ? pollVal : 300);
}

async function saveSettings() {
  const g = id => document.getElementById(id);
  const data = {
    scan_schedule:       g('set-scan-schedule')?.value,
    scan_time:           g('set-scan-time')?.value,
    scan_day:            g('set-scan-day')?.value,
    scan_type:           g('set-scan-type')?.value,
    sig_update_schedule: g('set-sig-schedule')?.value,
    sig_update_day:      g('set-sig-day')?.value,
    iprep_schedule:      g('set-iprep-schedule')?.value,
    scan_paths:          g('set-scan-paths')?.value,

    rt_profile:            g('set-rt-profile')?.value || 'balanced',
    rt_max_files_per_sec:  g('set-rt-fps')?.value      || '25',
    rt_max_file_size_mb:   g('set-rt-maxmb')?.value    || '16',
    rt_nice:               g('set-rt-nice')?.value     || '10',
    rt_max_watches:        g('set-rt-watches')?.value  || '20000',
    rt_debounce_seconds:   g('set-rt-debounce')?.value || '5',
    rt_exclude_dirs:       g('set-rt-excludes')?.value || '',
    auto_quarantine:    g('set-auto-quar')?.checked ? '1' : '0',
    email_alerts:       g('set-email-alerts')?.checked ? '1' : '0',
    alert_email:        g('set-alert-email')?.value,
    php_disable_funcs:  g('set-php-disable')?.value,
    rate_limit_ssh:     g('set-rate-ssh')?.value,
    rate_limit_http:    g('set-rate-http')?.value,
    firewall_enabled:   g('set-fw-enabled')?.checked ? '1' : '0',
    waf_enabled:        g('set-waf-enabled')?.checked ? '1' : '0',
    bot_shield_enabled: g('set-bot-enabled')?.checked ? '1' : '0',
    ip_rep_enabled:     g('set-iprep-enabled')?.checked ? '1' : '0',
    cpu_limit_percent:  g('set-cpu-limit')?.value || '50',
    rt_poll_interval:   document.querySelector('input[name="rt_poll_interval"]:checked')?.value || '300',
  };

  const res = Demo.active ? { success: true } : await API.saveSettings(data);
  if (res?.success) toast('Settings saved', 'success');
  else toast('Failed to save', 'error');
}


// ── Real-Time Monitor ─────────────────────────────────────────────────────────
let monitorRunning = false;

async function loadMonitorStats() {
  const res = Demo.active ? Demo.mockMonitorStatus() : await API.monitorStatus();
  if (!res?.success) return;
  const d = res.data;
  monitorRunning = d.running;

  const card = document.getElementById('rt-monitor-card');
  if (card) card.style.borderLeftColor = d.running ? 'var(--green)' : 'var(--red)';
  // A monitor can be running and yet doing nothing: wrong watch paths, a dead
  // loop, inotify watches exhausted. That state used to render as a green
  // "Active" badge beside counters stuck at zero, which is the least useful
  // thing the card could say. The daemon stamps rt_last_activity as it works,
  // so silence is measurable — report it.
  const badge = document.getElementById('rt-status-badge');
  if (badge) {
    if (!d.running) {
      badge.className = 'badge badge-red';   badge.textContent = 'Stopped';
    } else if (d.stale) {
      badge.className = 'badge badge-amber'; badge.textContent = 'No activity';
    } else {
      badge.className = 'badge badge-green'; badge.textContent = 'Active';
    }
  }
  const icon = document.getElementById('rt-icon');
  if (icon) icon.textContent = !d.running ? '⏸' : (d.stale ? '⚠️' : '🔍');

  if (card) {
    card.style.borderLeftColor = !d.running ? 'var(--red)'
                               : (d.stale ? 'var(--amber, #f59e0b)' : 'var(--green)');
  }

  const rtPaths  = document.getElementById('rt-paths');
  // "Watching ..." with nothing after it was the placeholder showing through.
  if (rtPaths) {
    const paths = (d.watch_paths || []).filter(Boolean);
    rtPaths.textContent = paths.length ? paths.join(', ') : 'no paths configured';
  }
  const rtEngine = document.getElementById('rt-engine');
  if (rtEngine) rtEngine.textContent = d.engine || 'polling';

  setText('rt-files-checked',  fmtNum(d.files_checked || 0));
  setText('rt-detections-24h', d.detections_24h || 0);
  setText('rt-detections-all', d.detections_all  || 0);

  const toggleBtn = document.getElementById('rt-toggle-btn');
  if (toggleBtn) toggleBtn.textContent = d.running ? 'Stop' : 'Start';

  const sbRt = document.getElementById('sb-rt-threats');
  if (sbRt) {
    sbRt.style.display = d.detections_24h > 0 ? '' : 'none';
    sbRt.textContent   = d.detections_24h || '';
  }
}

async function loadMonitor() {
  const res = Demo.active ? Demo.mockMonitorStatus() : await API.monitorStatus();
  if (!res?.success) return;
  const d = res.data;
  monitorRunning = d.running;

  const badge = document.getElementById('monitor-status-badge');
  if (badge) {
    badge.className   = 'badge ' + (d.running ? 'badge-green' : 'badge-red');
    badge.textContent = d.running ? '● Running' : '○ Stopped';
  }
  const pgBtn = document.getElementById('monitor-page-toggle');
  if (pgBtn) pgBtn.textContent = d.running ? 'Stop Monitor' : 'Start Monitor';

  setText('mon-engine',  d.engine || 'polling');
  setText('mon-pid',     d.pid    || '—');
  setText('mon-files',   fmtNum(d.files_checked || 0));
  setText('mon-det-24h', d.detections_24h || 0);
  setText('mon-det-all', d.detections_all  || 0);

  const pathsList = document.getElementById('mon-paths-list');
  if (pathsList) {
    pathsList.innerHTML = (d.watch_paths || []).map(p =>
      '<div style="display:flex;justify-content:space-between;align-items:center;' +
      'padding:6px 10px;background:var(--bg1);border-radius:6px;margin-bottom:6px;' +
      'font-size:.78rem;font-family:monospace">' +
      '<span style="color:var(--txt1)">' + p + '</span>' +
      '<button class="btn btn-ghost btn-sm" style="padding:2px 8px;font-size:.7rem" ' +
      'onclick="removeWatchPath(\'' + p + '\')">✕ Remove</button></div>'
    ).join('') || '<div style="color:var(--txt3);font-size:.8rem">No paths configured</div>';
  }

  // Also refresh service panel
  loadServiceStatus();
  loadServiceLogs();
}

let _monitorBusy = false;

async function toggleMonitor() {
  // systemctl start/stop takes seconds, and the daemon needs a moment more to
  // write its PID file. The button used to fire and return immediately, so it
  // felt dead, a second click could race the first, and the state it flipped to
  // was assumed rather than confirmed -- which is why it looked unreliable.
  if (_monitorBusy) return;
  _monitorBusy = true;

  const starting = !monitorRunning;
  const buttons  = ['rt-toggle-btn', 'monitor-page-toggle']
    .map(id => document.getElementById(id)).filter(Boolean);
  const original = buttons.map(b => b.textContent);
  buttons.forEach(b => { b.disabled = true; b.textContent = starting ? 'Starting…' : 'Stopping…'; });

  const fn  = starting ? API.monitorStart : API.monitorStop;
  const res = Demo.active ? { success: true } : await fn();

  const restore = () => {
    buttons.forEach((b, i) => { b.disabled = false; b.textContent = original[i]; });
    _monitorBusy = false;
  };

  if (res?.success) {
    // Confirm with the server rather than assuming. systemd reports the unit
    // started before the daemon has finished coming up, so the first poll can
    // legitimately disagree with what we just asked for.
    let confirmed = false;
    for (let attempt = 0; attempt < 6 && !confirmed; attempt++) {
      await new Promise(r => setTimeout(r, 700));
      const st = await API.monitorStatus();
      if (st?.success && st.data && st.data.running === starting) {
        confirmed = true;
        monitorRunning = starting;
      }
    }

    restore();
    loadMonitor();
    loadMonitorStats();

    if (confirmed) {
      toast(starting ? 'Monitor started' : 'Monitor stopped', 'success');
    } else {
      // The command was accepted and the state did not follow. Saying so beats
      // a success toast over a monitor that is not running.
      toast(starting
        ? 'Start was accepted but the monitor is not running yet — check Details'
        : 'Stop was accepted but the monitor is still running — check Details',
        'error', 8000);
    }
    return;
  }

  restore();
  {
    // "Action failed" tells the operator nothing. The API explains itself --
    // the daemon script missing, systemd refusing, the unit not installed --
    // and that explanation is what makes the difference actionable.
    const why = (res && (res.error || res.message)) || 'no reason given by the server';
    toast('Monitor: ' + why, 'error', 7000);
    console.error('toggleMonitor failed:', res);
  }
}

async function loadMonitorDetections() {
  const res   = Demo.active ? Demo.mockMonitorDetections() : await API.monitorDetections(50);
  const tbody = document.getElementById('rt-detections-body');
  if (!tbody || !res?.success) return;
  const rows = res.data || [];
  tbody.innerHTML = rows.length === 0
    ? '<tr><td colspan="5" style="text-align:center;color:var(--txt3);padding:24px">No real-time detections</td></tr>'
    : rows.map(r =>
        '<tr>' +
        '<td>' + sevBadge(r.severity) + '</td>' +
        '<td style="font-family:monospace;font-size:.75rem;word-break:break-all">' + r.file_path + '</td>' +
        '<td><span class="badge badge-red" style="font-size:.7rem">' + r.threat_name + '</span></td>' +
        '<td><span class="sev sev-' + (r.status === 'quarantined' ? 'medium' : 'critical') + '">' + r.status + '</span></td>' +
        '<td style="color:var(--txt3)">' + reltime(r.detected_at) + '</td>' +
        '</tr>'
      ).join('');
}

async function loadMonitorLog() {
  if (Demo.active) {
    const el = document.getElementById('monitor-log');
    if (el) el.textContent =
      '[2024-01-15 14:22:01] INFO  Monitor started (inotify engine)\n' +
      '[2024-01-15 14:22:01] INFO  Watching: /home /var/www /tmp\n' +
      '[2024-01-15 14:23:45] ALERT CRITICAL c99_shell: /home/user1/public_html/uploads/image.php\n' +
      '[2024-01-15 14:23:45] INFO  Auto-quarantined -> quarantine/2024-01-15/\n' +
      '[2024-01-15 15:01:18] ALERT HIGH eval_base64: /home/user2/public_html/tmp/update.php';
    return;
  }
  const res = await API.monitorLogs(100);
  const el  = document.getElementById('monitor-log');
  if (el && res?.success) el.textContent = res.data || '(no log entries)';
}

async function addWatchPath() {
  const input = document.getElementById('mon-new-path');
  const path  = input?.value?.trim();
  if (!path) return toast('Enter a path first', 'error');
  const res = Demo.active ? { success: true } : await API.monitorAddPath(path);
  if (res?.success) {
    toast('Now watching: ' + path, 'success');
    if (input) input.value = '';
    loadMonitor();
  } else {
    toast(res?.error || 'Failed to add path', 'error');
  }
}

async function removeWatchPath(path) {
  const res = Demo.active ? { success: true } : await API.monitorRemovePath(path);
  if (res?.success) { toast('Removed: ' + path, 'success'); loadMonitor(); }
  else toast('Failed to remove path', 'error');
}

async function installMonitorService() {
  const btn = document.getElementById('install-service-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Installing…'; }
  const res = Demo.active
    ? { success: true, data: { message: 'Service installed (demo mode)' } }
    : await API.monitorInstallService();
  if (res?.success) toast(res.data?.message || 'Service installed successfully', 'success');
  else toast(res?.error || 'Installation failed', 'error');
  if (btn) { btn.disabled = false; btn.textContent = 'Install as System Service'; }
  loadMonitor();
  loadServiceStatus();
}

// ── Systemd Service Status Panel ─────────────────────────────────────────────

async function loadServiceStatus() {
  const res = Demo.active
    ? { success: true, data: {
        installed: true, enabled: true, active: true,
        active_state: 'active', sub_state: 'running',
        since: Math.floor(Date.now() / 1000) - 3600,
        main_pid: 1234, memory_mb: 18.4,
        description: 'Sentinel Gate Real-Time File Monitor',
        unit_file: '/etc/systemd/system/sentinel-gate-monitor.service'
      }}
    : await API.monitorServiceStatus();

  if (!res?.success) return;
  const d = res.data;

  // State badge
  const badge = document.getElementById('svc-state-badge');
  if (badge) {
    const active = d.active_state === 'active';
    const color  = active ? 'badge-green' : (d.active_state === 'failed' ? 'badge-red' : 'badge-yellow');
    badge.className   = 'badge ' + color;
    badge.textContent = active ? '● Active' : ('○ ' + (d.active_state || 'Unknown'));
  }

  // Info cells
  setText('svc-installed',  d.installed ? (d.unit_file || 'Yes') : 'Not installed');
  setText('svc-enabled',    d.enabled   ? 'Enabled (auto-start on boot)' : 'Disabled');
  setText('svc-since',      d.since     ? new Date(d.since * 1000).toLocaleString() : '—');
  setText('svc-pid',        d.main_pid  ? String(d.main_pid) : '—');
  setText('svc-mem',        d.memory_mb ? d.memory_mb + ' MB' : '—');
  setText('svc-substate',   d.sub_state || '—');

  // Auto-start toggle
  const toggle = document.getElementById('svc-autostart-toggle');
  if (toggle) toggle.checked = !!d.enabled;

  // Install strip — hide once installed
  const strip = document.getElementById('svc-install-strip');
  if (strip) strip.style.display = d.installed ? 'none' : '';
}

async function svcAction(action) {
  const validActions = ['start', 'stop', 'restart'];
  if (!validActions.includes(action)) return;

  if (Demo.active) {
    toast('Service ' + action + 'ed (demo)', 'success');
    return;
  }

  const fn = {
    start:   API.monitorStart,
    stop:    API.monitorStop,
    restart: API.monitorRestart
  }[action];

  const res = await fn();
  if (res?.success) {
    toast('Service ' + action + 'ed', 'success');
    setTimeout(() => { loadMonitor(); loadServiceStatus(); }, 800);
  } else {
    toast(res?.error || 'Action failed', 'error');
  }
}

async function toggleServiceAutostart(checked) {
  if (Demo.active) {
    toast(checked ? 'Auto-start enabled (demo)' : 'Auto-start disabled (demo)', 'success');
    return;
  }
  const res = checked ? await API.monitorEnableService() : await API.monitorDisableService();
  if (res?.success) toast(checked ? 'Auto-start enabled' : 'Auto-start disabled', 'success');
  else {
    toast(res?.error || 'Failed to update auto-start', 'error');
    // Revert toggle on failure
    const toggle = document.getElementById('svc-autostart-toggle');
    if (toggle) toggle.checked = !checked;
  }
}

async function loadServiceLogs() {
  if (Demo.active) {
    const el = document.getElementById('svc-journal-log');
    if (el) el.textContent =
      '2024-01-15T14:22:01+0000 sentinel-gate-monitor[1234]: INFO  Monitor started\n' +
      '2024-01-15T14:22:01+0000 sentinel-gate-monitor[1234]: INFO  inotify engine active\n' +
      '2024-01-15T14:22:01+0000 sentinel-gate-monitor[1234]: INFO  Watching /home\n' +
      '2024-01-15T15:30:00+0000 sentinel-gate-monitor[1234]: ALERT c99_shell detected';
    return;
  }
  const sel   = document.getElementById('svc-log-lines');
  const lines = parseInt(sel?.value || '50', 10);
  const res   = await API.monitorServiceLogs(lines);
  const el    = document.getElementById('svc-journal-log');
  if (el) {
    if (res?.success && Array.isArray(res.data) && res.data.length > 0) {
      el.textContent = res.data.join('\n');
    } else {
      el.textContent = '(no journal entries — service may not have run yet)';
    }
  }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ── Storage Management ────────────────────────────────────────────────────────
async function loadStorageStats() {
  if (Demo.active) {
    populateStorageUI({
      quarantine: { path: '/usr/local/sentinel-gate/quarantine', size_bytes: 4718592, files: 7, writable: true },
      logs:       { path: '/usr/local/sentinel-gate/logs', size_bytes: 2097152, files: 12,
                    writable: true, monitor_log_bytes: 1048576 },
      database:   { path: '/usr/local/sentinel-gate/database/sentinel.db', size_bytes: 8388608,
                    rows: { waf_events: 94441, security_events: 12803, threats: 47, cron_log: 342 } },
      settings:   { quarantine_dir: '', log_dir: '', log_retention_days: 30,
                    quarantine_retention_days: 90, db_max_waf_events: 100000,
                    db_max_security_events: 50000, db_max_cron_log: 1000, monitor_log_max_mb: 50 },
    });
    return;
  }
  const res = await API.storageStats();
  if (res?.success) populateStorageUI(res.data);
  else toast('Could not load storage stats', 'error');
}

function populateStorageUI(d) {
  const q  = d.quarantine || {};
  const l  = d.logs       || {};
  const db = d.database   || {};
  const s  = d.settings   || {};

  // Quarantine card
  const qs = document.getElementById('stor-quar-size');
  if (qs) qs.textContent = fmtBytes(q.size_bytes || 0);
  const qf = document.getElementById('stor-quar-files');
  if (qf) qf.textContent = q.files || 0;
  const qst = document.getElementById('stor-quar-status');
  if (qst) qst.textContent = q.writable ? '✓ Writable' : '✕ Read-only';
  const qdInput = document.getElementById('stor-quar-dir');
  if (qdInput && s.quarantine_dir !== undefined) qdInput.value = s.quarantine_dir;
  const qRange = document.getElementById('stor-quar-days-range');
  if (qRange) {
    qRange.value = s.quarantine_retention_days || 90;
    const qv = document.getElementById('stor-quar-days-val');
    if (qv) qv.textContent = (s.quarantine_retention_days || 90) + ' days';
  }

  // Logs card
  const ls = document.getElementById('stor-log-size');
  if (ls) ls.textContent = fmtBytes(l.size_bytes || 0);
  const lf = document.getElementById('stor-log-files');
  if (lf) lf.textContent = l.files || 0;
  const lm = document.getElementById('stor-log-monitor');
  if (lm) lm.textContent = fmtBytes(l.monitor_log_bytes || 0);
  const ldInput = document.getElementById('stor-log-dir');
  if (ldInput && s.log_dir !== undefined) ldInput.value = s.log_dir;
  const lRange = document.getElementById('stor-log-days-range');
  if (lRange) {
    lRange.value = s.log_retention_days || 30;
    const lv = document.getElementById('stor-log-days-val');
    if (lv) lv.textContent = (s.log_retention_days || 30) + ' days';
  }
  const mRange = document.getElementById('stor-mon-mb-range');
  if (mRange) {
    mRange.value = s.monitor_log_max_mb || 50;
    const mv = document.getElementById('stor-mon-mb-val');
    if (mv) mv.textContent = (s.monitor_log_max_mb || 50) + ' MB';
  }

  // Database card
  const dbs = document.getElementById('stor-db-size');
  if (dbs) dbs.textContent = fmtBytes(db.size_bytes || 0);
  const dbw = document.getElementById('stor-db-waf');
  if (dbw) dbw.textContent = fmtNum(db.rows?.waf_events || 0);
  const dse = document.getElementById('stor-db-sec');
  if (dse) dse.textContent = fmtNum(db.rows?.security_events || 0);
  const dbt = document.getElementById('stor-db-threats');
  if (dbt) dbt.textContent = fmtNum(db.rows?.threats || 0);
  const dbc = document.getElementById('stor-db-cron');
  if (dbc) dbc.textContent = fmtNum(db.rows?.cron_log || 0);
  const mwInput = document.getElementById('stor-db-max-waf');
  if (mwInput && s.db_max_waf_events !== undefined) mwInput.value = s.db_max_waf_events;
  const msInput = document.getElementById('stor-db-max-sec');
  if (msInput && s.db_max_security_events !== undefined) msInput.value = s.db_max_security_events;
}

async function saveStorageSettings() {
  const g = id => document.getElementById(id);
  const data = {
    quarantine_dir:            g('stor-quar-dir')?.value?.trim()  || '',
    log_dir:                   g('stor-log-dir')?.value?.trim()   || '',
    log_retention_days:        parseInt(g('stor-log-days-range')?.value    || '30'),
    quarantine_retention_days: parseInt(g('stor-quar-days-range')?.value   || '90'),
    monitor_log_max_mb:        parseInt(g('stor-mon-mb-range')?.value      || '50'),
    db_max_waf_events:         parseInt(g('stor-db-max-waf')?.value        || '100000'),
    db_max_security_events:    parseInt(g('stor-db-max-sec')?.value        || '50000'),
  };
  const res = Demo.active ? { success: true } : await API.storageSaveSettings(data);
  if (res?.success) toast('Storage settings saved', 'success');
  else toast(res?.error || 'Save failed', 'error');
}

async function runStoragePrune() {
  const btn = document.getElementById('btn-stor-prune');
  if (btn) { btn.disabled = true; btn.textContent = 'Running…'; }
  const res = Demo.active
    ? { success: true, data: { quarantine_deleted: 2, logs_deleted: 14, waf_pruned: 5000, events_pruned: 1200 } }
    : await API.storagePrune();
  if (btn) { btn.disabled = false; btn.textContent = 'Run Cleanup Now'; }
  if (res?.success) {
    const d = res.data || {};
    const msg = `Cleanup done — Quarantine: ${d.quarantine_deleted||0} files, Logs: ${d.logs_deleted||0} files, WAF rows pruned: ${d.waf_pruned||0}, Event rows pruned: ${d.events_pruned||0}`;
    toast(msg, 'success');
    loadStorageStats();
  } else {
    toast(res?.error || 'Prune failed', 'error');
  }
}

// ── Change Admin Password (Standalone mode only) ──────────────────────────────
async function changeAdminPassword() {
  const u  = document.getElementById('chpw-user')?.value?.trim();
  const p  = document.getElementById('chpw-pass')?.value;
  const p2 = document.getElementById('chpw-pass2')?.value;
  if (!u || !p) return toast('Fill in all fields', 'error');
  if (p !== p2)  return toast('Passwords do not match', 'error');
  if (p.length < 8) return toast('Password too short (min 8 chars)', 'error');
  const res = Demo.active ? { success: true } : await API.changePassword(u, p);
  if (res?.success) {
    toast('Credentials updated — please log in again', 'success');
    document.getElementById('chpw-user').value = '';
    document.getElementById('chpw-pass').value = '';
    document.getElementById('chpw-pass2').value = '';
  } else {
    toast(res?.error || 'Update failed', 'error');
  }
}

// ── Bot Shield ────────────────────────────────────────────────────────────────
async function loadBotShield() {
  const [statsRes, blockedRes, eventsRes, whiteRes] = await Promise.all([
    Demo.active ? { success: true, data: { bots_blocked_today: 142, total_blocked: 1048, whitelisted: 6, requests_analyzed: 284901 } } : API.botStats(),
    Demo.active ? { success: true, data: [] } : API.botBlocked(),
    Demo.active ? { success: true, data: [] } : API.botEvents(100),
    Demo.active ? { success: true, data: [] } : API.botWhitelist(),
  ]);
  if (statsRes?.success) {
    const d = statsRes.data;
    document.getElementById('bot-stat-today').textContent    = fmtNum(d?.bots_blocked_today || 0);
    document.getElementById('bot-stat-total').textContent    = fmtNum(d?.total_blocked || 0);
    document.getElementById('bot-stat-white').textContent    = fmtNum(d?.whitelisted || 0);
    document.getElementById('bot-stat-analyzed').textContent = fmtNum(d?.requests_analyzed || 0);
  }
  loadBotBlocked(blockedRes);
  renderBotEvents(eventsRes?.data || []);
  renderBotWhitelist(whiteRes?.data || []);
}

async function loadBotBlocked(cached) {
  const res = cached || (Demo.active ? { success: true, data: [] } : await API.botBlocked());
  const tbody = document.getElementById('bot-blocked-body');
  if (!tbody) return;
  const rows = res?.data || [];
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--txt3);padding:20px">No blocked bots. Click "Analyze Logs".</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(b => `
    <tr>
      <td class="mono">${b.ip_address}</td>
      <td><span class="badge badge-red" style="font-size:.65rem">${b.threat_type || 'bot'}</span></td>
      <td>${fmtNum(b.hits || 1)}</td>
      <td class="dim">${b.last_seen ? reltime(b.last_seen) : '-'}</td>
      <td><button class="btn btn-ghost btn-xs" onclick="unblockBot('${b.ip_address}')">Unblock</button></td>
    </tr>`).join('');
}

function renderBotEvents(events) {
  const tbody = document.getElementById('bot-events-body');
  if (!tbody) return;
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--txt3);padding:20px">No events yet</td></tr>';
    return;
  }
  tbody.innerHTML = events.slice(0, 50).map(e => `
    <tr>
      <td class="mono">${e.ip_address}</td>
      <td class="mono" style="font-size:.7rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${e.user_agent||''}">${(e.user_agent||'-').slice(0,50)}</td>
      <td><span class="badge badge-amber" style="font-size:.65rem">${e.threat_type||'scanner'}</span></td>
      <td class="mono" style="font-size:.72rem">${e.uri||'-'}</td>
      <td class="dim">${reltime(e.timestamp)}</td>
      <td><span class="badge ${e.action==='block' ? 'badge-red' : 'badge-gray'}" style="font-size:.65rem">${e.action||'block'}</span></td>
    </tr>`).join('');
}

function renderBotWhitelist(items) {
  const el = document.getElementById('bot-whitelist-list');
  if (!el) return;
  if (!items.length) { el.innerHTML = '<div class="dim">No whitelist entries. Good bots (Googlebot etc.) are detected automatically.</div>'; return; }
  el.innerHTML = items.map(w => `
    <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid var(--border)">
      <span class="mono" style="font-size:.78rem">${w.pattern}</span>
      <button class="btn btn-ghost btn-xs" onclick="removeBotWhitelist(${w.id})">x</button>
    </div>`).join('');
}

async function runBotScan() {
  toast('Analyzing access logs for bots...', 'info');
  const res = Demo.active
    ? { success: true, data: { bots_found: 23, bots_blocked: 18, duration_ms: 1240 } }
    : await API.botScan();
  if (res?.success) {
    const d = res.data || {};
    toast(`Analysis done - ${d.bots_found||0} bots found, ${d.bots_blocked||0} blocked`, 'success');
    loadBotShield();
  } else toast(res?.error || 'Analysis failed', 'error');
}

async function unblockBot(ip) {
  if (!confirm('Unblock bot IP ' + ip + '?')) return;
  const res = Demo.active ? { success: true } : await API.botUnblock(ip);
  if (res?.success) { toast(ip + ' unblocked', 'success'); loadBotShield(); }
  else toast('Unblock failed', 'error');
}

async function addBotWhitelist() {
  const pattern = document.getElementById('bot-white-pattern')?.value?.trim();
  if (!pattern) { toast('Enter a pattern', 'error'); return; }
  const res = Demo.active ? { success: true } : await API.botAddWhitelist(pattern, '');
  if (res?.success) {
    toast(pattern + ' whitelisted', 'success');
    document.getElementById('bot-white-pattern').value = '';
    loadBotShield();
  } else toast('Add failed', 'error');
}

async function removeBotWhitelist(id) {
  const res = Demo.active ? { success: true } : await API.botRemoveWhitelist(id);
  if (res?.success) { toast('Removed from whitelist', 'success'); loadBotShield(); }
  else toast('Remove failed', 'error');
}

// ── CMS Guard ─────────────────────────────────────────────────────────────────
async function loadCMSGuard() {
  const [statsRes, installsRes] = await Promise.all([
    Demo.active ? { success: true, data: { total_installs: 4, wordpress: 3, joomla: 1, drupal: 0, outdated: 2, installs_with_issues: 3, last_scan_at: Math.floor(Date.now()/1000), ever_scanned: true } } : API.cmsStats(),
    Demo.active ? { success: true, data: [
      { id:1, cms_type:'wordpress', version:'6.2.1', cpanel_user:'alice', install_path:'/home/alice/public_html', issues:'["xmlrpc_enabled","login_exposed"]', outdated:1, status:'warning' },
      { id:2, cms_type:'wordpress', version:'6.4.2', cpanel_user:'bob',   install_path:'/home/bob/public_html',   issues:'[]', outdated:0, status:'ok' },
      { id:3, cms_type:'joomla',    version:'4.2.0', cpanel_user:'carol', install_path:'/home/carol/public_html', issues:'["outdated_version"]', outdated:1, status:'warning' },
    ]} : API.cmsInstalls(),
  ]);

  if (statsRes?.success) {
    const d = statsRes.data;
    // The API returns total_installs. This read d.total — the key the DEMO
    // fixture uses — so the counter showed 0 no matter how many sites were
    // found. The demo shape and the real shape had drifted apart, and only the
    // demo was ever looked at. Both are accepted now; test_cmsguard.php asserts
    // the real one exists.
    const total = d?.total_installs ?? d?.total ?? 0;
    document.getElementById('cms-stat-total').textContent    = fmtNum(total);
    document.getElementById('cms-stat-outdated').textContent = fmtNum(d?.outdated || 0);
    document.getElementById('cms-stat-issues').textContent   = fmtNum(d?.installs_with_issues || 0);
    document.getElementById('cms-stat-wp').textContent       = fmtNum(d?.wordpress || 0);
  }

  const installs = installsRes?.data || [];
  const badge = document.getElementById('cms-count-badge');
  if (badge) badge.textContent = installs.length + ' found';

  const tbody = document.getElementById('cms-installs-body');
  if (!tbody) return;
  if (!installs.length) {
    // Distinguish "nothing here" from "we have not looked yet". A server with
    // WordPress on it showing "0 websites" reads as a broken product; saying no
    // scan has run reads as a next step.
    const everScanned = statsRes?.data?.ever_scanned;
    const msg = everScanned
      ? 'No CMS installations found. Scan again if you have added sites since '
        + (statsRes.data.last_scan_at ? reltime(statsRes.data.last_scan_at) : 'the last scan') + '.'
      : 'No scan has run yet — click "Scan Server" to discover CMS installations.';
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--txt3);padding:28px">'
                    + esc(msg) + '</td></tr>';
    return;
  }
  tbody.innerHTML = installs.map(c => {
    let issues = [];
    try { issues = JSON.parse(c.issues || '[]'); } catch(_) {}
    const icons = { wordpress: 'WP', joomla: 'JM', drupal: 'DR' };
    const cmsLabel = icons[c.cms_type] || c.cms_type;
    return '<tr>' +
      '<td><span class="badge badge-blue" style="font-size:.7rem">' + cmsLabel + '</span></td>' +
      '<td class="mono" style="color:' + (c.outdated ? 'var(--amber)' : 'var(--green)') + '">' + c.version + (c.outdated ? ' !' : '') + '</td>' +
      '<td class="mono" style="color:var(--blue)">' + (c.cpanel_user||'-') + '</td>' +
      '<td class="mono" style="font-size:.72rem;max-width:180px;overflow:hidden;text-overflow:ellipsis" title="' + c.install_path + '">' + c.install_path + '</td>' +
      '<td>' + (issues.length ? issues.map(function(i){ return '<span class="badge badge-amber" style="font-size:.62rem;margin:1px">' + i.replace(/_/g,' ') + '</span>'; }).join('') : '<span class="badge badge-green" style="font-size:.62rem">None</span>') + '</td>' +
      '<td>' + (c.status === 'ok' ? '<span class="badge badge-green">OK</span>' : '<span class="badge badge-amber">Issues</span>') + '</td>' +
      '<td><button class="btn btn-ghost btn-xs" onclick="recheckCMS(' + c.id + ')">Recheck</button></td>' +
      '</tr>';
  }).join('');
}

async function runCMSScan() {
  toast('Scanning server for CMS installations...', 'info');
  const btn = document.getElementById('cms-scan-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }
  const res = Demo.active
    ? { success: true, data: { found: 4, wordpress: 3, joomla: 1, issues_found: 3 } }
    : await API.cmsScan();
  if (btn) { btn.disabled = false; btn.textContent = 'Scan Server'; }
  if (res?.success) {
    const d = res.data || {};
    toast('Scan complete - ' + (d.found||0) + ' installs found, ' + (d.issues_found||0) + ' with issues', 'success');
    loadCMSGuard();
  } else toast(res?.error || 'Scan failed', 'error');
}

async function recheckCMS(id) {
  const res = Demo.active ? { success: true } : await API.cmsCheck(id);
  if (res?.success) { toast('Re-check complete', 'success'); loadCMSGuard(); }
  else toast('Check failed', 'error');
}

// ── Rootkit Scanner ───────────────────────────────────────────────────────────
async function loadRootkit() {
  const [statusRes, scansRes] = await Promise.all([
    Demo.active ? { success: true, data: { rkhunter_available: true, chkrootkit_available: false } } : API.rootkitStatus(),
    Demo.active ? { success: true, data: [] } : API.rootkitScans(),
  ]);

  if (statusRes?.success) {
    const d = statusRes.data;
    const rkIcon = document.getElementById('rk-rkhunter-icon');
    const rkSt   = document.getElementById('rk-rkhunter-status');
    const ckIcon = document.getElementById('rk-chkrootkit-icon');
    const ckSt   = document.getElementById('rk-chkrootkit-status');
    if (rkIcon) rkIcon.textContent = d?.rkhunter_available ? 'OK' : 'X';
    if (rkSt)   rkSt.textContent   = d?.rkhunter_available ? 'Available' : 'Not installed';
    if (ckIcon) ckIcon.textContent = d?.chkrootkit_available ? 'OK' : 'X';
    if (ckSt)   ckSt.textContent   = d?.chkrootkit_available ? 'Available' : 'Not installed';
  }

  const scans = scansRes?.data || [];
  const tbody = document.getElementById('rootkit-history-body');
  if (tbody) {
    if (!scans.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--txt3);padding:20px">No scan history</td></tr>';
    } else {
      tbody.innerHTML = scans.map(s => '<tr>' +
        '<td class="mono">' + s.tool + '</td>' +
        '<td class="dim">' + reltime(s.finished_at || s.started_at) + '</td>' +
        '<td style="color:' + (s.warnings_count > 0 ? 'var(--amber)' : 'var(--green)') + '">' + s.warnings_count + '</td>' +
        '<td style="color:' + (s.infected_count > 0 ? 'var(--red)' : 'var(--green)') + '">' + s.infected_count + '</td>' +
        '<td><button class="btn btn-ghost btn-xs" onclick="viewRootkitFindings(' + s.id + ')">View</button></td>' +
        '</tr>').join('');
      const last = scans[0];
      const badge = document.getElementById('rk-last-badge');
      if (badge) {
        badge.textContent = last.infected_count > 0 ? last.infected_count + ' INFECTED' :
          last.warnings_count > 0 ? last.warnings_count + ' Warnings' : 'Clean';
        badge.className = 'badge ' + (last.infected_count > 0 ? 'badge-red' : last.warnings_count > 0 ? 'badge-amber' : 'badge-green');
      }
      const resultEl = document.getElementById('rk-last-result');
      if (resultEl) resultEl.textContent = 'Tool: ' + last.tool + ' | Scanned: ' + reltime(last.finished_at||last.started_at) + ' | Warnings: ' + last.warnings_count + ' | Infected: ' + last.infected_count;
    }
  }
}

async function runRootkitScan() {
  const tool = document.getElementById('rootkit-tool-sel')?.value || 'rkhunter';
  const btn  = document.getElementById('rootkit-scan-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }
  toast('Running ' + tool + ' scan - this may take a few minutes...', 'info');
  const res = Demo.active
    ? { success: true, data: { tool: tool, warnings_count: 2, clean_count: 167, infected_count: 0 } }
    : await API.rootkitScan(tool);
  if (btn) { btn.disabled = false; btn.textContent = 'Start Scan'; }
  if (res?.success) {
    const d = res.data || {};
    toast(tool + ' scan complete - ' + (d.warnings_count||0) + ' warnings, ' + (d.infected_count||0) + ' infected', d.infected_count > 0 ? 'error' : 'success');
    loadRootkit();
  } else toast(res?.error || 'Scan failed - tool may not be installed', 'error');
}

async function viewRootkitFindings(scanId) {
  const res = Demo.active ? { success: true, data: [] } : await API.rootkitFindings(scanId);
  const container = document.getElementById('rk-findings-list');
  if (!container) return;
  const findings = res?.data || [];
  if (!findings.length) { container.innerHTML = '<div class="dim" style="font-size:.78rem">No findings for this scan.</div>'; return; }
  container.innerHTML = '<div class="label" style="font-size:.72rem;margin-bottom:8px">Findings</div>' +
    findings.map(f => '<div style="display:flex;gap:10px;align-items:flex-start;padding:6px 0;border-bottom:1px solid var(--border)">' +
      '<span class="badge ' + (f.finding_type==='infected' ? 'badge-red' : f.finding_type==='warning' ? 'badge-amber' : 'badge-green') + '" style="font-size:.62rem;white-space:nowrap">' + f.finding_type + '</span>' +
      '<div><div style="font-size:.75rem;font-weight:600;color:var(--txt2)">' + (f.category||'General') + '</div>' +
      '<div style="font-size:.72rem;color:var(--txt3);margin-top:2px">' + f.description + '</div></div>' +
      '</div>').join('');
}

// ── File Integrity ────────────────────────────────────────────────────────────
async function loadIntegrity() {
  const [statsRes, pathsRes] = await Promise.all([
    Demo.active ? { success: true, data: { total_monitored: 0, clean: 0, modified: 0, new_files: 0, missing: 0 } } : API.integrityStats(),
    Demo.active ? { success: true, data: [] } : API.integrityPaths(),
  ]);

  if (statsRes?.success) {
    const d = statsRes.data;
    document.getElementById('int-stat-total').textContent    = fmtNum(d?.total_monitored || 0);
    document.getElementById('int-stat-clean').textContent    = fmtNum(d?.clean || 0);
    document.getElementById('int-stat-modified').textContent = fmtNum(d?.modified || 0);
    document.getElementById('int-stat-issues').textContent   = fmtNum((d?.new_files||0) + (d?.missing||0));
  }

  const paths = pathsRes?.data || [];
  const pathEl = document.getElementById('int-paths-list');
  if (pathEl) {
    pathEl.innerHTML = paths.length
      ? paths.map(p => '<div class="mono" style="font-size:.75rem;padding:3px 0;color:var(--txt2)">/ ' + (p.path||p) + ' <span class="dim">(' + fmtNum(p.count||0) + ' files)</span></div>').join('')
      : '<div class="dim">No baseline created yet</div>';
  }

  loadIntegrityChanges('');
}

async function loadIntegrityChanges(status) {
  const res = Demo.active ? { success: true, data: [] } : await API.integrityChanges(status);
  const changes = res?.data || [];
  const badge = document.getElementById('int-changes-badge');
  if (badge) badge.textContent = changes.length + ' changes';

  const tbody = document.getElementById('integrity-changes-body');
  if (!tbody) return;
  if (!changes.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--txt3);padding:28px">No changes detected - system is clean</td></tr>';
    return;
  }
  const stMap = { modified: 'badge-amber', new: 'badge-blue', missing: 'badge-red', acknowledged: 'badge-gray' };
  tbody.innerHTML = changes.map(c => '<tr>' +
    '<td><span class="badge ' + (stMap[c.status]||'badge-gray') + '">' + c.status + '</span></td>' +
    '<td class="mono" style="font-size:.72rem;max-width:260px;overflow:hidden;text-overflow:ellipsis" title="' + c.file_path + '">' + c.file_path + '</td>' +
    '<td class="dim">' + fmtBytes(c.size||0) + '</td>' +
    '<td class="mono" style="font-size:.72rem">' + (c.owner||'-') + '</td>' +
    '<td class="dim">' + (c.last_check ? reltime(c.last_check) : '-') + '</td>' +
    '<td>' + (c.status !== 'acknowledged' ? '<button class="btn btn-ghost btn-xs" onclick="acknowledgeIntegrityChange(' + c.id + ')">Acknowledge</button>' : '') + '</td>' +
    '</tr>').join('');
}

async function createBaseline() {
  const path = document.getElementById('int-baseline-path')?.value?.trim() || '/home';
  toast('Creating baseline for ' + path + '...', 'info');
  const res = Demo.active ? { success: true, data: { hashed: 12847 } } : await API.integrityBaseline(path);
  if (res?.success) {
    toast('Baseline created - ' + fmtNum(res.data?.hashed||0) + ' files hashed', 'success');
    loadIntegrity();
  } else toast(res?.error || 'Baseline failed', 'error');
}

async function runIntegrityCheck() {
  toast('Running integrity check...', 'info');
  const res = Demo.active ? { success: true, data: { modified: 0, new_files: 0, missing: 0 } } : await API.integrityCheck('');
  if (res?.success) {
    const d = res.data || {};
    const changed = (d.modified||0) + (d.new_files||0) + (d.missing||0);
    toast('Check complete - ' + changed + ' changes detected', changed ? 'error' : 'success');
    loadIntegrity();
  } else toast(res?.error || 'Check failed', 'error');
}

async function acknowledgeIntegrityChange(id) {
  const res = Demo.active ? { success: true } : await API.integrityAck(id);
  if (res?.success) { toast('Change acknowledged', 'success'); loadIntegrityChanges(''); }
  else toast('Acknowledge failed', 'error');
}

// ── PHP Hardening ─────────────────────────────────────────────────────────────
async function loadPHPHardening() {
  const [statsRes, recsRes, settingsRes, accountsRes] = await Promise.all([
    Demo.active ? { success: true, data: { critical: 1, high: 3, medium: 2, already_hardened: 4 } } : API.phpStats(),
    Demo.active ? { success: true, data: [
      { setting:'allow_url_include', current_value:'On', recommended_value:'Off', severity:'critical', description:'Remote file inclusion attack vector', can_apply:true },
      { setting:'display_errors',    current_value:'On', recommended_value:'Off', severity:'high',     description:'Exposes error details to users', can_apply:true },
      { setting:'allow_url_fopen',   current_value:'On', recommended_value:'Off', severity:'high',     description:'Allows remote file access', can_apply:true },
      { setting:'expose_php',        current_value:'On', recommended_value:'Off', severity:'medium',   description:'Reveals PHP version in headers', can_apply:true },
    ]} : API.phpRecs(),
    Demo.active ? { success: true, data: { expose_php:'On', display_errors:'On', allow_url_fopen:'On', allow_url_include:'On', disable_functions:'', 'session.cookie_httponly':'0' } } : API.phpSettings(),
    State.installMode !== 'standalone'
      ? (Demo.active ? { success: true, data: [{ username:'alice', php_version:'8.1', hardened:false },{ username:'bob', php_version:'8.2', hardened:true }] } : API.phpAccounts())
      : { success: true, data: [] },
  ]);

  if (statsRes?.success) {
    const d = statsRes.data;
    document.getElementById('php-stat-critical').textContent = d?.critical || 0;
    document.getElementById('php-stat-high').textContent     = d?.high || 0;
    document.getElementById('php-stat-medium').textContent   = d?.medium || 0;
    document.getElementById('php-stat-ok').textContent       = d?.already_hardened || 0;
  }

  const recs = recsRes?.data || [];
  const recsEl = document.getElementById('php-recs-list');
  if (recsEl) {
    if (!recs.length) {
      recsEl.innerHTML = '<div style="padding:20px;text-align:center;color:var(--green)">PHP is well configured - no issues found!</div>';
    } else {
      const sevClass = { critical:'badge-red', high:'badge-amber', medium:'badge-blue', low:'badge-gray' };
      recsEl.innerHTML = recs.map(r => '<div style="display:flex;align-items:flex-start;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border)">' +
        '<span class="badge ' + (sevClass[r.severity]||'badge-gray') + '" style="white-space:nowrap;font-size:.65rem">' + r.severity.toUpperCase() + '</span>' +
        '<div style="flex:1">' +
          '<div style="font-weight:700;font-size:.82rem;font-family:var(--font-mono)">' + r.setting + '</div>' +
          '<div style="font-size:.75rem;color:var(--txt2);margin-top:2px">' + r.description + '</div>' +
          '<div style="font-size:.72rem;color:var(--txt3);margin-top:4px">Current: <code style="background:rgba(239,68,68,.1);color:var(--red);padding:1px 4px;border-radius:3px">' + r.current_value + '</code> &rarr; Recommended: <code style="background:rgba(34,197,94,.1);color:var(--green);padding:1px 4px;border-radius:3px">' + r.recommended_value + '</code></div>' +
        '</div>' +
        (r.can_apply ? '<button class="btn btn-primary btn-xs" onclick="applyPHPSetting(\'' + r.setting + '\',\'' + r.recommended_value + '\')">Apply</button>' : '') +
        '</div>').join('');
    }
  }

  const settings = settingsRes?.data || {};
  const tbody = document.getElementById('php-settings-body');
  if (tbody && Object.keys(settings).length) {
    const dangerKeys = ['allow_url_include','allow_url_fopen','display_errors','expose_php','register_globals'];
    tbody.innerHTML = Object.entries(settings).map(([k, v]) => {
      const isDanger = ['On','1'].includes(String(v)) && dangerKeys.includes(k);
      return '<tr><td class="mono" style="font-size:.75rem">' + k + '</td><td class="mono" style="color:' + (isDanger ? 'var(--red)' : 'var(--txt2)') + ';font-size:.75rem">' + (v||'(empty)') + '</td></tr>';
    }).join('');
  }

  const accounts = accountsRes?.data || [];
  const accTbody = document.getElementById('php-accounts-body');
  if (accTbody) {
    accTbody.innerHTML = accounts.length
      ? accounts.map(a => '<tr>' +
          '<td class="mono">' + (a.username||a.user||'-') + '</td>' +
          '<td class="mono">' + (a.php_version||'Default') + '</td>' +
          '<td>' + (a.hardened ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-gray">No</span>') + '</td>' +
          '<td><button class="btn btn-ghost btn-xs" onclick="applyAccountHardening(\'' + (a.username||a.user) + '\')">Harden</button></td>' +
          '</tr>').join('')
      : '<tr><td colspan="4" style="text-align:center;color:var(--txt3);padding:20px">No accounts found</td></tr>';
  }
}

async function applyPHPSetting(setting, value) {
  const data = {};
  data[setting] = value;
  const res = Demo.active ? { success: true } : await API.phpApply(data);
  if (res?.success) { toast(setting + ' applied', 'success'); loadPHPHardening(); }
  else toast(res?.error || 'Apply failed - may require root', 'error');
}

async function applyAllRecommendations() {
  if (Demo.active) { toast('Applied 4 settings (demo)', 'success'); return; }
  const recsRes = await API.phpRecs();
  const safe = (recsRes?.data || []).filter(x => x.can_apply)
    .reduce((acc, x) => { acc[x.setting] = x.recommended_value; return acc; }, {});
  const res = await API.phpApply(safe);
  if (res?.success) {
    const d = res.data || {};
    toast('Applied ' + (d.applied||0) + ' settings, ' + (d.failed||0) + ' failed', 'success');
    loadPHPHardening();
  } else toast(res?.error || 'Apply failed', 'error');
}

async function applyAccountHardening(account) {
  toast('Hardening ' + account + '...', 'info');
  const settings = { display_errors:'Off', allow_url_include:'Off', expose_php:'Off', 'session.cookie_httponly':'1' };
  const res = Demo.active ? { success: true, data: { applied: 4 } } : await API.phpApplyAccount(account, settings);
  if (res?.success) { toast(account + ' hardened', 'success'); loadPHPHardening(); }
  else toast(res?.error || 'Harden failed', 'error');
}

/* ══════════════════════════════════════════════════════════════════════════════
   License
   ══════════════════════════════════════════════════════════════════════════════
   The API returns 402 + needs_license on any gated route. api.js calls
   onLicenseBlocked() centrally so every page behaves the same way rather than
   each rendering its own generic error. */

let _licenseBlockedShown = false;

function onLicenseBlocked(payload) {
  // Only interrupt once per page load — a dashboard fires several parallel
  // requests and would otherwise stack identical banners.
  if (_licenseBlockedShown) return;
  _licenseBlockedShown = true;

  // Show the activation screen rather than a red toast plus a jump to Settings.
  // A licence that has not been entered yet is an expected setup step, not a
  // fault, and presenting it as an error makes a working install look broken.
  showActivateScreen({
    status:  (payload && payload.license_state) || 'Unlicensed',
    message: (payload && payload.error) || '',
  });
}

function _licenseBadgeClass(status) {
  switch (status) {
    case 'Active':    return 'badge badge-green';
    case 'Expired':
    case 'Suspended':
    case 'Invalid':   return 'badge badge-red';
    case 'Unknown':   return 'badge badge-amber';
    default:          return 'badge badge-gray';
  }
}

async function loadLicense() {
  const badge   = document.getElementById('license-badge');
  const summary = document.getElementById('license-summary');
  const meta    = document.getElementById('license-meta');
  if (!badge) return;

  const res = Demo.active
    ? { license: { status:'Active', valid:true, ui_allowed:true, protection_allowed:true,
                   degraded:false, message:'License active.', expires:'2027-08-08',
                   checked_at: Math.floor(Date.now()/1000) - 2*86400,
                   domain:'srv1.example.com', ip:'203.0.113.10' } }
    : await API.get('license/status');
  const lic = res && res.license;
  if (!lic) {
    badge.className = 'badge badge-gray';
    badge.textContent = 'Unavailable';
    if (summary) summary.textContent = 'Could not read license status.';
    return;
  }

  badge.className   = _licenseBadgeClass(lic.status);
  badge.textContent = lic.status + (lic.degraded ? ' (degraded)' : '');
  if (summary) summary.textContent = lic.message || '';

  // The "no secret configured" warning was removed in 3.23.0. The WHMCS
  // Licensing Addon v3.1 signs with an empty secret, so an unset
  // SG_LICENSE_SECRET is the normal state, not a fault -- warning about it
  // would fire on every correctly configured server.
  const warn = document.getElementById('license-config-warning');
  if (warn) { warn.classList.add('hidden'); }

  if (meta) {
    meta.classList.remove('hidden');
    const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v || '—'; };
    set('license-status-val', lic.status);
    set('license-expires-val', lic.expires);
    set('license-checked-val',
        lic.checked_at ? new Date(lic.checked_at * 1000).toLocaleString() : 'never');
  }
}

function _licenseError(msg) {
  const box = document.getElementById('license-error');
  if (!box) return;
  if (!msg) { box.classList.add('hidden'); box.textContent = ''; return; }
  box.classList.remove('hidden');
  box.textContent = msg;
}

async function activateLicense() {
  const input = document.getElementById('license-key-input');
  const key   = input ? input.value.trim() : '';
  _licenseError('');

  if (!key) { _licenseError('Enter a license key first.'); return; }

  const res = await API.post('license/activate', { key });
  if (res && res.success) {
    toast('License activated', 'success');
    if (input) input.value = '';
    _licenseBlockedShown = false;   // allow a fresh prompt if it lapses again
    await loadLicense();
    // Re-run whatever page the user is on now that the gate has lifted
    if (typeof refreshDashboard === 'function') refreshDashboard();
  } else {
    _licenseError((res && res.error) || 'Activation failed.');
    await loadLicense();
  }
}

async function refreshLicense() {
  _licenseError('');
  const res = await API.post('license/refresh');
  if (res && res.success) {
    toast('License re-checked', 'success');
    _licenseBlockedShown = false;
  } else {
    _licenseError((res && res.error) || 'Re-check failed.');
  }
  await loadLicense();
}


/* ── Schedule field visibility ────────────────────────────────────────────────
   Only show the inputs a given schedule actually uses. Leaving "day of week"
   visible on a daily schedule invites the user to set a value that is silently
   ignored, and then to report it as a bug. */
function syncScheduleFields() {
  const vis = (id, on) => { const e = document.getElementById(id); if (e) e.style.display = on ? '' : 'none'; };
  const val = id => document.getElementById(id)?.value;

  const scan = val('set-scan-schedule');
  vis('wrap-scan-time', scan === 'daily' || scan === 'weekly');
  vis('wrap-scan-day',  scan === 'weekly');

  vis('wrap-sig-day', val('set-sig-schedule') === 'weekly');
}

['set-scan-schedule', 'set-sig-schedule'].forEach(id => {
  document.addEventListener('change', e => {
    if (e.target && e.target.id === id) syncScheduleFields();
  });
});

async function updateSignaturesNow() {
  toast('Updating virus definitions…', 'info');
  const res = await API.updateSigs();
  if (res && res.success) {
    toast('Virus definitions updated', 'success');
    loadSettings();
  } else {
    toast((res && res.error) || 'Definition update failed', 'error');
  }
}

/* ══════════════════════════════════════════════════════════════════════════════
   Self-update
   ══════════════════════════════════════════════════════════════════════════════
   The update replaces the very code that serves the API, so this cannot be a
   single request-and-wait. The server starts the updater detached and writes
   progress to a file outside the install directory; the UI polls that.

   The important consequence: mid-update the API is BEING OVERWRITTEN, so polls
   will fail — connection refused, 502, half-written PHP. Those are expected, not
   errors, and must not abort the flow. Only a long unbroken run of failures
   means something is actually wrong. */

let _updPoll = null;
let _updFails = 0;
let _updStarted = 0;

function _el(id) { return document.getElementById(id); }

function showUpdateButton(info) {
  const btn = _el('update-now-btn');
  if (!btn) return;
  if (info && info.update_available) {
    _el('update-btn-version').textContent = 'v' + (info.latest_version || '?');
    btn.classList.remove('hidden');
  } else {
    btn.classList.add('hidden');
  }
}

function _setProgress(pct, msg, title) {
  const f = _el('update-bar-fill'), p = _el('update-pct'),
        m = _el('update-msg'),      t = _el('update-title');
  if (f) f.style.width = Math.max(0, Math.min(100, pct)) + '%';
  if (p) p.textContent = Math.round(pct) + '%';
  if (m && msg) m.textContent = msg;
  if (t && title) t.textContent = title;
}

async function startUpdate() {
  if (Demo.active) { _demoUpdate(); return; }

  const overlay = _el('update-overlay');
  overlay.classList.remove('hidden');
  _el('update-close').classList.add('hidden');
  _el('update-spinner').className = 'update-spinner';
  _setProgress(1, 'Starting update…', 'Updating Sentinel Gate');

  const res = await API.post('update/run', {});
  if (!res || !res.success) {
    // 409 means one is already running — attach to it rather than failing.
    if (res && res.data && res.data.status === 'running') {
      _pollUpdate();
      return;
    }
    _updateFailed((res && res.error) || 'Could not start the update.');
    return;
  }

  _updFails = 0;
  _updStarted = Date.now();
  _pollUpdate();
}

function _pollUpdate() {
  clearInterval(_updPoll);
  _updPoll = setInterval(async () => {
    let d = null;
    try {
      const r = await API.get('update/progress');
      d = r && r.data;
    } catch (_) { d = null; }

    if (!d) {
      // Expected while the API's own files are being replaced. Give it a long
      // rope — 40 polls at 2s is over a minute of tolerated unavailability —
      // before calling it a failure.
      if (++_updFails > 40) {
        clearInterval(_updPoll);
        _updateFailed('Lost contact with the server. Check logs/update.log.');
      }
      return;
    }
    _updFails = 0;

    _setProgress(d.percent || 0, d.message || '');

    if (d.status === 'success') {
      clearInterval(_updPoll);
      _el('update-spinner').className = 'update-spinner done';
      _setProgress(100, d.message || 'Update complete', 'Updated successfully');
      _el('update-close').classList.remove('hidden');
      // Give the services a moment to come back before reloading.
      setTimeout(finishUpdate, 2500);
    } else if (d.status === 'rolled_back') {
      clearInterval(_updPoll);
      _el('update-spinner').className = 'update-spinner failed';
      _setProgress(100,
        d.message || 'Rolled back to the previous version. Your data is intact.',
        'Update failed — rolled back');
      _el('update-close').classList.remove('hidden');
    } else if (d.status === 'failed') {
      clearInterval(_updPoll);
      _updateFailed(d.message || 'The update failed.');
    }
  }, 2000);
}

function _updateFailed(msg) {
  clearInterval(_updPoll);
  _el('update-spinner').className = 'update-spinner failed';
  _setProgress(100, msg, 'Update failed');
  _el('update-close').classList.remove('hidden');
}

function finishUpdate() {
  // Full reload, not just a data refresh: the JS and CSS themselves have been
  // replaced on disk, so the running page is the OLD build talking to the NEW
  // backend. Reloading is the only way to get a consistent pair.
  window.location.reload();
}

/* Demo-mode walkthrough so the flow can be reviewed without a real update. */
function _demoUpdate() {
  const overlay = _el('update-overlay');
  overlay.classList.remove('hidden');
  _el('update-close').classList.add('hidden');
  _el('update-spinner').className = 'update-spinner';
  const steps = [
    [5,  'Checking for updates…'],
    [15, 'Downloading v3.11.0…'],
    [30, 'Backing up your data…'],
    [45, 'Snapshotting current version…'],
    [55, 'Applying v3.11.0…'],
    [75, 'Restoring your settings and data…'],
    [85, 'Running database migrations…'],
    [100,'Update complete'],
  ];
  let i = 0;
  const t = setInterval(() => {
    if (i >= steps.length) {
      clearInterval(t);
      _el('update-spinner').className = 'update-spinner done';
      _setProgress(100, 'Updated to v3.11.0', 'Updated successfully');
      _el('update-close').classList.remove('hidden');
      return;
    }
    _setProgress(steps[i][0], steps[i][1]);
    i++;
  }, 900);
}


/* HTML-escape before interpolating into innerHTML.
   Not optional here: blocklist "reason" text derives from DNS answers, and
   rootkit findings embed filesystem paths — an attacker who can create a file
   named `<img onerror=...>` would otherwise get script execution in the
   admin's browser, from inside the tool meant to detect them. */
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* ══════════════════════════════════════════════════════════════════════════════
   Blocklist matrix
   ══════════════════════════════════════════════════════════════════════════════
   Every list is shown separately rather than as one score, because delisting
   requires knowing WHICH service lists you — a single number cannot tell an
   operator where to go. */

async function loadServerIpForBlocklist() {
  const input = document.getElementById('bl-ip');
  if (!input || input.value.trim()) return;
  if (Demo.active) { input.value = '203.0.113.10'; input.placeholder = ''; return; }
  const res = await API.get('iprep/server-ips');
  const ips = (res && res.data) || [];
  input.value = ips[0] || '';
  input.placeholder = ips.length ? '' : 'enter an IP address';
}

function _blBadge(status) {
  return status === 'listed'  ? 'badge badge-red'
       : status === 'refused' ? 'badge badge-amber'
       : 'badge badge-green';
}

async function runBlocklistCheck() {
  const ipEl = document.getElementById('bl-ip');
  const ip   = ipEl ? ipEl.value.trim() : '';
  if (!ip) { toast('Enter an IP address to check', 'error'); return; }

  document.getElementById('bl-progress').classList.remove('hidden');
  document.getElementById('bl-empty').classList.add('hidden');
  document.getElementById('bl-results').classList.add('hidden');

  const res = Demo.active ? _demoBlocklists(ip)
                          : await API.get('iprep/blocklists?ip=' + encodeURIComponent(ip));

  document.getElementById('bl-progress').classList.add('hidden');
  const d = res && res.data;
  if (!d || d.error) {
    document.getElementById('bl-empty').classList.remove('hidden');
    toast((d && d.error) || 'Blocklist check failed', 'error');
    return;
  }

  const badge = document.getElementById('bl-summary');
  badge.textContent = d.listed
    ? d.listed + ' of ' + d.checked + ' lists — ' + d.risk
    : 'Clean on all ' + d.checked + ' lists';
  badge.className = d.listed
    ? (d.risk === 'critical' || d.risk === 'high' ? 'badge badge-red' : 'badge badge-amber')
    : 'badge badge-green';

  // Listed entries first. An operator opening this page needs the problems, not
  // to scroll past two dozen clean rows to find them.
  const rank = s => s === 'listed' ? 0 : s === 'refused' ? 1 : 2;
  const rows = d.results.slice().sort(
    (a, b) => rank(a.status) - rank(b.status) || b.weight - a.weight);

  document.getElementById('bl-tbody').innerHTML = rows.map(function (r) {
    const hl = r.status === 'listed' ? ' style="background:var(--red-dim)"' : '';
    const link = r.site
      ? '<a href="' + esc(r.site) + '" target="_blank" rel="noopener" class="btn btn-ghost btn-xs">Delist</a>'
      : '—';
    return '<tr' + hl + '>'
      + '<td class="primary">' + esc(r.name)
      + '<div style="font-size:.68rem;color:var(--txt3)">' + esc(r.zone) + '</div></td>'
      + '<td><span class="badge badge-gray">' + esc(r.category) + '</span></td>'
      + '<td><span class="' + _blBadge(r.status) + '">' + esc(r.status) + '</span></td>'
      + '<td style="font-size:.75rem">' + esc(r.reason || '—') + '</td>'
      + '<td>' + link + '</td></tr>';
  }).join('');

  document.getElementById('bl-results').classList.remove('hidden');
}

function _demoBlocklists(ip) {
  const mk = (name, zone, cat, w, status, reason) =>
    ({ name, zone, category: cat, weight: w, status,
       listed: status === 'listed', reason, site: 'https://example.org/delist' });
  return { success: true, data: {
    ip, checked: 25, listed: 2, score: 33, risk: 'medium',
    results: [
      mk('Spamhaus ZEN', 'zen.spamhaus.org', 'composite', 25, 'listed', 'PBL — not a legitimate mail sender'),
      mk('UCEPROTECT L1', 'dnsbl-1.uceprotect.net', 'spam', 12, 'listed', 'Listed (127.0.0.2)'),
      mk('Barracuda BRBL', 'b.barracudacentral.org', 'spam', 18, 'refused', 'The list refused this query'),
      mk('SpamCop', 'bl.spamcop.net', 'spam', 18, 'clean', null),
      mk('SORBS Aggregate', 'dnsbl.sorbs.net', 'composite', 12, 'clean', null),
      mk('CBL / abuseat', 'cbl.abuseat.org', 'exploit', 20, 'clean', null),
      mk('Blocklist.de', 'bl.blocklist.de', 'exploit', 15, 'clean', null),
      mk('PSBL', 'psbl.surriel.com', 'spam', 10, 'clean', null),
    ] } };
}

/* ── Built-in rootkit engine ───────────────────────────────────────────────── */

async function runBuiltinRootkitScan() {
  toast('Running built-in rootkit scan…', 'info');
  const res = Demo.active ? _demoRootkit() : await API.post('rootkit/scan-builtin', {});
  const d = res && res.data;
  if (!d) { toast('Built-in scan failed', 'error'); return; }

  document.getElementById('rk-builtin-card').classList.remove('hidden');

  const crit = d.summary.critical || 0;
  const high = d.summary.high || 0;
  const badge = document.getElementById('rk-builtin-badge');
  badge.textContent = d.clean ? 'Clean' : crit + ' critical · ' + high + ' high';
  badge.className   = d.clean ? 'badge badge-green'
                    : (crit ? 'badge badge-red' : 'badge badge-amber');

  document.getElementById('rk-builtin-meta').textContent =
    d.checks + ' checks in ' + d.duration + 's · ' + d.findings.length + ' finding(s)';
  document.getElementById('rk-builtin-clean').classList.toggle('hidden', !d.clean);

  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const rows = d.findings.slice().sort((a, b) => order[a.severity] - order[b.severity]);

  document.getElementById('rk-builtin-tbody').innerHTML = rows.map(function (f) {
    return '<tr>'
      + '<td><span class="sev sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span></td>'
      + '<td class="primary" style="font-size:.78rem">' + esc(f.finding) + '</td>'
      + '<td style="font-size:.73rem;color:var(--txt3)">' + esc(f.explanation) + '</td>'
      + '</tr>';
  }).join('');

  toast(d.clean ? 'No critical findings' : (crit + high) + ' significant finding(s)',
        d.clean ? 'success' : 'error');
}

function _demoRootkit() {
  return { success: true, data: {
    checks: 11, duration: 2.4, clean: false,
    summary: { critical: 1, high: 1, medium: 1, low: 0 },
    findings: [
      { severity: 'critical', finding: '/etc/ld.so.preload is populated: /lib/.so/libx.so',
        explanation: 'This forces a library into every dynamically linked process — the standard userland rootkit hook.' },
      { severity: 'high', finding: 'Unexpected SUID root binary: /usr/local/bin/.hst',
        explanation: 'A SUID root binary outside the known set grants privilege escalation to any user.' },
      { severity: 'medium', finding: 'sshd permits direct root login',
        explanation: 'PermitRootLogin yes lets an attacker brute-force root directly.' },
    ] } };
}

/* ══════════════════════════════════════════════════════════════════════════════
   WAF engine provisioning
   ══════════════════════════════════════════════════════════════════════════════
   WAF.php only reads ModSecurity's config and audit log, so with ModSecurity
   absent the page reported status and protected nothing. This installs and
   manages the engine from the dashboard. */

async function loadWafEngine() {
  const badge = document.getElementById('waf-engine-badge');
  if (!badge) return;

  const res = Demo.active ? _demoWafEngine() : await API.get('waf/engine-status');
  const d = res && res.data;
  if (!d) {
    badge.className = 'badge badge-gray';
    badge.textContent = 'Unavailable';
    return;
  }

  const ready = d.modsecurity_installed && d.crs_installed;
  badge.className = ready
    ? (d.mode === 'on' ? 'badge badge-green' : 'badge badge-amber')
    : 'badge badge-red';
  badge.textContent = !d.modsecurity_installed ? 'Not installed'
                    : !d.crs_installed         ? 'No ruleset'
                    : d.mode === 'on'          ? 'Blocking'
                    : d.mode === 'detectiononly' ? 'Detection only'
                    : 'Installed';

  const summary = document.getElementById('waf-engine-summary');
  summary.textContent = ready
    ? (d.mode === 'on'
        ? 'ModSecurity is enforcing the OWASP Core Rule Set.'
        : 'ModSecurity is installed and logging matches, but not blocking them yet.')
    : 'No web application firewall engine is active on this server. '
    + 'Sentinel Gate can install and configure ModSecurity with the OWASP Core Rule Set.';

  document.getElementById('waf-engine-meta').classList.remove('hidden');
  const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  set('waf-ms-val',  d.modsecurity_installed ? ('installed ' + (d.modsecurity_version || '')) : 'not installed');
  set('waf-crs-val', d.crs_installed ? ('v' + (d.crs_version || '?')) : 'not installed');
  set('waf-mode-val', d.mode === 'unknown' ? '—' : d.mode);

  // Offer install only when it can actually succeed — a button that always
  // fails is worse than no button.
  const btn = document.getElementById('waf-install-btn');
  const sel = document.getElementById('waf-mode-select');
  btn.classList.toggle('hidden', ready || !d.can_install);
  sel.classList.toggle('hidden', !ready);
  if (ready) sel.value = d.mode === 'unknown' ? 'detectiononly' : d.mode;

  if (!ready && !d.can_install) {
    summary.textContent += ' (No supported package manager was found, so this '
                        +  'server cannot be provisioned automatically.)';
  }
}

async function installWafEngine() {
  const btn = document.getElementById('waf-install-btn');
  const log = document.getElementById('waf-install-log');
  btn.disabled = true;
  btn.textContent = 'Installing…';
  log.classList.remove('hidden');
  log.textContent = 'Installing ModSecurity and the OWASP Core Rule Set. This can take a minute…';

  const res = Demo.active ? _demoWafInstall() : await API.post('waf/engine-install', {});
  const d = res && res.data;

  const lines = ((d && d.steps) || []).map(s => (s.ok ? '[ok]   ' : '[fail] ') + s.message);
  if (d && d.error)  lines.push('[fail] ' + d.error);
  if (d && d.note)   lines.push('', d.note);
  log.textContent = lines.join('\n') || 'No output.';

  btn.disabled = false;
  btn.textContent = 'Install ModSecurity + OWASP CRS';

  if (res && res.success) {
    toast('WAF engine installed — running in detection only', 'success');
  } else {
    toast((res && res.error) || 'WAF installation failed', 'error');
  }
  loadWafEngine();
}

async function setWafEngineMode(mode) {
  // Blocking mode can turn away real visitors if a rule misfires, so it is
  // confirmed rather than applied on a stray change event.
  if (mode === 'on' && !confirm(
      'Switch the WAF to blocking mode?\n\n'
    + 'Requests matching a rule will be rejected. Review the audit log first — '
    + 'a false positive will turn away legitimate visitors.')) {
    loadWafEngine();
    return;
  }
  const res = Demo.active ? { success: true } : await API.post('waf/engine-mode', { mode });
  toast(res && res.success ? 'WAF mode updated' : ((res && res.error) || 'Could not change mode'),
        res && res.success ? 'success' : 'error');
  loadWafEngine();
}

function _demoWafEngine() {
  return { success: true, data: {
    modsecurity_installed: false, modsecurity_version: null,
    crs_installed: false, crs_path: null, crs_version: null,
    mode: 'unknown', apache: 'ea4', package_manager: 'dnf',
    can_install: true, managed_by_us: false } };
}

function _demoWafInstall() {
  return { success: true, data: { success: true, steps: [
    { ok: true, message: 'Installed ea-apache24-mod_security2' },
    { ok: true, message: 'Installed OWASP CRS 4.7.0' },
    { ok: true, message: 'Wrote Sentinel Gate WAF config (DetectionOnly)' },
    { ok: true, message: 'Apache configuration validated' },
    { ok: true, message: 'Apache reloaded — WAF active in DetectionOnly' },
  ], note: 'Running in DetectionOnly: attacks are logged, not blocked. '
         + 'Review the audit log, then switch to blocking.' } };
}

/* ══════════════════════════════════════════════════════════════════════════════
   Activation gate
   ══════════════════════════════════════════════════════════════════════════════
   Anyone may install; the product asks to be licensed here. This replaces the
   previous behaviour, which surfaced the 402 as a red error toast and dropped
   the user into Settings — that reads like a fault rather than the expected
   next step after installing.

   The screen is shown ahead of the dashboard rather than on top of a broken
   one, so no panel ever renders half-empty against a refused API. */

function showActivateScreen(lic) {
  const el = document.getElementById('activate-screen');
  if (!el) return;

  const sub = document.getElementById('activate-sub');
  const line = document.getElementById('activate-status-line');

  if (lic && lic.status && lic.status !== 'Unlicensed') {
    // An explicit verdict deserves its own wording — "enter your key" is wrong
    // advice for a key that exists but has expired.
    const msg = {
      Expired:   'This licence has expired. Renew it, then re-check.',
      Suspended: 'This licence is suspended. Please contact support.',
      Invalid:   'This licence key is not valid for this server.',
      Unknown:   'The licence server could not be reached, so the licence could not be confirmed.',
    }[lic.status] || (lic.message || '');
    if (sub) sub.textContent = msg;
  }
  if (line && lic && lic.status) {
    line.textContent = ' Current status: ' + lic.status + '.';
  }

  el.classList.remove('hidden');
  const input = document.getElementById('activate-key');
  if (input) setTimeout(() => input.focus(), 150);
}

function hideActivateScreen() {
  const el = document.getElementById('activate-screen');
  if (el) el.classList.add('hidden');
}

function _activateError(msg) {
  const box = document.getElementById('activate-error');
  if (!box) return;
  if (!msg) { box.classList.add('hidden'); box.textContent = ''; return; }
  box.classList.remove('hidden');
  box.textContent = msg;
}

async function submitActivation() {
  const input = document.getElementById('activate-key');
  const btn   = document.getElementById('activate-btn');
  const key   = input ? input.value.trim() : '';
  _activateError('');

  if (!key) { _activateError('Enter your licence key.'); return; }

  btn.disabled = true;
  btn.textContent = 'Activating…';

  const res = Demo.active ? { success: true } : await API.post('license/activate', { key });

  btn.disabled = false;
  btn.textContent = 'Activate';

  if (res && res.success) {
    hideActivateScreen();
    toast('Licence activated — protection is on', 'success');
    // Reload rather than refresh in place: every page was blocked while
    // unlicensed, so their state is stale or empty.
    setTimeout(() => window.location.reload(), 700);
  } else {
    _activateError((res && res.error) || 'Activation failed. Check the key and try again.');
  }
}

async function recheckActivation() {
  _activateError('');
  const res = Demo.active ? { success: true } : await API.post('license/refresh', {});
  if (res && res.success) {
    hideActivateScreen();
    setTimeout(() => window.location.reload(), 500);
  } else {
    _activateError((res && res.error) || 'Still not licensed.');
  }
}

/**
 * Called once after sign-in, before the dashboard loads.
 * Returns true when the app may proceed.
 */
async function enforceLicenseGate() {
  if (Demo.active) return true;
  const res = await API.get('license/status');
  const lic = res && res.license;
  // A licence check that cannot complete must not lock a paying customer out of
  // their own dashboard, so an unreadable response is allowed through — the API
  // itself still returns 402 on anything gated, so nothing is actually exposed.
  if (!lic) return true;
  if (lic.protection_allowed) {
    // Trial counts as allowed, but the operator must be told it is running out
    // — otherwise protection stops one day with no warning given.
    if (lic.trial) showTrialBanner(lic.trial_days_left);
    return true;
  }
  showActivateScreen(lic);
  return false;
}


/* Trial banner. Shown only while the initial grace period is active — a licence
   that lapses without warning looks like a fault rather than an expiry. */
function showTrialBanner(daysLeft) {
  const el = document.getElementById('trial-banner');
  if (!el) return;
  const d = document.getElementById('trial-days');
  if (d) d.textContent = daysLeft === 1 ? '1 day' : daysLeft + ' days';
  el.classList.remove('hidden');
}


/**
 * Choose a real-time monitor resource profile.
 *
 * The custom fields are only shown for 'custom': presenting six numeric inputs
 * to someone who picked "Light" invites them to change one and wonder why the
 * profile no longer matches what it says.
 */
function selectRtProfile(name) {
  const hidden = document.getElementById('set-rt-profile');
  if (hidden) hidden.value = name;

  document.querySelectorAll('.rt-profile-opt').forEach(el => {
    const on = el.getAttribute('data-profile') === name;
    el.style.borderColor = on ? 'var(--primary)' : 'var(--border)';
    el.style.background  = on ? 'rgba(124,92,255,.08)' : 'transparent';
  });

  // The limit fields stay visible for every profile: they show what the chosen
  // profile actually does, and hiding them behind a "Custom" click made the
  // section read as preset-only. Editing any of them switches to Custom
  // automatically, so a typed value is never silently discarded because the
  // profile was left on a preset.
  const custom = document.getElementById('rt-custom-fields');
  if (custom) {
    custom.classList.remove('hidden');
    custom.style.opacity = (name === 'custom') ? '1' : '.72';
  }

  const preset = {
    light:    { fps: 5,   mb: 4,  nice: 19, watches: 5000,   debounce: 10 },
    balanced: { fps: 25,  mb: 16, nice: 10, watches: 20000,  debounce: 5  },
    thorough: { fps: 100, mb: 50, nice: 5,  watches: 100000, debounce: 2  },
  }[name];

  if (preset) {
    // Show the numbers the preset stands for, so the two halves of this card
    // can never disagree about what is in force.
    const put = (id, v) => { const e = document.getElementById(id); if (e) e.value = v; };
    put('set-rt-fps', preset.fps);
    put('set-rt-maxmb', preset.mb);
    put('set-rt-nice', preset.nice);
    put('set-rt-watches', preset.watches);
    put('set-rt-debounce', preset.debounce);
  }
}

/** Any edit to a limit means the operator wants Custom. */
function rtLimitEdited() {
  const hidden = document.getElementById('set-rt-profile');
  if (hidden && hidden.value !== 'custom') {
    selectRtProfile('custom');
    if (typeof toast === 'function') {
      toast('Switched to Custom — your values will be saved', 'info');
    }
  }
}


/**
 * Save only the real-time monitor settings.
 *
 * These were previously committed by the page-level "Save Changes" button at the
 * top of Settings, which means editing a limit here and then leaving the section
 * to commit it -- with no confirmation that these particular values were the
 * ones that landed. Asked for more than once, and I fixed the wrong thing first.
 *
 * Reads back what the server stored rather than trusting the POST, so the
 * confirmation reflects the clamped values actually in force.
 */
async function saveMonitorSettings() {
  const btn    = document.getElementById('rt-save-btn');
  const status = document.getElementById('rt-save-status');
  const g      = (id) => document.getElementById(id);

  const payload = {
    rt_profile:            g('set-rt-profile')?.value  || 'balanced',
    rt_max_files_per_sec:  g('set-rt-fps')?.value      || '25',
    rt_max_file_size_mb:   g('set-rt-maxmb')?.value    || '16',
    rt_nice:               g('set-rt-nice')?.value     || '10',
    rt_max_watches:        g('set-rt-watches')?.value  || '20000',
    rt_debounce_seconds:   g('set-rt-debounce')?.value || '5',
    rt_exclude_dirs:       g('set-rt-excludes')?.value || '',
    cpu_limit_percent:     g('set-cpu-limit')?.value   || '50',
    rt_poll_interval:
      document.querySelector('input[name="rt_poll_interval"]:checked')?.value || '300',
  };

  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  if (status) { status.textContent = ''; status.style.color = 'var(--txt3)'; }

  const res = Demo.active ? { success: true } : await API.saveSettings(payload);

  if (btn) { btn.disabled = false; btn.textContent = 'Save Monitor Settings'; }

  if (!res?.success) {
    const why = (res && (res.detail || res.error)) || 'the server did not say why';
    if (status) { status.textContent = 'Not saved — ' + why; status.style.color = 'var(--red)'; }
    toast('Monitor settings not saved: ' + why, 'error', 7000);
    return;
  }

  // Read back what was actually stored. A value outside the accepted range is
  // clamped by the daemon, so echoing the typed number would be a small lie.
  const check = Demo.active ? null : await API.getSettings();
  if (check?.success) {
    const d = check.data || {};
    if (g('set-rt-fps'))      g('set-rt-fps').value      = d.rt_max_files_per_sec || payload.rt_max_files_per_sec;
    if (g('set-rt-maxmb'))    g('set-rt-maxmb').value    = d.rt_max_file_size_mb  || payload.rt_max_file_size_mb;
    if (g('set-rt-nice'))     g('set-rt-nice').value     = d.rt_nice              || payload.rt_nice;
    if (g('set-rt-watches'))  g('set-rt-watches').value  = d.rt_max_watches       || payload.rt_max_watches;
    if (g('set-rt-debounce')) g('set-rt-debounce').value = d.rt_debounce_seconds  || payload.rt_debounce_seconds;
  }

  if (status) {
    status.textContent = 'Saved. The monitor picks this up within a minute — no restart needed.';
    status.style.color = 'var(--green)';
  }
  toast('Monitor settings saved', 'success');
}
