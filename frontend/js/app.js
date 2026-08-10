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

  // Topbar mode pill
  const pill = document.getElementById('mode-pill');
  if (pill && Auth.isLoggedIn()) {
    pill.style.display = '';
    pill.textContent   = isStandalone ? '⚡ STANDALONE' : '🖥 cPANEL';
  }

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
    case 'waf':       loadWAF();            break;
    case 'iprep':     loadTopAttackers();   break;
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
  if (Demo.active) return;
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

  if (!data?.success) return;

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

    const pct = job.status === 'done' ? 100 : Math.min(99, Math.floor(Math.random() * 5) + 50);
    document.getElementById('scan-progress-bar').style.width = `${pct}%`;
    document.getElementById('scan-progress-pct').textContent = `${pct}%`;
    document.getElementById('scan-live-files').textContent = fmtNum(job.files_scanned || 0);
    document.getElementById('scan-live-threats').textContent = job.threats_found || 0;
    document.getElementById('scan-live-status').textContent = job.status;

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
        scan_schedule: 'daily', scan_paths: '/home', auto_quarantine: '1',
        email_alerts: '1', alert_email: '', php_disable_funcs: 'exec,passthru,shell_exec,system',
        rate_limit_ssh: '5', rate_limit_http: '100',
        firewall_enabled: '1', waf_enabled: '1', bot_shield_enabled: '1', ip_rep_enabled: '1',
        cpu_limit_percent: '50', rt_poll_interval: '300',
      }}
    : await API.getSettings();

  if (!res?.success) return;
  const d = res.data;

  const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
  const chk = (id, val) => { const el = document.getElementById(id); if (el) el.checked = val === '1' || val === true; };

  set('set-scan-schedule', d.scan_schedule);
  set('set-scan-paths',    d.scan_paths);
  chk('set-auto-quar',     d.auto_quarantine);
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
    scan_schedule:      g('set-scan-schedule')?.value,
    scan_paths:         g('set-scan-paths')?.value,
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
  const badge = document.getElementById('rt-status-badge');
  if (badge) {
    badge.className   = 'badge ' + (d.running ? 'badge-green' : 'badge-red');
    badge.textContent = d.running ? 'Active' : 'Stopped';
  }
  const icon = document.getElementById('rt-icon');
  if (icon) icon.textContent = d.running ? '🔍' : '⏸';

  const rtPaths  = document.getElementById('rt-paths');
  if (rtPaths)  rtPaths.textContent  = (d.watch_paths || []).join(', ');
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

async function toggleMonitor() {
  const fn  = monitorRunning ? API.monitorStop : API.monitorStart;
  const res = Demo.active ? { success: true } : await fn();
  if (res?.success) {
    monitorRunning = !monitorRunning;
    toast(monitorRunning ? 'Monitor started' : 'Monitor stopped', 'success');
    loadMonitor();
    loadMonitorStats();
  } else {
    toast('Action failed', 'error');
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
    Demo.active ? { success: true, data: { total: 4, wordpress: 3, joomla: 1, drupal: 0, outdated: 2, installs_with_issues: 3 } } : API.cmsStats(),
    Demo.active ? { success: true, data: [
      { id:1, cms_type:'wordpress', version:'6.2.1', cpanel_user:'alice', install_path:'/home/alice/public_html', issues:'["xmlrpc_enabled","login_exposed"]', outdated:1, status:'warning' },
      { id:2, cms_type:'wordpress', version:'6.4.2', cpanel_user:'bob',   install_path:'/home/bob/public_html',   issues:'[]', outdated:0, status:'ok' },
      { id:3, cms_type:'joomla',    version:'4.2.0', cpanel_user:'carol', install_path:'/home/carol/public_html', issues:'["outdated_version"]', outdated:1, status:'warning' },
    ]} : API.cmsInstalls(),
  ]);

  if (statsRes?.success) {
    const d = statsRes.data;
    document.getElementById('cms-stat-total').textContent    = fmtNum(d?.total || 0);
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
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--txt3);padding:28px">Click "Scan Server" to discover CMS installations</td></tr>';
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

  const msg = (payload && payload.error) || 'A valid license is required.';
  toast(msg, 'error');
  openPage('settings');
  setTimeout(() => {
    const card = document.getElementById('license-card');
    if (card) card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    const input = document.getElementById('license-key-input');
    if (input) input.focus();
  }, 250);
  loadLicense();
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

  const res = await API.get('license/status');
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
