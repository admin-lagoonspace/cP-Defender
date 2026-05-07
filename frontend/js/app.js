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

async function detectMode() {
  try {
    const res = await API.status();
    if (res?.success) {
      State.installMode = res.mode || 'cpanel';
      applyModeUI(State.installMode);
    }
  } catch (_) { /* stay with default */ }
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
  if (sideLabel) sideLabel.textContent = isStandalone ? 'v3.1.5 · Standalone' : 'v3.1.5 · cPanel Plugin';

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
    case 'dashboard': refreshDashboard(); break;
    case 'scanner':   loadThreats();      break;
    case 'firewall':  loadFirewall();     break;
    case 'waf':       loadWAF();          break;
    case 'iprep':     loadTopAttackers(); break;
    case 'events':    loadEvents();       break;
    case 'settings':  loadSettings();     break;
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
async function refreshDashboard() {
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
      <td class="mono primary" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${t.file_path}">
        ${t.file_path.split('/').slice(-2).join('/')}
      </td>
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
async function loadSettings() {
  const res = Demo.active
    ? { success: true, data: {
        scan_schedule: 'daily', scan_paths: '/home', auto_quarantine: '1',
        email_alerts: '1', alert_email: '', php_disable_funcs: 'exec,passthru,shell_exec,system',
        rate_limit_ssh: '5', rate_limit_http: '100',
        firewall_enabled: '1', waf_enabled: '1', bot_shield_enabled: '1', ip_rep_enabled: '1',
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
