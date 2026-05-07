/**
 * Sentinel Gate — API Client
 * Thin fetch wrapper around the PHP REST API
 */

const API = (() => {
  const BASE = './backend/api';

  function token() {
    return localStorage.getItem('sg_token') || '';
  }

  async function req(method, path, data = null) {
    const opts = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token()}`,
      },
    };
    if (data && method !== 'GET') opts.body = JSON.stringify(data);

    const url = BASE + '/' + path.replace(/^\//, '');
    try {
      const r = await fetch(url, opts);
      const json = await r.json();
      if (r.status === 401) {
        // Token expired — go back to login
        Auth.logout();
      }
      return json;
    } catch (e) {
      console.error('API error:', e);
      return { success: false, error: e.message };
    }
  }

  return {
    get:    (path)        => req('GET',    path),
    post:   (path, data)  => req('POST',   path, data),
    put:    (path, data)  => req('PUT',    path, data),
    delete: (path)        => req('DELETE', path),

    // Auth
    login:          (username, password) => req('POST', 'auth/login',           { username, password }),
    status:         ()                   => req('GET',  'auth/status'),
    changePassword: (username, password) => req('POST', 'auth/change-password', { username, password }),

    // Dashboard
    dashStats: ()  => req('GET', 'dashboard/stats'),

    // Scanner
    startScan:        (path, type)  => req('POST',   'scanner/start', { path, type }),
    scanStatus:       (jobId)       => req('GET',    `scanner/status/${jobId}`),
    scanStats:        ()            => req('GET',    'scanner/stats'),
    threats:          (status)      => req('GET',    `scanner/threats${status ? '?status='+status : ''}`),
    quarantineThreat: (id)          => req('POST',   `scanner/quarantine/${id}`, {}),
    restoreThreat:    (id)          => req('POST',   `scanner/restore/${id}`, {}),
    deleteThreat:     (id)          => req('DELETE', `scanner/delete/${id}`),
    updateSigs:       ()            => req('POST',   'scanner/update-sigs', {}),

    // Firewall
    fwStats:      ()           => req('GET',  'firewall/stats'),
    fwRules:      ()           => req('GET',  'firewall/rules'),
    fwBlocked:    ()           => req('GET',  'firewall/blocked'),
    fwBlockIP:    (ip, reason, permanent) => req('POST', 'firewall/block', { ip, reason, permanent }),
    fwUnblockIP:  (ip)         => req('POST', 'firewall/unblock', { ip }),
    fwAllowIP:    (ip, comment)=> req('POST', 'firewall/allow', { ip, comment }),
    fwAddRule:    (rule)       => req('POST', 'firewall/add-rule', rule),
    fwToggleRule: (id, enabled)=> req('POST', 'firewall/toggle-rule', { id, enabled }),
    fwDeleteRule: (id)         => req('DELETE',`firewall/delete-rule/${id}`),
    fwReload:     ()           => req('POST', 'firewall/reload', {}),
    fwGeoBlock:   (countries)  => req('POST', 'firewall/geo-block', { countries }),

    // WAF
    wafStatus:    ()           => req('GET',  'waf/status'),
    wafStats:     ()           => req('GET',  'waf/stats'),
    wafEvents:    (sev)        => req('GET',  `waf/events${sev ? '?severity='+sev : ''}`),
    wafCats:      ()           => req('GET',  'waf/categories'),
    wafSetMode:   (mode)       => req('POST', 'waf/set-mode', { mode }),

    // IP Reputation
    ipCheck:      (ip)         => req('GET',  `iprep/check?ip=${encodeURIComponent(ip)}`),
    ipTopAttack:  ()           => req('GET',  'iprep/top-attackers'),

    // Events
    events:       (sev)        => req('GET',  `events/list${sev ? '?severity='+sev : ''}`),
    resolveEvent: (id)         => req('POST', `events/resolve?id=${id}`, {}),

    // Settings
    getSettings:  ()           => req('GET',  'settings/get'),
    saveSettings: (data)       => req('POST', 'settings/set', data),

    // Real-Time Monitor
    monitorStatus:        ()       => req('GET',  'monitor/status'),
    monitorStats:         ()       => req('GET',  'monitor/stats'),
    monitorStart:         ()       => req('POST', 'monitor/start',          {}),
    monitorStop:          ()       => req('POST', 'monitor/stop',           {}),
    monitorRestart:       ()       => req('POST', 'monitor/restart',        {}),
    monitorDetections:    (limit)  => req('GET',  `monitor/detections?limit=${limit||50}`),
    monitorLogs:          (lines)  => req('GET',  `monitor/logs?lines=${lines||100}`),
    monitorAddPath:       (path)   => req('POST', 'monitor/add-path',       { path }),
    monitorRemovePath:    (path)   => req('POST', 'monitor/remove-path',    { path }),
    monitorInstallService:()       => req('POST', 'monitor/install-service', {}),

    // Storage Management
    storageStats:        ()       => req('GET',  'storage/stats'),
    storagePrune:        ()       => req('POST', 'storage/prune',          {}),
    storageSaveSettings: (data)   => req('POST', 'storage/save-settings',  data),
  };
})();

// Extend Demo mode with monitor mock
Object.assign(Demo, {
  mockMonitorStatus() {
    return {
      success: true,
      data: {
        running:        true,
        pid:            12847,
        engine:         'inotify',
        watch_paths:    ['/home', '/var/www', '/tmp'],
        files_checked:  284930,
        threats_found:  3,
        detections_24h: 2,
        detections_all: 3,
        service_active: true,
      }
    };
  },

  mockMonitorDetections() {
    return { success: true, data: [
      { id:10, file_path:'/home/user1/public_html/wp-content/uploads/image.php', threat_name:'SG.RT.c99_shell',      severity:'critical', status:'quarantined', detected_at: Date.now()/1000 - 1800 },
      { id:11, file_path:'/home/user2/public_html/tmp/update.php',               threat_name:'SG.RT.eval_base64',    severity:'high',     status:'active',      detected_at: Date.now()/1000 - 5400 },
      { id:12, file_path:'/home/user3/public_html/assets/thumb.php',             threat_name:'SG.RT.backdoor_connect',severity:'critical', status:'quarantined', detected_at: Date.now()/1000 - 86400 },
    ]};
  }
});

// Demo mode: returns realistic mock data when API isn't available
const Demo = {
  active: false,

  mockDashStats() {
    const rand = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
    return {
      success: true,
      scanner: {
        total_threats: 47, active: 12, quarantined: 32, files_scanned: 1284930,
        last_scan: { status: 'done', finished_at: Date.now()/1000 - 7200, files_scanned: 1284930, threats_found: 3 },
        by_type: [
          { threat_type: 'webshell',    count: 18 },
          { threat_type: 'obfuscated',  count: 14 },
          { threat_type: 'malware',     count:  9 },
          { threat_type: 'backdoor',    count:  6 },
        ]
      },
      firewall: { blocked_ips: 382, active_rules: 14, blocked_today: 8241 },
      waf:      { total_events: 94441, events_today: 3221 },
      events: [
        { id:1, severity:'critical', type:'SQL Injection',    source_ip:'185.220.101.47', target:'/wp-admin/login', description:'SQLi attempt blocked', timestamp: Date.now()/1000 - 120,  resolved:0 },
        { id:2, severity:'high',     type:'Brute Force SSH',  source_ip:'45.33.32.156',   target:'server:22',       description:'32 failed SSH attempts', timestamp: Date.now()/1000 - 300,  resolved:0 },
        { id:3, severity:'high',     type:'Malware Upload',   source_ip:'192.168.200.1',  target:'/uploads/',       description:'PHP webshell detected',  timestamp: Date.now()/1000 - 720,  resolved:0 },
        { id:4, severity:'medium',   type:'XSS Attempt',      source_ip:'104.21.15.98',   target:'/contact.php',    description:'XSS payload in form',    timestamp: Date.now()/1000 - 1440, resolved:0 },
        { id:5, severity:'medium',   type:'Suspicious Scan',  source_ip:'198.51.100.23',  target:'All ports',       description:'Port scan detected',     timestamp: Date.now()/1000 - 1860, resolved:1 },
        { id:6, severity:'low',      type:'Invalid Token',    source_ip:'203.0.113.47',   target:'/api/v1/auth',    description:'Invalid JWT token',      timestamp: Date.now()/1000 - 2700, resolved:1 },
      ],
      timeline: Array.from({length:30}, (_,i) => ({
        date: new Date(Date.now() - (29-i)*86400000).toISOString().slice(0,10),
        waf_blocks:  rand(20,95),
        brute_force: rand(5, 40),
        malware:     rand(0, 12),
      })),
      server: { hostname: 'demo-server.example.com', php_version: '8.2.14', load: [0.42, 0.38, 0.31] }
    };
  },

  mockThreats() {
    return { success: true, data: [
      { id:1, file_path:'/home/user1/public_html/wp-content/uploads/shell.php',   threat_name:'SG.PHP.c99_shell',        threat_type:'webshell',   severity:'critical', status:'active',      size:24880, detected_at: Date.now()/1000 - 7200 },
      { id:2, file_path:'/home/user2/public_html/config.php',                     threat_name:'SG.PHP.eval_base64',      threat_type:'obfuscated', severity:'high',     status:'quarantined', size:3120,  detected_at: Date.now()/1000 - 14400 },
      { id:3, file_path:'/home/user1/public_html/images/thumb.php',               threat_name:'SG.PHP.backdoor_connect', threat_type:'backdoor',   severity:'critical', status:'active',      size:1820,  detected_at: Date.now()/1000 - 21600 },
      { id:4, file_path:'/home/user3/public_html/wp-includes/class-cache.php',    threat_name:'SG.PHP.xmrig_pattern',    threat_type:'cryptominer', severity:'high',    status:'deleted',     size:8940,  detected_at: Date.now()/1000 - 86400 },
      { id:5, file_path:'/home/user2/public_html/wp-admin/includes/media.php',    threat_name:'SG.PHP.eval_gzinflate',   threat_type:'obfuscated', severity:'medium',   status:'active',      size:2340,  detected_at: Date.now()/1000 - 3600 },
    ]};
  },

  mockFWRules() {
    return { success: true, data: [
      { id:1,  name:'ALLOW_SSH',          direction:'in',  protocol:'tcp', port:'22',   action:'ACCEPT', enabled:1, hits:98441 },
      { id:2,  name:'ALLOW_HTTP',         direction:'in',  protocol:'tcp', port:'80',   action:'ACCEPT', enabled:1, hits:284441 },
      { id:3,  name:'ALLOW_HTTPS',        direction:'in',  protocol:'tcp', port:'443',  action:'ACCEPT', enabled:1, hits:312002 },
      { id:4,  name:'ALLOW_cPanel',       direction:'in',  protocol:'tcp', port:'2082', action:'ACCEPT', enabled:1, hits:8821 },
      { id:5,  name:'BLOCK_NULL_PACKETS', direction:'in',  protocol:'tcp', port:null,   action:'DROP',   enabled:1, hits:14221 },
      { id:6,  name:'RATE_LIMIT_SSH',     direction:'in',  protocol:'tcp', port:'22',   action:'LIMIT',  enabled:1, hits:3892 },
      { id:7,  name:'GEO_BLOCK_HIGH',     direction:'in',  protocol:'tcp', port:null,   action:'DROP',   enabled:1, hits:22104 },
    ]};
  },

  mockWAFStats() {
    return { success: true, data: {
      total_events: 94441, events_today: 3221,
      by_severity: [
        { severity:'error',   count: 1240 },
        { severity:'warning', count: 4821 },
        { severity:'notice',  count: 9820 },
      ],
      top_rules: [
        { rule_id:'942100', rule_msg:'SQL Injection Attack via libinjection', hits: 2841 },
        { rule_id:'941100', rule_msg:'XSS Attack Detected via libinjection',  hits: 1920 },
        { rule_id:'913100', rule_msg:'Found User-Agent associated with scanner', hits: 1204 },
        { rule_id:'932160', rule_msg:'Remote Command Execution',              hits:  892 },
      ],
      top_ips: [
        { ip_address:'185.220.101.47', hits:3421 },
        { ip_address:'45.33.32.156',   hits:2889 },
      ]
    }};
  },

  mockIPAttackers() {
    return { success: true, data: [
      { ip_address:'185.220.101.47', country:'RU', score:98, rbl_hits:'["spamhaus","sorbs"]', hits:3421, last_seen: Date.now()/1000 - 120 },
      { ip_address:'45.33.32.156',   country:'CN', score:91, rbl_hits:'["spamhaus"]',          hits:2889, last_seen: Date.now()/1000 - 300 },
      { ip_address:'192.168.200.1',  country:'UA', score:74, rbl_hits:'["barracuda"]',          hits:1204, last_seen: Date.now()/1000 - 720 },
      { ip_address:'104.21.15.98',   country:'BR', score:55, rbl_hits:'[]',                    hits: 987, last_seen: Date.now()/1000 - 1440 },
      { ip_address:'198.51.100.23',  country:'DE', score:38, rbl_hits:'[]',                    hits: 442, last_seen: Date.now()/1000 - 3600 },
    ]};
  }
};
