/**
 * Sentinel Gate — SVG Chart Library
 * Pure SVG, no dependencies
 */

const Charts = {

  /**
   * Sparkline — tiny inline line chart for stat cards
   */
  sparkline(svgEl, data, color) {
    if (!svgEl) return;
    if (!data?.length) {
      // An SVG cannot hold a message, so clear it and let the caller's empty
      // state show instead of leaving a stale or blank chart.
      svgEl.innerHTML = '';
      const holder = svgEl.parentElement;
      if (holder && holder.dataset.emptyMessage) {
        this.empty(holder, holder.dataset.emptyMessage);
      }
      return;
    }
    const W = svgEl.clientWidth || 160;
    const H = 28;
    const mx = Math.max(...data);
    const mn = Math.min(...data);
    const rng = mx - mn || 1;

    const pts = data.map((v, i) => {
      const x = (i / (data.length - 1)) * W;
      const y = H - ((v - mn) / rng) * (H - 4) - 2;
      return `${x},${y}`;
    });

    svgEl.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svgEl.innerHTML = `
      <polyline
        points="${pts.join(' ')}"
        fill="none"
        stroke="${color}"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
        vector-effect="non-scaling-stroke"
      />`;
  },

  /**
   * Multi-line timeline chart
   */
  timeline(svgEl, data, datasets) {
    if (!svgEl) return;
    if (!data?.length) {
      // An SVG cannot hold a message, so clear it and let the caller's empty
      // state show instead of leaving a stale or blank chart.
      svgEl.innerHTML = '';
      const holder = svgEl.parentElement;
      if (holder && holder.dataset.emptyMessage) {
        this.empty(holder, holder.dataset.emptyMessage);
      }
      return;
    }
    const W   = svgEl.clientWidth  || 900;
    const H   = 180;
    const PAD = { top: 10, right: 10, bottom: 30, left: 40 };
    const cW  = W - PAD.left - PAD.right;
    const cH  = H - PAD.top  - PAD.bottom;

    const allVals = datasets.flatMap(d => d.values);
    const mx = Math.max(...allVals, 1);

    const ptX = i => PAD.left + (i / (data.length - 1)) * cW;
    const ptY = v  => PAD.top  + cH - (v / mx) * cH * 0.9;

    let svg = `<svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg"
                 style="width:100%;height:${H}px;overflow:visible">`;

    // Grid lines + Y labels
    for (let i = 0; i <= 4; i++) {
      const y = PAD.top + (i / 4) * cH;
      const val = Math.round(mx * (1 - i / 4) * 0.9);
      svg += `<line x1="${PAD.left}" y1="${y}" x2="${W - PAD.right}" y2="${y}"
                stroke="#1e293b" stroke-width="1"/>`;
      svg += `<text x="${PAD.left - 6}" y="${y + 4}" text-anchor="end"
                font-size="10" fill="#475569" font-family="monospace">${val}</text>`;
    }

    // Y axis
    svg += `<line x1="${PAD.left}" y1="${PAD.top}" x2="${PAD.left}" y2="${PAD.top+cH}"
              stroke="#1e2d4e" stroke-width="1"/>`;

    // X labels (every 5th day)
    data.forEach((d, i) => {
      if (i % 5 === 0 || i === data.length - 1) {
        const x = ptX(i);
        const label = d.slice(5); // MM-DD
        svg += `<text x="${x}" y="${H - 4}" text-anchor="middle"
                  font-size="10" fill="#475569" font-family="monospace">${label}</text>`;
      }
    });

    // Dataset lines
    datasets.forEach(({ values, color, label }) => {
      const points = values.map((v, i) => `${ptX(i)},${ptY(v)}`).join(' ');
      svg += `<polyline points="${points}" fill="none" stroke="${color}"
                stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"
                vector-effect="non-scaling-stroke"/>`;

      // Dots every 5th
      values.forEach((v, i) => {
        if (i % 5 === 0 || i === values.length - 1) {
          svg += `<circle cx="${ptX(i)}" cy="${ptY(v)}" r="3.5"
                    fill="${color}" stroke="#0f172a" stroke-width="1.5"/>`;
        }
      });
    });

    svg += '</svg>';
    svgEl.outerHTML = svg;
  },

  /**
   * Say "nothing here" rather than leaving whatever was in the container.
   *
   * Every chart used to `return` on empty data, which leaves the static
   * "Loading…" placeholder in place for ever. A server with zero threats -- the
   * good outcome -- therefore displayed a panel that looked stuck loading, and
   * was reported as broken.
   */
  empty(container, message) {
    if (!container) return;
    container.innerHTML =
      '<div style="padding:22px 4px;text-align:center;color:var(--txt3);font-size:.8rem">'
      + message + '</div>';
  },

  /**
   * Horizontal bar chart for threat breakdown
   */
  threatBars(container, data) {
    if (!container) return;
    if (!data?.length) {
      return this.empty(container, 'No threats detected.');
    }
    const total = data.reduce((s, d) => s + d.count, 0) || 1;
    const colors = {
      webshell:    '#ef4444',
      obfuscated:  '#3b82f6',
      malware:     '#f59e0b',
      backdoor:    '#ef4444',
      cryptominer: '#22d3ee',
      phishing:    '#a855f7',
      spam:        '#6b7280',
      trojan:      '#f87171',
      suspicious:  '#60a5fa',
    };

    container.innerHTML = data.map(({ threat_type, count }) => {
      const pct  = Math.round((count / total) * 100);
      const col  = colors[threat_type] || '#60a5fa';
      const name = threat_type.replace(/_/g, ' ');
      return `
        <div style="margin-bottom:12px">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <span style="font-size:.78rem;text-transform:capitalize">${name}</span>
            <span style="font-size:.78rem;font-family:monospace;color:${col}">${count}</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width:${pct}%;background:${col}"></div>
          </div>
        </div>`;
    }).join('');
  },

  /**
   * WAF severity donut-like bars
   */
  wafSeverityBars(container, data) {
    if (!container) return;
    const colors = { critical:'#ef4444', error:'#f87171', warning:'#f59e0b', notice:'#60a5fa', unknown:'#6b7280' };
    const total = data.reduce((s, d) => s + d.count, 0) || 1;

    container.innerHTML = data.map(({ severity, count }) => {
      const pct = Math.round((count / total) * 100);
      const col = colors[severity] || '#60a5fa';
      return `
        <div style="margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;margin-bottom:3px">
            <span style="font-size:.75rem;text-transform:capitalize">${severity}</span>
            <span style="font-size:.75rem;font-family:monospace;color:${col}">${count.toLocaleString()}</span>
          </div>
          <div class="progress-bar" style="height:6px">
            <div class="progress-fill" style="width:${pct}%;background:${col}"></div>
          </div>
        </div>`;
    }).join('');
  },

  /**
   * IP risk score gauge (simple colored bar)
   */
  ipRiskGauge(score) {
    const col  = score >= 75 ? '#ef4444' : score >= 50 ? '#f59e0b' : score >= 25 ? '#60a5fa' : '#22c55e';
    const label = score >= 75 ? 'Critical' : score >= 50 ? 'High' : score >= 25 ? 'Medium' : 'Low';
    return `
      <div style="margin-bottom:8px;display:flex;justify-content:space-between">
        <span style="font-size:.78rem;color:var(--txt2)">Risk Score</span>
        <span style="font-size:.78rem;font-weight:700;color:${col}">${score}/100 — ${label}</span>
      </div>
      <div class="progress-bar" style="height:10px">
        <div class="progress-fill" style="width:${score}%;background:${col}"></div>
      </div>`;
  }
};
