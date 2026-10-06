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
    // Room at the top for the value labels, which sit above their points.
    const PAD = { top: 20, right: 14, bottom: 30, left: 44 };
    const cW  = W - PAD.left - PAD.right;
    const cH  = H - PAD.top  - PAD.bottom;

    const allVals = datasets.flatMap(d => d.values);
    const mx = Math.max(...allVals, 1);

    const ptX = i => PAD.left + (i / (data.length - 1)) * cW;
    const ptY = v  => PAD.top  + cH - (v / mx) * cH * 0.9;

    // Thousands separators: an unseparated 97400 beside a 3174 is hard to
    // compare at a glance, which is the whole point of putting it there.
    const fmt = v => Number(v).toLocaleString();

    let svg = '';

    // Grid lines + Y labels
    for (let i = 0; i <= 4; i++) {
      const y = PAD.top + (i / 4) * cH;
      const val = Math.round(mx * (1 - i / 4) * 0.9);
      svg += `<line x1="${PAD.left}" y1="${y}" x2="${W - PAD.right}" y2="${y}"
                stroke="#1e293b" stroke-width="1"/>`;
      svg += `<text x="${PAD.left - 6}" y="${y + 4}" text-anchor="end"
                font-size="10" fill="#475569" font-family="monospace">${fmt(val)}</text>`;
    }

    // Y axis
    svg += `<line x1="${PAD.left}" y1="${PAD.top}" x2="${PAD.left}" y2="${PAD.top+cH}"
              stroke="#1e2d4e" stroke-width="1"/>`;

    // X labels (every 5th day)
    data.forEach((d, i) => {
      if (i % 5 === 0 || i === data.length - 1) {
        const x = ptX(i);
        const label = String(d).slice(5); // MM-DD
        svg += `<text x="${x}" y="${H - 4}" text-anchor="middle"
                  font-size="10" fill="#475569" font-family="monospace">${label}</text>`;
      }
    });

    // Which points carry a printed value.
    //
    // Not all of them: thirty days times three series is ninety labels on one
    // small chart, which is less readable than none. The rule is the points
    // that tell you something -- the regularly spaced ones, the final one, and
    // each series' own peak -- and never a zero, because a flat line of "0 0 0
    // 0 0" is noise that hides the numbers that matter.
    const labelled = datasets.map(({ values }) => {
      const keep = new Set();
      values.forEach((v, i) => {
        if (v > 0 && (i % 5 === 0 || i === values.length - 1)) { keep.add(i); }
      });
      const peak = values.indexOf(Math.max(...values));
      if (values[peak] > 0) { keep.add(peak); }
      return keep;
    });

    // Dataset lines
    datasets.forEach(({ values, color }, di) => {
      const points = values.map((v, i) => `${ptX(i)},${ptY(v)}`).join(' ');
      svg += `<polyline points="${points}" fill="none" stroke="${color}"
                stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"
                vector-effect="non-scaling-stroke"/>`;

      values.forEach((v, i) => {
        const isDot = i % 5 === 0 || i === values.length - 1 || labelled[di].has(i);
        if (!isDot) return;
        svg += `<circle cx="${ptX(i)}" cy="${ptY(v)}" r="3.5"
                  fill="${color}" stroke="#0f172a" stroke-width="1.5"/>`;
      });
    });

    // Value labels, drawn after every line so nothing is painted over them.
    //
    // Series are offset from each other at the same date: two numbers at the
    // same place would overlap into something unreadable, and the whole reason
    // they are here is to be read.
    // Placed labels, so a new one can be moved clear of the ones already
    // down. Offsetting by series index alone is not enough: two series at
    // ADJACENT dates with similar values collide, which is how "120" and "58"
    // ended up printed on top of each other.
    const placed = [];
    const hits = (x, y, w) => placed.some(q =>
      Math.abs(q.x - x) < (q.w + w) / 2 + 3 && Math.abs(q.y - y) < 12);

    datasets.forEach(({ values, color }, di) => {
      values.forEach((v, i) => {
        if (!labelled[di].has(i)) return;

        const x = ptX(i);
        const text = fmt(v);
        // Monospace at this size is close enough to 6.3px a glyph for
        // collision purposes; being a pixel out only costs a little spacing.
        const w = text.length * 6.3;

        let y = ptY(v) - 8;
        let tries = 0;
        while (hits(x, y, w) && tries < 6) { y -= 12; tries++; }
        // Out of room above: go below the point instead and try again there.
        if (y < 10) {
          y = ptY(v) + 16;
          tries = 0;
          while (hits(x, y, w) && tries < 4) { y += 12; tries++; }
        }
        placed.push({ x, y, w });

        // Nudge the ends inward so a label is not clipped by the edge.
        const anchor = i === 0 ? 'start'
                     : (i === values.length - 1 ? 'end' : 'middle');

        // paint-order puts the dark stroke behind the glyphs, so a number
        // sitting on a grid line or another series stays legible.
        svg += `<text x="${x}" y="${y}" text-anchor="${anchor}"
                  font-size="10.5" font-weight="700" font-family="monospace"
                  fill="${color}" stroke="#0b1220" stroke-width="3"
                  paint-order="stroke" style="pointer-events:none">${fmt(v)}</text>`;
      });
    });

    // One hover target per day, carrying every series' value for that date.
    // The printed labels cover the notable points; this covers all the rest
    // without putting ninety numbers on the chart.
    const band = cW / Math.max(1, data.length - 1);
    data.forEach((d, i) => {
      const lines = datasets
        .map(ds => `${ds.label || 'series'}: ${fmt(ds.values[i] ?? 0)}`)
        .join('\n');
      svg += `<rect x="${ptX(i) - band / 2}" y="${PAD.top}" width="${band}" height="${cH}"
                fill="transparent"><title>${d}\n${lines}</title></rect>`;
    });

    // innerHTML, not outerHTML.
    //
    // Replacing the element discarded its id, so every later refresh looked
    // the chart up by id, found nothing, and silently did nothing -- the
    // dashboard has been showing whatever was true when the page first loaded.
    svgEl.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svgEl.style.width    = '100%';
    svgEl.style.height   = `${H}px`;
    svgEl.style.overflow = 'visible';
    svgEl.innerHTML = svg;
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
