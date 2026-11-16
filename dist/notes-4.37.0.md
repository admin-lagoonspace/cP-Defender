# ServerScrub 4.37.0

[4.37.0] - 2026-11-16

### Added

- **`cpu_limit_percent` is now an actual ceiling, not a priority.** It mapped
  to a `nice` value and nothing else, and `nice` caps nothing — it decides who
  yields when processes *compete*. On the production server:

  ```
  PID 781423 root 39 19 1136888 983912 R 97.0 1.6 0:13.26 clamscan
  ```

  `NI 19` — the floor — holding 97% of a core with 44.8% of the machine idle,
  and `scan_max_concurrent` already at 1. Both levers the product had were at
  their stops, and neither of them was a ceiling. A setting that says "50%"
  and cannot enforce 50% is a promise nothing is keeping.

  Each clamscan batch now runs in a transient cgroup scope
  (`systemd-run --scope -p CPUQuota=N%`), which the kernel enforces whether
  the box is busy or idle. `CPUWeight`/`IOWeight` are set low as well, so a
  capped scan still loses to real work — the quota alone would let it hold its
  full share against a busy server. `nice` and `ionice` are kept: the quota is
  the ceiling, `nice` is the yielding, and they answer different questions.

  **On by default**, because the setting already claimed to be a limit.
  Scans take longer with it on; the toggle is in the new Resource Usage card.

  The mechanism is *proven* before use, by running `/bin/true` under it and
  caching the result — `systemd-run` exists on every systemd host and still
  fails without root or where the cgroup hierarchy refuses `CPUQuota`, and a
  prefix that fails is a scan that does not run. Hosts that refuse it fall
  back to `cpulimit`, then to `nice` alone, exactly as before. **The card says
  which of the three is in force**, in those words, rather than showing a
  percentage next to a mechanism that caps nothing.

- **Resource-usage controls on the Real-Time Monitor page.** The limits were
  already settable and already enforced — in Settings, several screens from the
  page an operator is looking at when they decide the monitor is costing too
  much. Being asked "how much of this server may it take?" and having to leave
  the page to answer is the complaint, so the controls are now beside what they
  govern: the four profiles (Light / Balanced / Thorough / Custom), the six
  individual limits, and the CPU ceiling that governs the on-demand and
  scheduled scanners as well as the monitor.

  The row along the top reports what the **daemon** says is in force, not what
  the settings say. Those differ for up to a minute after a save, because the
  daemon re-reads its limits on a cycle, and permanently when a value was out
  of range and got clamped. It also shows the watch count against the ceiling
  and says plainly when the kernel has refused more watches — that state is
  partial coverage, and it used to render as a healthy monitor.

  Saving reads the stored values back rather than echoing what was typed, so a
  clamped number is shown as what it became.

### Fixed

- **The daemon published only two of the limits it was enforcing.** The panel
  could infer nice, the watch ceiling, the file-size cap and the debounce
  window from the profile *name*, which works for a preset and says nothing at
  all for `custom` — the one case where the operator typed the numbers and most
  needs them confirmed. `monitor.py` now publishes all of them and
  `RealTimeMonitor::status()` exposes them.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
