# ServerScrub 4.9.0

[4.9.0] - 2026-10-20

Network-layer guards, so the built-in firewall covers what CSF covers rather
than being a fallback for it.

### Added

- **Port-scan detection.** A connection to a port nothing is listening on
  leaves a short-lived SYN_RECV entry and no established socket, so reading
  which ports one address has touched that are *not* in the local listening set
  separates a scan from traffic — a real client connects to the one port it
  wants. Default threshold: 10 distinct closed ports.

- **Connection flood limits.** Concurrent connections per source address, over
  a configurable ceiling (default 150). **Ports 80 and 443 are exempt by
  default and that is load-bearing:** a browser opens six connections per page,
  a corporate NAT or CDN presents hundreds of real users as one address, and
  this product's own dashboard is served over 443 — a flood limit there locks
  the operator out of the page they would need to turn it off.

- **Egress filtering**, off by default, with no automatic enable anywhere. A
  wrong *inbound* rule blocks visitors and you hear about it. A wrong
  *outbound* rule breaks the server's own updates, DNS, NTP, mail, licence
  checks and backups — quietly, usually at the next cron run. So it previews by
  default, refuses an empty allow-list, and **refuses any policy that does not
  allow port 53**, because without resolution nothing works and every
  downstream failure looks like something else.

### Notes

- **No new blocking path.** The detectors record into the brute-force table
  under their own service names, and `BruteForce::evaluate()` escalates them
  through the ladder that already exists (3h → 6h → 24h → permanent), honours
  the same whitelist, and `releaseExpired()` lets them go again. A second
  blocking path would mean a second set of rules about who must never be
  blocked — and that list includes the operator's own address and two
  JetBackup servers. A backup server opening dozens of parallel connections
  looks exactly like a flood, and losing backups to a false positive is worse
  than the attack being guarded against.

- **Clean-room, and the provenance is recorded in the source.** These
  capabilities exist in CSF (`PS_INTERVAL`, `CT_LIMIT`, `TCP_OUT`) and
  capabilities are not copyrightable; code is. CSF and both surviving forks are
  GPLv3, so deriving from them would make this product a derivative work and
  oblige it to ship under GPLv3 — incompatible with licensing it commercially.
  Everything here is written against the kernel's own interfaces: `/proc/net`,
  nftables and iptables. No CSF or CPGuard source was consulted.

- **It samples rather than watches**, on the scheduler's 15-minute tick. A
  continuous watcher means a daemon reading kernel connection state in a loop
  on a shared host, and an unbounded read of that is itself a performance
  incident — this server had one in October. A sample is sufficient: a scanner
  touching enough closed ports to matter is still mid-scan or in TIME_WAIT when
  the sample lands, and a flood persists by definition.

- **Refusing to guess.** If the local listening set cannot be read, every port
  looks closed and every ordinary visitor looks like a scanner. Rather than
  reporting that, the detector stops and says it declined to guess — reporting
  the whole internet as scanning and escalating it through the ladder would
  take the server off the air.

- `tests/test_networkguard.php` (66 assertions) covers the `/proc/net` byte
  order against three IPv4 addresses and IPv6 — decoding that wrong does not
  fail loudly, it blocks the wrong address — plus every refusal, the clamps,
  and CIDR whitelisting of the five addresses the October handoff says must
  never be blocked.

### Not built, deliberately

- **Country blocking** needs a GeoIP feed. MaxMind now requires an account and
  licence key; the free CIDR-per-country sources vary in accuracy and update
  cadence. That is a data-sourcing decision, not a coding one, and it should be
  made explicitly rather than by whichever feed was easiest to wire in.
- **Cluster mode** (sharing blocks between servers) is a protocol and trust
  design, not a feature — it needs authentication between nodes before any of
  it is safe.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
