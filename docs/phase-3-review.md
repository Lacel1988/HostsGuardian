# Phase 3: custom DNS Engine boundary

> Historical milestone baseline: this document records behavior and verification at that phase, not the current feature set. Preserve its original test counts. For the current architecture, completed milestones and limitations, see the [README](../README.md) and [Phase 5C baseline](phase5c-upstream-reliability.md).

LAN clients -> HostsGuardian.DnsEngine UDP 53 -> RuleStore -> upstream DNS.
At Phase 3: WPF -> Core HTTP client -> management API 3000 -> the same RuleStore. Phase 4 subsequently replaced management transport with authenticated HTTPS.
TCP 53 remains the target; it is not implemented and status explicitly reports that.
No automatic domains are installed. Health/status/discovery do not authorize policy.

Removed dnsmasq execution, apply/revert endpoints, client orchestration methods,
configuration paths and DHCP lease discovery. Best-effort router identification and network observation remain in WPF/Core; this is not authoritative DHCP lease discovery or router/DHCP integration.
The unused Core DNS executor and its unused wrapper were removed after reference checks.
Their descendant matching is preserved in RuleStore. Their unwired per-IP policy was
not active GUI behavior; future device policy work must use MAC identity.
DnsProxyServer, DnsProtocol and RuleStore are unchanged in this phase.

Deployment must explicitly inspect existing dnsmasq/systemd-resolved listeners and
port 53 conflicts before starting this Engine. No service or networking changes were
performed. Binding port 53 on Linux requires suitable privileges/capability, to be
handled during deployment testing. Do not deploy this intermediate version.

Phase 4: remove empty-token bypass, protect Windows credentials, constrain management
access, and resolve the currently unused ApiBindIp setting.
Phase 5: persisted explicitly authorized policy, startup restore/lifecycle, TCP DNS,
upstream correctness/error responses, concurrency and API failure propagation.
At this milestone, policy remained in memory; transport status does not claim synchronization
or independently enabled/disabled filtering. Full GUI state work remains Phase 6.
