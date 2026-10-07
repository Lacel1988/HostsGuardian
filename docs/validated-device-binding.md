# FOUNDATION BLOCKER — Validated Device Identity → DNS Enforcement Binding

Discovered during Roadmap #4 acceptance. Automated candidate; production/real-device acceptance pending. Roadmap #4 stays pending; client-side device search is deferred until this blocker is accepted. Roadmap #5 has not started.

## Audit
POST-5E-7 provided authenticated GET/POST binding endpoints, optimistic mapping generation, immutable expiring IPv4 bindings and shared UDP/TCP effective-policy resolution. Bindings intentionally clear on restart; they never increment policy revision. Production composition had no producer: only explicit management binding replacement could populate the store. Registry delivery and diagnostic MAC projection therefore succeeded while source-address identity stayed Unknown.

## Minimal integration
Program starts a background ValidatedBindingProducer beside the existing status publisher. Every two seconds it uses the same bounded PassiveIdentityEvidence kernel read already used by diagnostics (15-second cache). DNS workers remain snapshot-only. A shared RegisteredMacCorrelation primitive serves diagnostics and enforcement below presentation. No Monitor-owned registration or new database exists.

Binding evidence is a separately qualified view of that same kernel response: /proc/net/arp CACHED fallback, local adapter rows, mDNS/SSDP and hostname inference cannot authorize bindings. ip -j neigh must succeed with complete parseable bounded output (under 64 entries / 64 KiB). Failure, malformed/partial/oversized output yields no eligible evidence. FAILED/INCOMPLETE entries are retained in binding evidence to reject same-IP conflicts rather than being silently discarded.

## Trust / lifetime
Only unicast IPv4, a non-loopback/nonzero address, OBSERVED evidence, exactly REACHABLE state, known interface, one normalized unicast MAC, one registry member and unambiguous address/interface evidence qualify. Duplicate registered MAC, differing MACs for an address or repeated MAC across interfaces are rejected. DNS transports expose no interface scope; automatic observations use the existing null single-Engine IPv4 namespace and refuse cross-interface ambiguity. Names, type, manufacturer, old IP and fingerprint similarity do not authorize identity.

Every binding records DeviceId, current address, MAC evidence, interface, provenance, observed time and expiry (15 seconds from kernel observation read, not from producer refresh). Generation changes only when the immutable evidence list changes. Each producer pass replaces the entire automatic binding set: disappearance, stale state, conflict, provider failure or current registration removal withdraws it. Resolver rejects expiry independently even if producer stops. Registry deletion/registered-MAC change invalidates an older snapshot immediately during resolution. Shutdown clears automatic observations; restart requires new evidence. No permanent raw telemetry is retained.

REACHABLE kernel evidence is bounded local L2 evidence, not cryptographic device authentication or proof of permanent physical identity. Changes between kernel reads can remain undetected within the bounded cache window; ARP spoofing/resolver exclusivity are not solved here. STALE is intentionally insufficient even when a diagnostic friendly name remains available. Private MAC evidence can match a registration currently, but a different MAC never inherits it.

The existing authenticated manual binding replacement API is preserved for compatibility; the production background producer replaces its contents on the next pass. It is not a persistent/manual pinning facility. No WPF binding-write UI was added.

## Enforcement and coverage
Existing DnsRequestProcessor/DevicePolicyEvaluator consume the produced store for both UDP and TCP; domain matching, precedence, Safe Mode, global fallback and revisions are unchanged. GET /v2/bindings and effective-policy readback expose real generation/evidence and identity. IPv4 device enforcement is now supplied by current eligible evidence. IPv6 DNS listeners remain supported; IPv6 device enforcement stays explicitly unsupported. Diagnostic Registered does not independently imply a valid enforcement binding.

No YouTube service expansion or catalog was implemented. Real acceptance must use a deterministic domain, not claim complete app blocking.

## Tests / acceptance
New deterministic tests cover valid evidence/provenance/generation, DHCP move, IP reuse, stale TTL, conflicts/duplicate registration/partial reads, disappearance, Forget/MAC change, mismatched randomized MAC, IPv6 exclusion, preserved diagnostics, malformed/negative neighbour evidence, unavailable provider/shutdown and UDP/TCP blocked versus unbound global-allow decisions with no policy revision mutation. Existing WPF orphan/inference and policy readback suites remain required.

After separately reviewed guarded deployment, first use an explicitly registered stable-MAC test device. Confirm current REACHABLE evidence and /v2/bindings before a device-specific Block on one deterministic domain. Read back the matching DeviceId, rule and revision; observe real target query/blocked response and another client’s allowed query. Return policy to its reviewed prior state through explicit authorized WPF action. Do not impersonate a source IP or manually seed a binding to manufacture real-device acceptance. If the TV cannot originate a suitable fresh lookup, stop for an appropriate human test method; do not claim application success from synthetic fixtures.

The previously mismatched phone observation must remain DeviceId null. Multi-MAC continuity and per-device IPv6 enforcement are follow-up designs, not implemented here. Production not deployed.
