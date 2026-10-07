# Device identity, Binding V2 and topology source checkpoint

Status: v0.4.0 source release. The Engine/NetworkValidator deployment foundation is accepted; active ARP and broader real-LAN/visual acceptance remain pending. This source release does not deploy or change production.
See [release verification](checkpoint-v0.4.0.md).
Engine executes. Monitor observes. WPF decides.

## Identity and freshness

Monitor primary identity follows independently supported LAN registration even when DNS buckets contain both registered and unresolved requests. Unresolved requests retain their original attribution. The exact 58 attributed / 40 unresolved regression passes. Registered inventory persists independently of observations; cached presence is not Online. Existing retained inferred classification and Forget semantics remain intact.

Kernel evidence separates ReadAt, underlying ObservedAt/KernelUpdatedAt, ConfirmedAt and accepted ValidatedAt. Re-reading a cached neighbour never refreshes its confirmation. Missing kernel age remains unknown. Passive bindings still require fresh REACHABLE confirmation and expire after 15 seconds; they do not accept STALE merely to pass acceptance.

## Validation comparison and architecture

Passive neighbour evidence is inexpensive but NUD state and age limit current ownership proof. Ordinary targeted TCP/UDP may provoke neighbour resolution but assumes remote service behavior and cannot reliably prove a fresh mapping. Dedicated targeted ARP provides direct bounded current network-claim evidence without assigning CAP_NET_RAW to the full Engine. ARP is unauthenticated: this improves freshness, not cryptographic identity or resistance to a lone consistent MAC spoofer.

The helper uses only an exact IPv4/interface request. It validates canonical on-link unicast targets against the interface's current address/netmask, excluding local, network, broadcast, multicast, loopback and link-local targets. No sweep, arbitrary packet interface, general capture or retained packets. Strict Ethernet/ARP field, target, interface, sender and size validation rejects malformed replies. It sends at most two requests over a two-second window; multiple MAC claims or more than 32 received ARP frames fail closed. Busy LANs can consequently cause conservative false negatives. Interface configuration changes invalidate the attempt.

PID1 owns a root-owned Unix socket, mode 0660, in a root-owned protected directory, mode 0755. The helper authorizes the configured service UID and live Engine MainPID using SO_PEERCRED, the root system bus and peer-pidfd lifetime checks. Engine/helper publications and all parent directories must be root-owned and not group/world writable. Requests are capped at 1024 bytes with duplicate-key rejection; Engine responses at 4096 bytes. Two concurrent operations, 30-second target cooldown, four admissions/second and 64 remembered candidates bound work. Framing has an absolute three-second deadline. Helper restarts use the PID1 listener; no mandatory proc-executable authorization remains.

The service UID is trusted: this design is not isolation against a fully compromised Engine/service account. ARP spoofing, neighbour poisoning and malicious hosts remain threats. Conflicting observations, duplicate registrations and inconsistent replies fail closed. Packet mutation tests do not constitute proof against all attacks or live-LAN validation.

## Binding V2

An optional background producer uses `HOSTSGUARDIAN_VALIDATOR_SOCKET`; absent configuration retains the passive producer. Active mode does not fall back to accepting passive STALE rows when the helper is unavailable. It considers at most 64 uniquely registered-MAC IPv4 candidates from a complete recent kernel read; two requests per refresh; immutable cached evidence expires within 45 seconds of the actual reply. DNS never waits for validation. UDP and TCP share AddressBindingStore.

Before and after each request, candidate evidence and registry membership must remain fresh/unambiguous. IP reuse, conflicting evidence, registry change, Forget, missing helper, timeout and expiry remove/withhold binding. Resolver reads additionally check current policy membership and expiry, including while background refresh is delayed. Binding proves a current IP/MAC claim on an interface, not permanent device identity.

IPv6 DNS transport is preserved; IPv6 per-device active binding is unsupported. Unknown identity uses the existing global policy fallback, not fabricated device enforcement.

## Randomized MAC continuity

Schema 3 registrations can persist up to eight explicit AcceptedNetworkIdentities with scope, provenance and acceptance time. Canonicalization and backup roundtrip are tested. This is domain compatibility for a future WPF Link to existing device action; aliases do not automatically become enforcement identities in this candidate. No IP/name-only merge, no automatic randomized-MAC linkage, no restoration of forgotten metadata. User-facing linking/revocation remains deferred.

## Counts and notifications

Registered inventory, provisional observations, DNS sources and validated bindings are distinct concepts. Topology labels registered and provisional counts explicitly and reports omitted inventory. Unrecognized observations use that wording rather than claiming a newly discovered physical device; notification keys normalize MAC formatting/canonical IP fallback. EN/HU strings are centralized. No persistent raw telemetry store was added.

## Topology model and Monitor

Core builds bounded schema 1 snapshots: up to 128 nodes, 256 links, 64 networks, eight addresses/MACs/evidence records per node. Persistent registered nodes survive absence of correlated observations. Engine, provisional clients, configured gateways, upstream DNS resolvers and optional infrastructure evidence remain separate roles. Multiple matches are not silently selected. Conflicting access claims are retained as Unknown evidence rather than promoted to certainty.

Linux Monitor adds a graphical TOPOLOGY page with shared vector icons, stable node selection/layout, independently scrollable graph/list/details, access/DNS/all layers, solid observed/proven and dashed inferred links, text confidence and WHY evidence. Primary nodes show presence and known network label. DNS activity edges are observed source-address evidence, not exclusive coverage or proof of every request's DeviceId. Configured OS gateway paths are inferred configuration, not observed traffic. Upstream aggregate attempts establish observed Engine upstream use, not any phone's alternate resolver. Binding overlay warns of unvalidated identity/global fallback; it does not claim a domain-specific winning policy without a domain request.

Remote Ethernet/Wi-Fi, AP, SSID, switch port, Internet boundary, exclusive DNS coverage and alternate client resolver remain Unknown without evidence. Optional access providers can contribute explicit technology/parent/network with confidence, provenance and bounded expiry; these are contracts/fixtures, not implemented router integrations. Network membership is not a policy group. Missing observation does not prove offline. The Engine's receiving interface does not establish the remote client's access technology. No current LAN address, router vendor, SSID or device name is hardcoded.

The publisher runs outside DNS processing and drops topology first if the existing 128 KiB Monitor payload cap is exceeded. Monitor rejects stale, malformed, duplicated and oversized graphs. There is no new management topology endpoint; Monitor consumes the existing local diagnostics publication.

## Verification

Final verification: Core/Engine 299 regression groups PASS; WPF 31 groups PASS; Linux Monitor 73 tests PASS including GTK fixtures; NetworkValidator 12 mocked/synthetic tests PASS on Windows and Linux; orchestrator 30 tests PASS. Solution rebuild: 0 errors, 10 warning occurrences. git diff --check PASS. Full logs and source manifest are supplied externally. Some earlier Core runs hit existing random-port/cancellation fixture failures; the final complete run passed. The graph image is an actual renderer output using synthetic fixture data, NOT a production screenshot. No real CAP_NET_RAW operation or production probe was performed.

## Corrected deployment boundary â€” review required, not executed

The earlier cb06271e design was blocked: proc executable authorization is incompatible with capability-based proc access; a shared-UID writable listener could be impersonated; the GI Cairo bridge was absent; final Linux artifacts had not been built. Those findings are superseded at source level by [IPC security v2](../network-validator/IPC-SECURITY.md).

PID1 creates a root-owned 0660 socket in a protected root-owned directory. The Engine authenticates PID1 creator credentials and inode/ownership before any request. The helper authorizes the fixed live Engine MainPID through the root system bus, with socket-associated kernel peer-pidfd lifetime checks. No mandatory proc executable authorization or new service user is required. Root-protected complete Engine/helper publication remains a deployment prerequisite; policy/security paths remain unchanged. CAP_NET_RAW stays helper-only.

Socket activation and service templates are under `network-validator/packaging`. `guarded_install.py` is a future human-reviewed root installer, never run during source work. It requires externally pinned source/payload/baseline integrity, protected root staging, explicit daemon-reload approval, existing Cairo prerequisites, and preserved policy/security/unit/old Engine evidence. Its initial mode verifies authenticated IPC while active ARP remains OFF. Candidate and rollback both use bounded readiness polling retaining every missing condition: IPv4/IPv6 UDP/TCP protocol/listener readiness, expected process ownership/capabilities, authenticated management, policy/security preservation and candidate helper health. It never restores policy over user changes, creates users/groups, installs dependencies, enables ARP, sets file capabilities or changes networking. Existing NeedDaemonReload=yes must be reviewed before any future daemon reload, and was not changed in source work.

The Monitor explicitly depends on python3-cairo/python3-gi-cairo. Without the bridge it retains usable list/details and clearly reports why the graph is unavailable; with the bridge tests realize the actual native GTK drawing callback. Isolated dependency extraction is not system installation.

Full corrected-candidate verification and binary/source identities are recorded in the accompanying external acceptance/deployment review. The earlier verification counts above describe the previous source candidate, not the corrected one.

## Human acceptance after guarded deployment

1. Monitor TOPOLOGY: select registered and provisional nodes; verify friendly identity, truthful presence, Unknown access/coverage, binding warning and WHY timestamps. Toggle access/DNS/all; resize and scroll a longer list; selection must survive refresh.
2. Confirm known offline inventory remains visible. Mixed registered/unresolved DNS counts must preserve friendly name without reassigning unresolved requests.
3. In a separately approved exact-device live test, verify a fresh ARP confirmation permits the registered TV's current IPv4 binding even while kernel NUD is STALE. Both UDP and TCP must resolve the same DeviceId. No policy delivery is necessary to inspect binding.
4. Verify helper unavailable/timeout/expiry/conflict does not grant device identity. Do not generate spoofing or production failure merely for visual acceptance; use retained deterministic evidence.
5. Verify randomized phone MAC remains unmerged; no registration or Link action is automatic. Check WPF preserved identity, draft/readback/Forget behavior without modifying production policy unless separately approved.

Human consent, minimal interruption and understandable evidence remain required.
