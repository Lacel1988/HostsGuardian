# Receive-only DNS L2 identity evidence — candidate, not deployed

This change fixes intermittent IPv4 attribution caused by requiring a kernel
neighbour confirmation younger than 15 seconds even while DNS packets arrive.
It does not make STALE neighbours valid and does not authenticate physical devices.

## Evidence and trust

The dedicated helper optionally receives Ethernet IPv4 DNS frames on one or two
explicitly approved interfaces using AF_PACKET / CAP_NET_RAW. No packets are
sent; no promiscuous membership, interface configuration or CAP_NET_ADMIN is used.
Engine privileges remain unchanged. PID1-owned socket, protected executable
hierarchy, SO_PEERCRED / live MainPID / SO_PEERPIDFD checks remain mandatory for
the new `passiveDnsRead` operation as for the existing active operation.

Accept only incoming PACKET_HOST frames addressed to the interface MAC and local
IPv4, with a valid on-link unicast source, IPv4 header and transport checksums,
and a DNS request to port 53. Ignore outbound, other-host, multicast, fragments,
IPv4 options, VLAN encapsulation, incomplete TCP DNS messages and oversized frames.
TCP requires a complete DNS message within one segment; no stream reconstruction.
IPv6 device enforcement remains unsupported. Never infer a MAC from UDP source IP.

Cache at most 64 IP/MAC/interface claims for 10 seconds in volatile memory. Keep
conflicting claims, never overwrite them with the last writer. Retain neither DNS
names nor payloads. Capacity overflow, receive-budget overflow (>1024 frames/s),
kernel packet loss, interface changes and receiver failure invalidate evidence.
Overflow/loss imposes a 10-second recovery quarantine. Interface changes/terminal
receiver failures require a reviewed helper restart; IPC health alone is not
capture health. `PassiveDnsL2State`/`PassiveDnsL2Reason` report capture readback
separately from the existing READY IPC state.

Engine accepts only a recent authenticated bounded readback, a fresh packet claim,
one matching registered MAC, and a complete fresh neighbour read corroborating
that same IP/MAC/interface without duplicate IPv4/interface claims or negative
FAILED/INCOMPLETE evidence. STALE/DELAY/PROBE can corroborate, but cannot establish
or refresh identity. Same-interface IPv6 neighbours do not invalidate IPv4 evidence.
Packet timestamps alone set expiry; readback never renews it. Monotonic helper
age and Engine publication guards prevent wall-clock rollback extending trust.
The existing freshness setting can tighten (1–10s), never extend the 10s ceiling.

L2/ARP claims are unauthenticated. Complete IP+MAC impersonation is indistinguishable
from the legitimate sender without stronger network/client authentication. Detected
MAC/IP/interface disagreements fail closed for identity. This is not spoof-proof
physical identity or proof of DNS response delivery/application blocking.
Conflict reaction is bounded by background IPC refresh, not synchronous per packet.
After restart/idle expiry, the first query can remain unbound until the next
background refresh (nominally 2 seconds). Under existing policy semantics an unbound
request uses global policy; no unverified device-specific Block is applied.

## Activation and compatibility

Both sides are explicit opt-ins, requiring one reviewed deployment, not an action
for each policy change:

* Helper: append `--passive-dns` to the protected helper service ExecStart, retaining
  its exact existing arguments, interface allowlist, user, socket and hardening.
* Engine: `HOSTSGUARDIAN_PASSIVE_DNS_L2=1` plus the existing trusted validator socket.
* Keep `HOSTSGUARDIAN_ACTIVE_VALIDATION=0`, empty approved DeviceIds and duration.
* With passive L2 disabled, the current kernel-only path is unchanged.
* Old helper/unsupported operation, missing socket, incomplete capture, invalid
  freshness or failed readback creates no L2 binding. DNS remains independent.
* No public API, policy schema, device registry or user-owned metadata changes.

## Deployment and rollback plan (not executed)

1. Review/seal the new Engine and helper payload together. The existing Engine-only
   installer intentionally preserves helper state; do not use it to silently change
   helper selection. No Monitor/WPF deployment or policy/domain expansion is needed.
2. Read-only verify the accepted production baseline; back up byte-for-byte the
   Engine/helper service/drop-in definitions, selected releases and capabilities,
   policy/security hashes and registrations. Keep all prior evidence/recovery intact.
3. Stage both payloads in a new root-owned protected release hierarchy; hash-check
   them. Retain helper-only CAP_NET_RAW, Engine-only CAP_NET_BIND_SERVICE, current
   interface restrictions and PID1 socket. Never grant CAP_NET_RAW to Engine.
4. In one separately reviewed guarded transaction, change only release selection
   and the explicit receive-only opt-ins. Preserve monitoring/security drop-ins and
   socket ownership/boot enablement. One required daemon-reload; controlled helper
   and Engine restart. Active ARP remains OFF throughout.
5. Verify authenticated IPC/capture health separately; actual IPv4/IPv6 UDP/TCP DNS
   and HTTPS readiness; unchanged policy/Safe Mode/security/registrations; capability
   and socket invariants. Verify fresh passive bindings while NUD confirmation exceeds
   15s, TTL expiry, and no active ARP. Do not claim live Block without client responses.
6. On failure restore exact previous definitions, release selections and capabilities,
   reload once and restore previous runtime. Verify original DNS/API and preservation.
   Preserve evidence; never reset/migrate policy or disable security to force readiness.

No production action is authorized/executed by this source task. A future deployment
needs a new pinned guarded handoff; this document is not an executable deployment command.

## Verification

Deterministic tests cover UDP/TCP packet parsing, direction/checksum/scope rejection,
parallel reads, conflict retention, overflow/loss, expiry, clock errors, interface
changes, disabled helper, original IPC authorization, Linux peer pidfd semantics,
old-helper compatibility and Engine/DNS independence. Integrated tests keep a fixed
old neighbour confirmation while fresh DNS L2 evidence continues, then verify
TV-only sinkhole bytes, independent control Allow, subdomain matching and exact
Inherit Restore with upstream response bytes while Active Validation is OFF.
All device names/addresses in tests are fixtures, not product defaults.
