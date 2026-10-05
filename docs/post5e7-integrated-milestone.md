# POST-5E-7 integrated milestone: source architecture and gates

Phase 5E-8 whole-LAN/router acceptance remains PAUSED. No commits/pushes or real
Windows/Linux/network/security/runtime-policy changes were made by this work.
Starting HEAD: `de1398564038199ccf1441bd53bad11e25a2b340` (clean checkout).

## Internal checkpoints

1. HOSTS retirement: PASS. Ordinary UI/VM/Core/console/filter-selection paths
   removed. DNS selections and credential references retained. Cleanup-only
   migration requires an explicit target; both known ownership formats are
   validated before backup/write. Unrelated bytes and BOM are preserved;
   malformed markers/Unicode and changed/linked targets are refused. Actual
   Windows hosts was read only: readable, 827 bytes, no HOSTSGUARDIAN marker text.
   This is marker evidence, not a claim about unrelated hosts entries.
2. Request identity: PASS. Immutable context from UDP RemoteEndPoint and each TCP
   frame RemoteEndPoint. Port is diagnostic only; receive time precedes UDP
   worker bookkeeping. Incoming interface scope is not established by these
   transport APIs; null scope means the single Engine IPv4 address namespace.
3. Device architecture: PASS. Guid DeviceId, registry name/MAC/provenance/scope,
   expiring independent IP observations, immutable snapshots and separate mapping
   generation. Ambiguous/expired/unvalidated/unregistered identities are Unknown.
   No synchronous shell/discovery/DHCP work in DNS processing. Multiple addresses
   can share one DeviceId. IPv6 device enforcement is unsupported explicitly.
4. Device policy: PASS. Safe Mode first bypasses filtering, most-specific device
   override next, global exact/parent block next, otherwise Allow. A most-specific
   Inherit rule resumes global policy. Unknown identities use global only.
   Domain Block covers all queried record types: IN A keeps the proven sink
   response; other types/classes receive an empty answer. MX/TXT/HTTPS cannot
   bypass a domain Block. Allowed-domain MX forwarding remains covered.
   Legacy IsBlocked is retained as unassigned preference; no block-all policy
   or automatic conversion is implemented.
5. Persistence/API: PASS. Schema1 restores into schema2 in memory, without rewriting
   evidence/revision; next authorized commit writes canonical schema2. Validation,
   persist-before-ack, atomic immutable policy publication, retained policy on
   failed writes, rejected evidence preservation and Safe Mode guarantees remain.
   Full replacement uses expected revision and instance. Legacy global mutations
   preserve registry/overrides. Full canonical readback and authenticated status
   (including instance) are required for synchronization. Bindings are ephemeral:
   restart clears observations, retaining durable device policy; refresh does not
   increment policy revision. Authentication precedes every new endpoint.
6. WPF: PASS for build/automated semantics. DNS-only controls; six separate
   operational states, expiring evidence, diagnostics and guarded Safe Mode.
   Configured HTTPS Engine endpoint is distinct from this PC's interface DNS
   resolver list. That list does not establish actual browser/DoH routing.
   Virtualized master/detail device policy, non-color text/symbols, editable
   Inherit/Allow/Block, global/device draft effect and authenticated effective
   explanation. Reading Engine device policy explicitly imports overrides;
   local global selections remain a draft. Registering observed MAC does not
   approve an Engine binding. Physical WPF layout/keyboard/screen-reader checks
   remain manual acceptance. Domain counts are not assumed to be small.
7. Automated Windows verification: see final checkpoint report and logs.
8. Linux monitor: source/package/parser preparation complete; Vivo runtime gate
   NOT passed. Optional Engine-owned status publisher, bounded operational events,
   non-root GTK4 viewer, fixed-unit D-Bus/polkit recovery and XDG autostart source.
   Proposed drop-in and polkit rule are not installed by the package skeleton.
   Do not replace the proven service or its security settings.
9. Representative E2E: plan prepared; not executed. See real-device-e2e-plan.md.

## Versioned API

All endpoints require the existing HTTPS/bearer authentication boundary.

- GET `/v2/capabilities`: schema/capability compatibility, IPv4/IPv6 claims.
- GET `/v2/policy`: complete canonical policy, revision and instance.
- POST `/v2/policy/replace`: expectedRevision, expectedInstanceId and complete policy.
- GET `/v2/bindings`: separate generation and immutable observations.
- POST `/v2/bindings/replace`: expectedGeneration and replacement observations.
- GET `/v2/effective-policy?address=...&domain=...&scope=...`: read-only explanation.
- GET `/v2/dns-observations`: most recent 64 actual received DNS decisions, including
  transport/source identity/timestamp, resolved DeviceId, revision/generation.
  These bounded in-memory diagnostics may contain queried domain/device addresses;
  they are authenticated and never persisted/exported to the public local monitor.

Full policy fields: schemaVersion=2, globalBlockedDomains, devices, overrides.
Device registry: deviceId/name/mac/scope/provenance; overrides: deviceId/domain/state.
Binding observations: address/networkScope/deviceId/provenance/observedAtUtc/
expiresAtUtc/validated. IPv4 canonical addresses only; maximum lifetime one day.
Only explicitly reviewed observations should be validated. A Windows scan is
metadata and cannot establish that an Engine sees the same IP/network namespace.
Null transport/binding scope is only suitable for one unambiguous IPv4 namespace.
Overlapping networks, NAT/router proxy identity loss and IPv6 require future work;
never manufacture per-device identity for them.

## Verification commands

The already running WPF process locks its normal output directory. Builds were
performed using a separate output directory without closing that process:

```
dotnet build HostsGuardian.sln --no-restore -p:BaseOutputPath=bin\milestone\
dotnet run --project HostsGuardian.RegressionTests --no-restore
dotnet run --project HostsGuardian.Wpf.RegressionTests --no-restore -p:BaseOutputPath=bin\milestone\
python -X utf8 -m unittest discover -s linux-monitor -p test_*.py
python -X utf8 -m py_compile linux-monitor/monitor.py linux-monitor/monitor_core.py
```

All DNS/API/security/policy/cleanup tests use temporary fixtures and high loopback
ports. DNS flush execution is injected; no real cache flush occurs. Linux permission
rules are tested using explicit POSIX metadata fixtures on Windows; actual Unix
ownership, GTK/D-Bus/polkit/systemd validation requires Vivo. Existing deterministic
schema assertion was updated to schema2 canonical bytes, and the WPF source
assertion now requires full-policy readback/expected revision. Their protections
were preserved, with additional full-content and instance mismatch checks.
