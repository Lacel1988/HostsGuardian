# Architecture, Innovation Preservation and Roadmap

**Review date: 2026-10-13. Documentation checkpoint, not deployment acceptance.**

## Evidence rules and version accounting

IMPLEMENTED means source exists; VERIFIED requires observed runtime behavior; PARTIAL means a working subset; UNVERIFIED means insufficient runtime proof; BLOCKED means a known prerequisite is missing. Tests do not turn candidate code into production evidence.

Published source baseline for this review: `8f517c081a52385e22b182db910428d251dead45`, master. Six existing commits after the remote baseline cover socket boot persistence, scoped validation, guarded upgrades, evidence refresh, passive L2 correlation and coordinated Engine/helper upgrades. They are distinct from the remaining local candidate edits.

The selected WPF package matches the main checkout's 156 WPF/Core/build-related manifest entries and seven WPF regression files. WPF executable SHA-256: `ec4bd628d2822e596afdef4c83e65b515b442d7faaf1949dd7e95f9163b48bcc`; WPF DLL: `8590326edc4e729f167686f471f2eaee5bffa61dc3af6bd22e03cac7685521b5`. An apphost hash alone is not version identity. Candidate source identity: `6853c56ee73b3751f0244ab3a71b4dbe3cfaaeb17c3eff8924329204af4fb1f4`.

The complete manifest comparison found seven later differences: `linux-monitor/monitor.py`, `operations.py`, `test_gui.py`, `test_operations.py`; `network-validator/l2_upgrade.py`, `release_bootstrap.py`, `test_l2_upgrade.py`. Existing local source changes are preserved, not committed by this documentation task. Candidate-only paths below may therefore not exist in a clean checkout of this documentation commit.

## 1. PDP / PEP and global/device policy

**Goal:** one deterministic decision model, separately executed by DNS and future network enforcement.
**Implementation:** Core `Services/PolicyDecision.cs`; Engine `DevicePolicyEvaluator.cs` is the PDP projection, `DnsRequestProcessor.cs` produces DNS responses (PEP). `PolicyApplicationService.cs` commits authenticated updates. Schema supports global/device and program layers.
**Tests:** `IntegratedPolicyTests.cs`, `RoadmapPolicyTests.cs`, `ValidatedBindingTests.cs` in `HostsGuardian.RegressionTests`; included in preserved Core/Engine 332 passing candidate groups.
**Status:** production global DNS VERIFIED on October 13; selective device enforcement PARTIAL. **Next:** two-client selective Block/Restore with fresh identity and real response evidence. A policy readback alone is insufficient.

## 2. Authentic DeviceId binding, TTL and conflict handling

**Goal:** correlate DNS source with stable registered identity without permanent IP trust.
**Implementation:** Engine `AddressBindingStore.cs`, `PassiveDnsL2BindingProducer.cs`; Core `Services/RegisteredMacCorrelation.cs`, `Models/PassiveDnsL2Evidence.cs`; helper `network-validator/validator.py`. Packet/source evidence, registration and interface scope must agree; stale/conflicting claims fail identity attribution. L2 evidence is not cryptographic authentication.
**Tests:** `PassiveDnsL2Tests.cs`, `ValidatedBindingTests.cs`, helper `test_passive_dns.py`, including expiry, concurrent traffic, conflict and full impersonation limitations.
**Status:** production mechanism IMPLEMENTED, reliability PARTIAL; candidate invalidation improvements not deployed. **Next:** prove IP reuse, reconnect and ambiguous/randomized MAC behavior with controlled clients, without weakening TTL or accepting STALE.

## 3. Receiver lifecycle, recovery and bounded refresh

**Goal:** restore capture after interface failure and obtain fresh evidence before DNS decision within finite latency.
**Implementation:** candidate `validator.py` receiver generations/reopen/backoff; candidate `RequestBindingRefresh.cs` uses a monotonic 200 ms caller budget and coordinated refresh. Processor re-reads state; helper failure does not stop DNS. IPC availability and capture usability are separate.
**Tests:** helper `test_passive_dns.py` covers socket failure, down/up, old generation, restart and parallel snapshot reads; candidate `RequestBindingRefreshTests.cs` covers expiry, timeout/cancellation, staggered requests and passive fallback; `ReliabilityFoundationTests.cs` tests integrated failure cases. Preserved candidate suites passed; not a production outage/reboot proof.
**Status:** CANDIDATE, UNVERIFIED in production. **Next:** guarded deployment and interface recovery acceptance. Global shared refresh must not manufacture cross-device attribution.

## 4. IPv6 identity and network enforcement foundation

**Goal:** equal evidence semantics for both address families; separate DNS coverage from mandatory network enforcement.
**Implementation:** dual-stack listeners `DnsProxyServer.cs`, `TcpDnsServer.cs`; candidate passive IPv6 evidence/contracts and `PassiveDnsL2BindingProducer.cs`. `TopologyProjection.cs` records evidence, not invented physical links. Production dual-stack DNS readiness has prior evidence; IPv6 per-device enforcement does not.
**Tests:** Core `PassiveDnsL2Tests.cs`, `ReliabilityFoundationTests.cs`, helper `test_passive_dns.py`: IPv6 evidence/expiry and unsupported/unknown behavior in fixtures.
**Status:** dual-stack DNS IMPLEMENTED; reliable real IPv6 identity UNVERIFIED; full network PEP BLOCKED by absent chokepoint. **Next:** controlled privacy-address/prefix/interface-change acceptance. Future Engine adapter needs atomic firewall application/rollback, explicit failure mode, minimum privilege and an isolated routed test network. No firewall backend or gateway deployment is claimed.

## 5. Immutable snapshots, decisions and exact Restore

**Goal:** concurrent-safe decisions and restoration of ABSENT versus explicit Inherit/Allow/Block.
**Implementation:** `EnginePolicyState.cs`, `PolicyApplicationService.cs`, `PolicyPersistence.cs`, Core `PolicyCanonicalization.cs`; WPF `ViewModels/MainViewModel.cs` explicit delivery/readback. Candidate `Core/Services/DeviceOverrideRestore.cs` preserves absence and explicit state, with instance/CAS repair.
**Tests:** `FullPolicyClientTests.cs`, `IntegratedPolicyTests.cs`, WPF `RegistrationConsistencyTests.cs`; candidate recovery `development/roadmap/test_p0_policy_restore.py` covers partial restore, idempotence, conflicts and foreign changes.
**Status:** production global Restore VERIFIED (revision 46 → 47, original content); candidate device exact Restore has historical human evidence but no general all-client claim. **Next:** preserve CAS and independently prove the intended DeviceId/domain set, not GUI state alone.

## 6. Adaptive Simple/Indexed, thresholds and hysteresis

**Goal:** simpler small workloads and scalable large workloads without oscillation.
**Implementation:** candidate `AddressBindingStore.cs` has a fixed immutable address/scope dictionary index. Candidate telemetry uses dictionary lookup plus bounded FIFO. This is **not adaptive switching**. No measured switching threshold or index-mode hysteresis implementation was found in the targeted main/worktree search. Diagnostic severity hysteresis exists separately and must not be confused with algorithm-mode hysteresis.
**Tests/evidence:** candidate `ReliabilityBenchmarks.cs`, equivalence tests in `ReliabilityFoundationTests.cs`. Preserved isolated 10,000-lookup measurements: 64 bindings scan 40.995 ms versus index 0.717 ms; 1024 scan 178.757 ms versus index 0.624 ms. Rebuild costs and production throughput were not measured. Timing variation prevents inferring a scaling curve.
**Status:** fixed index CANDIDATE; adaptive algorithm DESIGN / UNIMPLEMENTED. **Next:** benchmark construction, churn and lookup together; add switching only if measured benefit exceeds complexity, with rollback and stable thresholds.

## 7. Domain Mode and Service Discovery Mode

**Goal:** direct domain rules plus evidence-assisted service-level configuration.
**Implementation:** WPF Domains and Core `Models/PolicyProgram.cs` service catalog (`CatalogService`) with declared domain sets; `PolicyDecision.cs` resolves service-backed rules. A service catalog is not automatic discovery. No distinct automatic Service Discovery Mode was found.
**Tests:** `RoadmapPolicyTests.cs`, `RoadmapDataTests.cs`, `IntegratedPolicyTests.cs`; within preserved 332-group candidate result.
**Status:** Domain policy VERIFIED globally; explicit service catalog IMPLEMENTED; automatic discovery DESIGN / UNIMPLEMENTED. **Next:** define bounded observations and explicit user confirmation; never silently mutate policy from inferred services.

## 8. Passive DNS correlation and learning service model

**Goal:** explain which observed domains belong to services without false certainty.
**Implementation:** `DnsObservationStore.cs`, `DnsRequestContext.cs`, local helper packet correlation; policy catalog is user-defined. Source attribution and packet correlation exist, but no autonomous learning service model was found.
**Tests:** `PassiveDnsL2Tests.cs`, `RoadmapDataTests.cs`, helper `test_passive_dns.py`; candidate fixtures, not learned real application coverage.
**Status:** observation IMPLEMENTED/PARTIAL; learning model UNIMPLEMENTED. **Next:** consented, bounded correlation experiments with provenance. A blocked hostname does not prove complete YouTube playback shutdown; caches, existing connections and additional names remain limitations.

## 9. Persistent aggregation, SQLite/WAL, retention and queue

**Goal:** useful retained evidence with bounded memory/storage and DNS-independent telemetry failures.
**Implementation:** published baseline has bounded in-memory DNS records; candidate `DnsObservationStore.cs` uses a 512-event Channel, 2048-record retention, FIFO/dictionary completion and loss counters. Candidate evidence improves correlation and reports completion outcomes. No SQLite/WAL aggregation implementation was found. Policy persistence is a separate concern.
**Tests:** `ReliabilityFoundationTests.cs` and `RoadmapDataTests.cs` cover retention/backpressure/completion; candidate benchmarks compare completion indexing. Previous candidate Core suite passed; no durable database tests exist.
**Status:** queue/retention CANDIDATE; durable SQLite/WAL DESIGN / UNIMPLEMENTED. **Next:** establish minimum privacy-safe aggregation requirements, disk budget and retention before adding persistence; never retain raw packets indefinitely.

## 10. Correlated monitoring and cross-component state

**Goal:** distinguish saved, deployed, identity-validated, decision-enforced, response-sent and application-blocked states.
**Implementation:** Engine diagnostics and `DnsObservationStore.cs`; Core `EngineStatusPresentation.cs`, `DeviceEnforcementReadiness.cs`, `DnsCoverageEvidence.cs`; WPF MainViewModel; Monitor `monitor.py`, `operations.py`, `topology_ui.py`. Candidate correlation/completion improvements remain local.
**Tests:** Core `RoadmapDataTests.cs`, WPF `RegistrationConsistencyTests.cs`; Monitor `test_operations.py`, `test_gui.py`. Preserved Windows Monitor 60 PASS/22 skips, Linux 63 PASS/19 skips. GUI skips are not human acceptance.
**Status:** GlobalBlock data channel VERIFIED; selected GUI event presentation UNVERIFIED; identity/coverage consistency PARTIAL. **Next:** one real request tracked to visible GUI with provenance and timestamps, no debug dump or fabricated coverage.

## 11. Rollback, generic recovery and integrated acceptance

**Goal:** transactional install/rollback and session-owned exact recovery independent of the agent.
**Implementation:** `network-validator/engine_upgrade.py`, `l2_upgrade.py`; candidate `release_bootstrap.py`, `durable_recovery.py`; roadmap `p0_policy_restore.py`, candidate `prepare_recovery_session.py`, `recovery_activation.py`. Timer loaded state, scheduled next firing, privileges and original states require separate verification. READY IPC is not a validated binding.
**Tests:** `test_engine_upgrade.py`, `test_l2_upgrade.py`; candidate `test_release_bootstrap.py`, `test_durable_recovery.py`, roadmap `test_p0_policy_restore.py`, `test_recovery_activation.py`. Preserved helper Windows 82 PASS/1 skip, Linux 83 PASS; recovery 36 PASS. Rootless interruption fixtures do not prove PID1 reboot recovery.
**Status:** previous guarded deployments have historical evidence; generic recovery CANDIDATE, production UNVERIFIED. **Next:** sealed manifest/pins, non-production transaction and independent restoration gates before privileged activation. Do not leave competing recovery sessions.

## Worktree preservation and release boundary

`dev/orchestrator-m1` and `dev/roadmap-integration` remain separate worktrees; their HEADs are not ancestors of master. Targeted comparison found no missing newer WPF feature requiring automatic integration. An operator-specific orchestrator configuration remains unique and must not be published. Differing source files remain preserved; exhaustive semantic equivalence of every worktree change is UNKNOWN. Do not delete or merge them on this evidence alone.

The 36 tracked local source modifications and 15 new candidate files remain outside this documentation commit. Seven differ from the preserved final candidate manifest, so its test counts cannot certify every current byte. No new build, production action or source integration occurs here. Public documentation omits personal DeviceIds, LAN addresses, credentials and machine paths.

## Next acceptance and priorities

P0: fresh real identity, selective two-client Block/Restore, real DNS responses and visible WPF/Monitor evidence. P1: vendor-independent resolver coverage and isolated mandatory network PEP feasibility. P2: correlated GUI evidence and privacy-bounded retention. P3: one official accepted WPF package, reproducible manifest and artifact retention.

October 13 global `example.com` Block/Restore is VERIFIED; device-specific enforcement, whole-LAN protection and application-independent blocking are not. Preserve useful concepts without presenting a design, worktree or candidate as a completed production feature.
