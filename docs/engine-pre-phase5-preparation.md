# Engine structural preparation

> Historical milestone baseline: this document records behavior and verification at that phase, not the current feature set. Preserve its original test counts. For the current architecture, completed milestones and limitations, see the [README](../README.md) and [Phase 5C baseline](phase5c-upstream-reliability.md).

This pass separates runtime ownership without implementing Phase 5 features.

## Responsibility map

- `Program`: read existing environment settings, validate a startup snapshot, compose components, register cancellation signals, return an exit code.
- `EngineSettings`: validate ports, address families, and timeout; preserve DNS 53 and HTTPS management 3000 defaults. Invalid DNS configuration now fails before listeners open instead of silently substituting addresses or failing on each query.
- `EngineLifetime`: start management then UDP, wait for cancellation/listener completion, stop UDP then management even after partial startup.
- `DnsProxyServer`: own the serial UDP socket, cancellation source, and awaited receive task. No packet concurrency or TCP.
- `DnsRequestProcessor`: preserve existing parse/filter/blocked-response/forwarding decisions without modifying rules.
- `UpstreamDnsForwarder`: own one UDP socket per request and classify response, timeout, cancellation, or transport failure. No retry/fallback/correlation changes.
- `PolicyApplicationService`: serialize API in-memory mutations and return their counts/results. No persistence, revision, restore, or default policy.
- `EngineRuntimeStatus`: expose a fresh read-only transport snapshot. TCP remains unimplemented; listener state is not policy synchronization.
- `ApiServer`: HTTPS ownership, unchanged authentication boundary/routes/limits, named validation/dispatch methods, sanitized errors, deterministic certificate/application cleanup.
- `EngineLog`: sanitized operational categories; no credentials, headers, bodies, or per-query client/domain logging.

`RuleStore`, `DnsProtocol`, Core management clients/security, protected credential storage, and WPF remain unchanged. Existing constructor/start/stop adapters remain for existing callers. Production composition shares one validated settings snapshot; compatibility API callers may correct security input before a startup retry.

## Explicit Phase 5 backlog

1. Fix and test `DnsProtocol.BuildBlockedResponse` AAAA early return: authority/additional counts can describe omitted records. Do this before TCP shares the processor. This defect is intentionally unchanged here.
2. Protocol validation/compression and appropriate failure responses.
3. TCP port 53 framing, connection limits, and shared request processing.
4. Durable authorized policy commit and startup restore, including corrupt/missing data handling. Never generate policy during startup/health/discovery.
5. Upstream response correlation, timeout/retry/fallback policy, and client-facing failure handling.
6. Bounded concurrency, richer runtime states and statistics, and precise policy synchronization results.

No Linux service, firewall, networking, real hosts, production certificate/credential, or deployment changes are part of this pass. Verification uses temporary fixtures and high loopback ports only. The existing Windows control plane and future read-only Linux monitor boundaries remain unchanged.

## Verification (2026-10-02)

- Complete solution rebuild: passed, zero errors, eight pre-existing warnings (six Core AdminService CA1416 warnings; two Console NU1701 compatibility warnings).
- Full regression/security suite: 46 groups passed, including all 39 existing groups and seven preparation groups.
- New coverage: stable/validated settings; atomic in-memory policy application; four upstream outcomes; preserved processor bytes/forwarding; awaited pending-upstream shutdown and restart; partial-startup rollback; cancellation-driven headless lifetime.
- `git diff --check`: passed. Git operations were limited to this read-only whitespace check.
- SHA-256 comparison with pre-pass source copies: DnsProtocol.cs, RuleStore.cs, and EngineConfig.cs unchanged. Core and WPF files were not edited.
- Deliberate failure fixtures emit sanitized operational error events; they are not failing tests.
- Linux signal delivery/systemd integration was not exercised. No production listener, system configuration, or deployment was changed.

Modified: Engine Program.cs, ApiServer.cs, DnsProxyServer.cs, and regression Program.cs.
Added: EngineSettings.cs, EngineLifetime.cs, EngineLog.cs, EngineRuntimeStatus.cs, PolicyApplicationService.cs, UpstreamDnsForwarder.cs, DnsRequestProcessor.cs, regression PreparationTests.cs, and this document.
Deleted: none.
