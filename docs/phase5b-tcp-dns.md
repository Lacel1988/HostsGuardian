# Phase 5B: TCP DNS serving

> Historical milestone baseline: this document records behavior and verification at that phase, not the current feature set. Preserve its original test counts. For the current architecture, completed milestones and limitations, see the [README](../README.md) and [Phase 5C baseline](phase5c-upstream-reliability.md).

## Architecture and lifetime

`EngineLifetime` restores policy, starts HTTPS management, starts UDP, then starts TCP on the same configured `EngineSettings.DnsPort` (production default 53). Startup failure rolls back TCP, UDP, and HTTPS in reverse order. Both listener completion tasks are monitored; cancellation closes active connections and awaits all owned work. No system networking or service configuration is modified.

`DnsProxyServer` retains UDP ownership and exposes its existing processor instance for composition. `TcpDnsServer` receives that same `DnsRequestProcessor` and the same runtime status object. It has no RuleStore reference, matching logic, policy mutation, persistence, or Safe Mode implementation. No changes to DnsProtocol, DnsRequestProcessor, UpstreamDnsForwarder, or Phase 5A commit/restore logic are required.

## Framing and limits

`TcpDnsFraming` reads two unsigned big-endian length bytes, excluding the prefix from the DNS payload. Exact-read operations handle fragmented prefixes/payloads and distinguish clean inter-message EOF from truncation. Payloads shorter than the 12-byte DNS header are closed before allocation. The unsigned prefix bounds allocation at 65,535 bytes. Responses are length-prefixed; NetworkStream.WriteAsync sends the complete buffer, handling partial socket writes.

References: [RFC 1035 section 4.2.2](https://www.rfc-editor.org/rfc/rfc1035#section-4.2.2) and [NetworkStream.WriteAsync contract](https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.networkstream.writeasync?view=net-8.0).

Each connection supports sequential queries with one response per processed frame. There is no parallel query pipelining. TCP has a fixed 16-connection cap, a bounded listen backlog, and 30-second frame-read/write deadlines. Completed tasks are observed/reaped during acceptance and all remaining tasks are awaited on stop. Idle, malformed, disconnected, or excess connections do not alter policy. Malformed/limit log events are emitted at most once per listener startup; no query contents, credential, or certificate secrets are logged.

TCP client transport is independent of upstream transport: allowed/Safe Mode traffic still uses the existing UDP forwarder. If processing returns no response, TCP closes the connection; no synthetic answer, retry, or alternative upstream is introduced. A large TCP request can exceed upstream UDP limits and fail forwarding; upstream TCP recovery requires separately reviewed future work and was not implemented in Phase 5C.

## Status and preservation

TcpImplemented is now true independently of listener activity. UDP and TCP listening flags are updated only by their respective listener owners. Runtime, management, loaded policy/revision, persistence fault, and Safe Mode remain separate. Historical Phase 5A/preparation reports describe their then-current TCP-unimplemented baseline; this document records the Phase 5B change.

Existing architecture/preparation/Phase 5A assertions are updated only where they previously expected TCP to be unimplemented. Matching, policy revision, disk-first commit, restore, Safe Mode, HTTPS/bearer/certificate validation, and protected credential storage are preserved. New tests use temporary committed policy and existing temporary certificate/token fixtures, high loopback ports, and a local UDP upstream fixture. No production port 53 is bound in verification.

## Remaining work

At the Phase 5B baseline, upstream correlation/retry/fallback and failure handling were not yet implemented, and UDP processing remained serial. Phase 5C subsequently added these reliability features and passive upstream observations; active upstream health probing remains unimplemented. Configurable connection limits/timeouts, wider protocol validation/compression handling, IPv6 listener binding, Linux deployment/signal/firewall verification, and real-network interoperability remain future work. No WPF changes, router/DHCP control, Linux/Vivo deployment, or Git synchronization are included. Stop for review before Phase 5C.

## Verification and inventory

Complete solution rebuild: zero errors, eight pre-existing warnings (six CA1416 in Core AdminService and two NU1701 in Console). Full suite: 75 groups passed, comprising the existing 63 plus 12 Phase 5B groups. No new warnings were introduced. Expected malformed-frame, connection-cap, persistence-failure, and startup-conflict fixture log events are not test failures.

Modified: Engine/DnsProxyServer.cs, Engine/EngineLifetime.cs, Engine/EngineRuntimeStatus.cs; RegressionTests/Program.cs, ArchitectureTests.cs, PreparationTests.cs, Phase5ATests.cs.
Added: Engine/TcpDnsFraming.cs, Engine/TcpDnsServer.cs, RegressionTests/Phase5BTests.cs, and this document.
Deleted: none.

The shutdown cancellation filter also covers TcpListener's stopped-listener InvalidOperationException, so stopping between a loop cancellation check and the next accept does not report an Engine fault. All normal errors remain local to their connection; unexpected accept-loop failure is observed by EngineLifetime.

No production DNS port was bound, no real system/network configuration was changed, and no deployment or repository synchronization was performed. Linux/runtime deployment validation remains deferred.
