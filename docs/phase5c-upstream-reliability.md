# Phase 5C: bounded UDP work and upstream reliability

## Ownership and admission

DnsProxyServer remains the only UDP receive owner. It admits up to MaxConcurrentUdpRequests (default 16, range 1–64) asynchronous request tasks without Task.Run or an application queue. Before each admission it awaits/reaps completed tasks. When full it drops the newest datagram, including local-block queries; clients may retry. Below capacity a slow upstream request does not delay a locally blocked query. Shutdown cancels and awaits all owned tasks. Worker exceptions are caught and logged without faulting the receive loop. A fatal receive-loop failure cancels its children before completing. ActiveRequestCount is a passive test/diagnostic count.

TCP remains bounded separately (16 connections, sequential queries), and both production transports retain the same DnsRequestProcessor instance. Maximum upstream work is bounded by UDP admission plus the TCP connection cap. No RuleStore lock is held during upstream I/O.

## Attempts and fallback

UpstreamDnsForwarder owns UDP send/receive, response validation, retries and fallback. Each attempt uses a fresh socket and a linked deadline covering send and all receives. UpstreamTimeoutMs is 10–10000 ms (default 2500). UpstreamRetryCount is 0–2 additional attempts per endpoint (default 1). Primary attempts occur first, then the optional explicitly configured fallback. The maximum is six attempts and 60 seconds of configured I/O time; scheduler/OS delay is not a hard real-time guarantee. Default: two primary attempts, 5 seconds, no fallback. There is no retry delay framework.

Timeout, invalid response, transient socket failure and upstream SERVFAIL can trigger the next attempt. Cancellation immediately stops further attempts and does not record upstream failure. Requests too large for UDP are terminal transport failures; another endpoint cannot fix them. Valid negative responses (including NXDOMAIN) are returned unchanged. Exhausted retains the last failure category and attempt count. No undocumented resolver is substituted. The pre-existing default primary 1.1.1.1 is retained; fallback defaults to disabled.

## Configuration

Validated EngineConfig -> EngineSettings precedes all listeners. Optional fallback must be IPv4 with a valid port and must differ from primary. Invalid numeric environment values fail initialization instead of being replaced with defaults.

| Environment variable | Default | Bounds/meaning |
| --- | --- | --- |
| HOSTSGUARDIAN_UPSTREAM_ADDRESS | existing 1.1.1.1 | IPv4 primary |
| HOSTSGUARDIAN_UPSTREAM_PORT | 53 | 1–65535 |
| HOSTSGUARDIAN_FALLBACK_ADDRESS | empty | disabled, or explicit IPv4 |
| HOSTSGUARDIAN_FALLBACK_PORT | 53 | 1–65535 |
| HOSTSGUARDIAN_UPSTREAM_TIMEOUT_MS | 2500 | 10–10000 per attempt |
| HOSTSGUARDIAN_UPSTREAM_RETRY_COUNT | 1 | 0–2 additional attempts per endpoint |
| HOSTSGUARDIAN_UDP_CONCURRENCY | 16 | 1–64 accepted requests |

DNS production listener remains UDP/TCP 53 and authenticated management HTTPS remains 3000. This work changes no installed service/environment/network configuration.

## Response validation and failure contract

The upstream source address/port, transaction ID, QR, opcode, one-question count, wire-label boundaries and octets (ASCII case-insensitive), type and class must correlate. Names require valid label/pointer boundaries and termination; resource-record owner names, fixed fields, section counts and RDATA bounds must fit the packet. Root owner names such as EDNS OPT are allowed. RDATA contents, DNSSEC signatures and every record-specific semantic are not validated. Eight invalid datagrams terminate an attempt; otherwise invalid datagrams are discarded within its unchanged deadline. Valid matching replies after unrelated packets can still succeed.

For a valid supported one-question client query, upstream failure returns SERVFAIL, preserving ID, question, RD and CD, with no answer/authority/additional records. Compressed questions are re-encoded to avoid dangling pointers. Unsupported opcodes, multi-question packets and malformed/unparsed questions are dropped (TCP closes for a null result), not blindly forwarded. The existing domain question parser does not support a root-only question. Existing A/AAAA local blocking and domain-selection behavior are preserved.

TC is distinct: a correlated truncated upstream reply produces Truncated, no additional UDP retries/fallback, then client SERVFAIL. Complete resolution of large/truncated upstream answers needs upstream TCP. It is deliberately NOT implemented in Phase 5C; TCP clients currently use the same UDP upstream and cannot recover this case. This is a known interoperability limitation, not a claim of complete recursive-resolver compatibility. See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-7.3) and [RFC 5452](https://www.rfc-editor.org/rfc/rfc5452#section-9.1).

## Passive status and bounded logs

UpstreamRuntimeState publishes an immutable snapshot under one lock, shared by UDP/TCP forwarding and EngineRuntimeStatus. Status exposes configured primary/fallback, last completed outcome, last successful communication, last failure/time, last-request fallback use and last completed fallback-use time. Historical failure is retained after later success; LastUpstreamOutcome distinguishes it from the most recent outcome. Cancellation leaves observations unchanged. UpstreamHealth remains NotMeasured: configuration and historical success are not active health checks. Status/health/test operations perform no probes and no policy writes.

BoundedEventLog permits one event per fixed category per 30 seconds per component instance. It covers timeout/socket/invalid/exhausted/truncated/fallback and UDP overload/worker/receive failures. No packet names, client identifiers, bearer tokens or certificate secrets are logged. No per-success packet logs are added.

## Preservation and verification

Safe Mode bypasses local filtering through the identical reliability path. No DNS request, retry, fallback or status operation can commit policy or alter revision/Safe Mode. Phase 4 security, PolicyApplicationService/PolicyPersistence/EnginePolicyState/RuleStore, TCP framing/server and EngineLifetime are unchanged.

Existing preparation and Phase 5A fake upstreams now set QR/RA instead of echoing queries as responses. The preparation shutdown fixture uses a long finite timeout instead of -1. Its malformed-client case now asserts drop; supported query/record types still forward unchanged. Tests retain all 75 existing groups and add focused Phase 5C loopback/high-port groups. Two internal delegate seams and InternalsVisibleTo allow deterministic worker-exception and transient-outcome tests without expanding the production abstraction model. Real UDP fixtures independently test transport failure, timeouts, fallback and response correlation.

No production port 53, real public DNS, Windows hosts/networking, Ubuntu/Vivo service, router or firewall operation is part of verification. Deployment, upstream TCP, IPv6 upstreams, broader network portability and Phase 5D/E remain deferred.

Verification: full solution rebuild 0 errors, 8 existing warnings (6 CA1416, 2 NU1701), no new warnings. Full suite passed: 100 groups (75 earlier plus 25 Phase 5C). Read-only git diff --check and explicit added-file whitespace/hash checks complete the verification.
