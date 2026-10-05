# Linux Engine Diagnostics Console V1

> **v0.3.0 checkpoint scope:** the Engine/Monitor diagnostics contracts below are retained. The candidate WPF operational-event polling described below is not integrated into the retained Windows-accepted WPF source. For current acceptance and limitations, see [the checkpoint record](checkpoint-v0.3.0.md).

Engine owns execution and analysis. Linux Monitor owns local diagnostics and observability.
WPF owns policy control and user decisions, including user notification presentation.

**RAW EVENT != USER NOTIFICATION.** Only important/actionable operational state transitions
cross into WPF notifications. WPF polls the bounded operational-event contract, not raw
telemetry. Raw telemetry stays Engine/Linux-side unless explicitly requested through the
existing protected management API.

This is Engine health/diagnostics, not Network Activity/Analytics. No website visit
counting, service classification, usage-duration estimates, persistent browsing history,
groups, schedules, device fingerprinting, router/DHCP management, or VPN work is included.

## Contract and ownership

`HostsGuardian.Core/Models/EngineDiagnostics.cs` contains versioned transport-neutral DTOs.
Engine `DnsTelemetry` produces measurements; `OperationalHealth` evaluates them.
`EngineDiagnostics` samples once per second independently of viewers and policy commands.
Linux Monitor stores only a ten-minute in-memory visualization buffer. Closing it discards
that buffer, never controls Engine lifetime, and leaves Engine monotonic counters intact.

Protected HTTPS GET routes:

- `/v2/diagnostics`: counters, bounded latency summaries, pressure, resolver evidence,
  runtime context, current operational components.
- `/v2/operational-events?after=N`: at most 64 meaningful transitions, current six-component
  state, process instance, latest cursor, and cursor-gap flag. No telemetry in this response.

Both routes pass through the existing bearer authorization and HTTPS/certificate path.
No new unauthenticated listeners or endpoints exist. Core's event reader retains pinned
certificate validation, redirect refusal, eight-second deadline and bounded response size.
WPF polls events every five seconds using its existing timer, a single-flight guard and
settings-generation checks. Failed reads do not fabricate recovery or change policy. Because an Engine cannot report its own disappearance, a separate client reachability observer requires 15 seconds of network-read failure before one Critical notification and 30 seconds of valid contract reads before recovery. Unsupported contracts do not prove outage or recovery; authentication/trust failures retain existing security presentation.
Older Engines without this route continue supporting existing policy/status functionality.
A single passive upstream failure no longer creates a WPF notification.

Push would require another trusted listener and delivery/security lifecycle, so V1 uses
read-only authenticated polling. Events are memory-only; missed/evicted transitions are
explicit (`CursorGap`). Current component states repair presentation after a cursor gap.
A new instance resets the reader cursor and retires prior-process conditions without
claiming a DNS recovery. Long-lived delivery/audit durability is outside this contract.

The existing schema-1 local status publisher has an additive `diagnostics` member. Old
readers keep working. Ownership, symlink refusal, file bound (128 KiB) and PID/freshness
checks remain intact. Its existing two-second atomic publication interval is retained:
V1 adds no separate disk history and no one-second disk writer. Monitor polls once per
second but only records changed Engine snapshots, so file transport normally yields one
actual sample every two seconds. It does not invent extra graph points. The one-second
Engine evaluator does not depend on local publication being enabled.

## Metrics: purpose and precise meaning

Counters are monotonic within an Engine instance and restart at process replacement.
They have no client/domain labels. `received` counts UDP datagrams and complete framed TCP
DNS messages, including malformed messages; TCP connection acceptance alone is not a query.

| Metric | Definition / diagnostic purpose |
|---|---|
| Received, UDP, TCP | Ingress volume and transport split; received is exactly UDP + TCP in each snapshot. |
| Queries/sec | Monitor delta of received / actual Engine monotonic uptime delta; not an Engine counter. Missing/reset/gap intervals display unavailable. |
| Recent rate peak | Largest valid sampled rate in the retained ten-minute visualization window. |
| Allowed | Processor returned the correlated forwarded upstream response. Does not assert delivery to the client. |
| PolicyBlocked | Processor built the intended policy response. **Successful filtering, never an error.** |
| Failed | Upstream failure/SERVFAIL construction or unexpected processor exception. |
| Rejected | Malformed/unsupported DNS input plus UDP admission-capacity drops. Does not include connection-only rejection. |
| CapacityDropped | UDP datagrams rejected by the real configured admission limit; a subset of rejected. |
| Cancelled | Shutdown/cancellation without a DNS answer; distinct from processing failure. |
| SERVFAIL | Engine-generated server-failure responses; subset of failed. Includes unsupported truncated upstream recovery under existing behavior. |
| UpstreamAttempts | Recorded attempt outcomes, including cancellation; attempts currently awaiting completion are not yet recorded. |
| UpstreamTimeouts | Actual attempt outcomes classified Timeout by the existing forwarder; invalid-response exhaustion remains a failure category, not a Timeout. |
| UpstreamFailures | Timeout, transport failure, invalid response, upstream SERVFAIL and other unsuccessful attempt outcomes; excludes cancellation. |
| UpstreamRetries | Every attempt after the first for one query, including the first fallback attempt. No retry/selection changes. |
| FallbackAttempts | Attempts against the configured fallback. Helps identify primary-resolver trouble hidden by successful fallback. |
| TCP connections rejected | Excess connections closed at the real 16-connection bound; not counted as DNS queries. |
| TransportFailures | Unexpected UDP processing/send or TCP processing exceptions, separate from classified query outcomes. Peer disconnects/idle frame closure are not Engine failure alerts. |
| Upstream recent/P50/P95 | Successful correlated attempt round-trip milliseconds, including network/resolver wait. Truncated correlated responses count as attempt latency but still fail query processing under existing behavior. Failed-attempt timeout duration is not mixed into success percentiles. |
| Processing recent/P50/P95 | Processor-entry through policy evaluation/forwarding/result construction milliseconds; includes blocked work and awaits, excludes receive scheduling/framing and response socket send. |
| Latency sample count / skipped | Evidence sufficiency and instrumentation sampling loss. No samples means unavailable, not zero latency. |
| Resolver address | Fixed configured primary/fallback endpoint only; no dynamic/high-cardinality labels. |
| Resolver attempts/timeouts/failures/retries/fallback/latency | Same attempt definitions scoped to that configured endpoint. |
| Resolver state | RecentSuccess / RecentFailure / Cancelled, expiring after 60 s to NotMeasured. This is latest-attempt evidence, **not** a persisted incident or notification. Aggregate operational analysis is separately shown. |
| Current/peak requests | Currently executing/awaiting processor calls; peak is process-lifetime, not a misleading recent peak. |
| UDP current/capacity | Real active UDP processing and configured `MaxConcurrentUdpRequests` (1–64). |
| TCP current requests/connections/capacity | Active framed processing and retained connections against the real 16-connection bound. Idle connections remain pressure on connection capacity. |
| Uptime, PID, start time, assembly revision | Monotonic process uptime and process/revision identification; counters/history reset by instance. Assembly version is not represented as a Git revision. |
| CPU | Process CPU time / elapsed monotonic time / logical processor count, percent of all logical CPU capacity. Secondary signal only. |
| Working set | Process resident memory bytes, not heap or whole-host RAM. Secondary signal only. |
| Health/components | Persisted operational incidents evaluated by Engine, independent of raw event/log volume. Healthy means no detected persistent incident, not proof of upstream reachability during idle time. |

Results percentages are lifetime answered/rejected outcomes (allowed + blocked + failed +
rejected), exclude cancellations, and do not add timeout/SERVFAIL subcategories twice.
Socket-delivery errors are separate because successful response construction is already
counted. TCP malformed framing rejected before a complete message is not invented as a
received DNS query. The UI labels these limitations in the details/contract.

## Bounded sampling, snapshots and performance

Each latency stream has eight fixed shards, each 256 observations, maximum 2,048.
Observations expire at 60 seconds and oldest slots are overwritten. High volume may retain
less than 60 seconds, and pooled per-thread shards are an approximate recent distribution,
not a complete traffic-weighted histogram. Percentiles use nearest-rank selection.
The query path uses primitive counter updates, Stopwatch timestamps and `Monitor.TryEnter`
on one shard. It never waits for percentile readers/writers; skipped writes are counted.
There are no per-sample objects, request retention or query-domain metric structures.
Sorting/copying samples happens in the diagnostics reader outside query processing.

Atomic counters are adjacent-in-time read snapshots, not a transactional freeze of workers.
Received split and completed outcome totals are derived from the same captured components;
SERVFAIL and capacity-drop subsets are included through exclusive outcome sums. Active
requests, resources, latency summaries and resolver counts can describe nearby instants.
No policy mutation or coherence/security guarantee is inferred from these measurements.
Existing immutable policy publication and filtering behavior remain unchanged.

Health retains at most window-seconds + 2 counter snapshots (default 32); configuration
bounds prevent unbounded queues. Incidents are six fixed component states and at most 64
transitions. Monitor deque is capped at 600 samples and trimmed to 600 elapsed seconds.
Graphs use a zero origin, readable 1/2/5 ceilings over the retained window, retain spikes,
break lines across unavailable/long intervals, and distinguish missing latency from zero.
GTK native snapshot rendering needs no Python Cairo foreign-struct binding. Graph work
occurs entirely in the unprivileged viewer, not in the DNS process.

## Automatic health rules and rationale

`HealthDefaults` is the centralized advanced-override foundation; AUTOMATIC defaults are
used in production. There is no threshold-management UI or policy-setting expansion.

| Rule | Initial default |
|---|---|
| Counter evidence window | 30 s; at least 10 observations to avoid sparse-sample alarms. |
| Upstream warning | Failed attempt fraction >= 20%, or successful-attempt P95 > 500 ms with >= 10 latency samples; condition persists 15 s. |
| Processing warning | Failed queries + actual UDP capacity drops >= 20% of non-cancelled completed processing outcomes, or at least 10 transport failures in the window; persists 15 s. |
| Processing critical | Impact fraction >= 50%, persists 30 s. Severe symptoms warn after 15 s, then escalate within the same incident. Policy blocks stay in successful outcomes. |
| Capacity warning | At least 10 real UDP admission drops or TCP connection rejections in the window; persists 15 s. No invented queue/pressure percentage. |
| Listener/API serious failure | Explicit listener fault or unavailable required listener while runtime is Running/Degraded: immediate Critical. Starting/stopping is not an outage. |
| Persistence | Reported policy persistence fault, or policy unavailable while Running: immediate warning. No policy repair, reset or Safe Mode mutation. |
| Recovery | 30 s confirmed better evidence; failure fraction <= 5%, upstream P95 < 300 ms (if samples exist). Listener readiness/persistence recovery also persists 30 s. |

These are conservative initial home-DNS defaults, not externally mandated standards.
500 ms sustained DNS latency is noticeable; the 300 ms recovery boundary provides
hysteresis. Ratios require volume and sustained windows; one 800 ms observation surrounded
by normal traffic does not dominate P95 or raise an incident. Failure symptoms have priority
over CPU/RAM, which never trigger health transitions. Upstream and processing cannot recover
merely because DNS traffic disappears: insufficient/newly absent evidence holds the incident.
Capacity recovers once a real no-drop window persists. A rolling window inherently delays
both detection and recovery; it does not promise reaction at exactly wall-clock 15/30 s from
the first individual bad query.

Events carry sequence, Engine instance, incident identity, component/type, Warning/Critical/
Recovery severity, UTC occurrence, current state, semantic summary identifier and recovery
relationship. Warning-to-Critical escalation retains incident identity. Repeated unresolved
states emit nothing. Recovery refers to the previously reported incident. WPF localizes
component presentation in EN/HU, escalates once, and keeps critical conditions visible even
when category delivery is muted. Desktop bindings/visual acceptance remain a Windows gate.

## Device boundary and deployment

Existing bounded actual-query diagnostic observations are preserved and not expanded.
“Forget diagnostic observation/history” would clear diagnostics only. “Delete/unregister
managed device” belongs to WPF and controls registration/policy decisions. They are not the
same operation; diagnostics never deletes DeviceId, registration, policy or authorization.
V1 implements neither deletion operation.

Build/test loops use controlled loopback/high ports and temporary self-signed fixture
credentials. No production port-53 mutation, live policy edit, router/DHCP or systemd change
is used to prove charts. The installed Engine does not gain these measurements until the
new artifact is explicitly deployed. User-owned artifacts and hashes are prepared; replacing
the running service or installed Monitor is a separate privileged human deployment checkpoint.
