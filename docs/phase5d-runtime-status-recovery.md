# Phase 5D — runtime, status, recovery and failure hardening

This is the source-level Phase 5D milestone. Phase 5E Linux/LAN deployment verification has **not** begun. The starting checkpoint was `db761c97f6db24935f468ce9eda020e2d26ca319`; no history changes, staging, commit or push form part of this phase.

## Purpose and audit

Report confirmed observations rather than requested state. The read-only audit covered composition/lifetime, configuration, HTTPS management, UDP/TCP ownership, the shared DNS processor, upstream observations/retries, policy application/persistence/RuleStore, logging, Core adapters, WPF commands/settings and existing tests.

| Finding | Phase 5D action |
| --- | --- |
| Separate volatile transport reads could report Running after a required listener stopped | Publish lifecycle/transport values under one short snapshot lock; derive Degraded when any required listener is absent |
| Listener bind/receive failure had no explicit transport fault category | Preserve NotStarted/Starting/Listening/Stopped/Faulted per transport; fault evidence survives cleanup and resets on explicit component restart |
| Management application termination was not a lifetime completion input | Observe ApplicationStopped alongside UDP/TCP completion; clean up all owned listeners on unexpected termination |
| UDP fatal receive errors could continue indefinitely as apparently healthy | Treat fatal receive errors as faults; preserve recoverable datagram-local reset/refused notifications and bounded logging |
| GUI used Enabled/configuration/history instead of confirmed live status | Use a shared, testable Core presentation model; show unknown/stale and explicit observation time |
| Fire-and-forget Engine commands could escape their outer exception handler | Await requests on the WPF dispatcher, guard concurrent commands and handle asynchronous failures within the command |
| HTTP success/`ok` alone could be interpreted as policy confirmation | Require positive durable revision/exact count; WPF additionally reads authenticated status before claiming synchronization |
| A reused revision on a different Engine could inherit synchronization | Associate synchronization with Engine instance identity; invalidate when selection or endpoint changes |
| Malformed/contradictory status and arbitrary category text could reach the GUI | Validate known categories, policy/count invariants, ports and required listener consistency; classify incompatible responses |
| Local hosts refresh failure left the old indicator looking current | Show local hosts UNKNOWN / ERROR; restore ACTIVE/INACTIVE only after a successful read |

Healthy configuration, DNS wire protocol/processing, policy persistence/application, RuleStore, bounded upstream behavior and logging were preserved. No policy schema, DNS answer, retry/fallback, authorization or trust redesign was needed.

## State contract

Authenticated HTTPS connectivity uses the existing `ConnectionState` categories: Authenticated, Unreachable, Timeout, NetworkFailure, TrustFailure, AuthenticationFailed, CredentialUnavailable, InvalidSettings, Incompatible and EngineError. Not checked/pending/stale are presentation states, not proof that the server is offline or filtering disabled.

The version-1 `/dns/status` response preserves Phase 5A–5C fields and adds a snapshot UTC time plus explicit UDP, TCP and management listener state. Transport booleans describe the same publication as their state strings. Lifecycle is NotStarted, Starting, Running, Degraded, Stopping, Stopped or Faulted. Running requires all three listeners to be listening. A Degraded observation may be brief while fail-fast lifetime cleanup proceeds; it is not a promise that a failed subsystem will be automatically restarted.

Policy remains an immutable publication: restore state, loaded flag, committed revision/count, active count, Safe Mode/reason and persistence fault. Policy mode and active rule count describe filtering decisions **when DNS can serve requests**; they are not a claim of DNS availability. Safe Mode keeps the durable policy and revision while active count becomes zero. A missing file is the existing empty revision-zero baseline; invalid/unavailable policy enters Safe Mode. Explicit authorized replacement and explicit Safe Mode exit remain required for corrupt-policy recovery.

Upstream state remains passive: configured primary/fallback, latest completed outcome, last success/failure, failure category and fallback observations. Historical failure information can remain after a newer success. Cancellation does not replace a completed observation. Status never sends an upstream probe, and upstream failure does not mark HTTPS management offline.

Lifecycle values are captured under a short lock, while policy and upstream each supply their immutable snapshot. There is no global lock over DNS/upstream I/O and no claim that independently evolving subsystems share one transactional instant. Related policy fields always come from one publication.

## Startup, shutdown and partial failure

Production composition restores authorized policy before starting HTTPS, UDP, then TCP. Startup reaches Running only after required starts succeed. Bind/security/init failures return failure, retain fault status and release resources in reverse order. Runtime observes management, UDP and TCP completion. Unexpected required listener termination returns failure and stops remaining owned components; no hidden policy reset or service-manager restart occurs.

Shutdown cancels receive/accept/owned request work, closes sockets and awaits owned UDP workers/TCP connections. Normal cancellation is a clean Stopped result, not an operational failure. HTTPS shutdown retains its existing deadline and credential zeroing/certificate disposal. Cleanup failures still produce a failure exit. A UDP peer-reset/refused notification is local to the datagram; fatal receive failures cannot spin forever behind a healthy indicator.

## Requested versus confirmed state and WPF

Engine actions follow request → acknowledgement → authenticated status → confirmed state. WPF displays management connectivity, Engine lifecycle, UDP/TCP, filtering/Safe Mode, policy revision, committed/active counts, restore/persistence state and latest passive upstream outcome separately, using the existing visual system.

A policy update must acknowledge a positive revision and the exact normalized selected count. WPF confirms synchronization only when subsequent status matches that revision/count and the local selection has not changed during the request. Ordinary diagnostics can show current policy but cannot establish a previously unconfirmed synchronization. Compatibility adapters report a validated commit acknowledgement, not a claim of current synchronization.

Failure makes current filtering/synchronization unknown immediately. Last confirmed data is retained only as timestamped historical information. Successful observations expire after 30 seconds; a five-second passive UI timer updates the display without sending requests. Settings changes discard old endpoint observations, and settings generations prevent in-flight responses from repainting a new endpoint. The connection dialog labels results as timestamped observations, displays actual TCP listening rather than merely implementation support, and invalidates changed drafts. Save and Test Connection remain policy read-only.

Local hosts indicators remain independent. A failed hosts read reports UNKNOWN / ERROR rather than turning off or changing hosts policy.

## Recovery and security boundaries

Recoverable upstream communication updates its later passive outcome normally. A persistence write failure retains prior revision/rules; a later explicit authorized retry can clear the fault after durable success. Safe Mode neither deletes policy nor silently exits following replacement. Component restart/cleanup remains local to the process; required listener failure is fail-fast rather than an automatic retry loop.

Bearer authentication, HTTPS-only management, explicit enrollment/name/expiry validation, protected Windows credentials, bounded requests/replies, safe response categories and sanitized operational logs are preserved. No anonymous recovery/policy endpoint, credential-generation endpoint, plaintext credential persistence, HTTP fallback or automatic enrollment was added. Health/status reads do not write policy or revisions.

A host/process/network outage cannot be repaired through an unreachable API. Local administrator/service recovery, permissions, firewall and port conflicts remain deployment concerns; the GUI does not control Linux services or network configuration.

## Verification

The complete suite preserves all **100 Phase 5C groups** and adds **41 Phase 5D groups**: **141/141 pass**. Coverage includes clean start/restore/corruption, authenticated management with DNS faulted, UDP/TCP/API startup failures, independent listeners, fatal versus datagram-local UDP errors, upstream failure/recovery, Safe Mode retention, read-only diagnostics, authentication/trust/timeout/network/incompatible classifications, revision acknowledgement/mismatch, stale/unknown/pending GUI state, instance identity, owned-work cancellation, management termination, sanitized fault logs, disk failure/retry and concurrent policy/lifecycle reads.

Existing tests were not weakened. The existing recording adapter fixture now includes actual API acknowledgement fields (revision/count) required by the strengthened contract; all original groups still execute.

Complete solution rebuild: **0 errors**, **6 existing CA1416 + 2 existing NU1701 warnings**, no new warnings. Regression fixtures use temporary credentials/certificates/policy files, loopback clients and high ports. DNS servers retain their production IPv4-any bind behavior on these high ports; tests do not bind port 53 or contact household/Internet resolvers. No production provisioning or system configuration was performed. Whitespace checks include new files; candidate artifacts are checked separately from ignored build output.

## Remaining limitations and Phase 5E

- Source/automated verification is not real Linux/LAN readiness and does not replace manual WPF review.
- This is a compact status presentation, not a complete Safe Mode control/revision history dashboard. There is no background polling, remote restart or automatic listener repair.
- Status is a recent observation, not an assurance of continuous availability. Expiration is a UI freshness convention; UTC clocks are not synchronized by this application.
- The architecture remains fail-fast on required listener failure. A monitor may miss its brief degraded/faulted interval before the process exits.
- Existing upstream limitations remain: UDP/IPv4 upstream only, no TCP truncation recovery or IPv6 upstream claims.
- Per-device Engine enforcement, router/DHCP integration, discovery/pairing, network portability and Linux graphical monitoring remain future work.
- Phase 5E must explicitly verify Linux runtime/service permissions, durable filesystem behavior, production UDP/TCP port 53 and HTTPS 3000, LAN/firewall/service conflicts, and manual GUI behavior. It has not begun.

See the [README](../README.md) and preserved [Phase 5C milestone](phase5c-upstream-reliability.md).
