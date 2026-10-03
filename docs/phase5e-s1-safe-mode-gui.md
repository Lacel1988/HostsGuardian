# Phase 5E source gate S1: Safe Mode GUI/Core completion

S1 is a source-level prerequisite for deployment acceptance. It does not complete Phase 5E or demonstrate real Linux/LAN readiness. The historical [Phase 5D baseline](phase5d-runtime-status-recovery.md) remains 141 groups; S1 adds 27 focused groups for **168/168 passing**. Complete rebuild: **0 errors**, the same **6 CA1416 + 2 NU1701 warnings**, no new warnings.

## Official management path

Windows WPF calls Core through the existing authenticated HTTPS transport. Core posts an empty JSON object to the existing `safe-mode/enter` or `safe-mode/exit` endpoint. No new Engine endpoint, management client, authentication mechanism, HTTP fallback, trust bypass, credential storage mechanism, or production provisioning is introduced.

## Requested versus confirmed

An HTTP acknowledgement alone is insufficient. Core validates the acknowledgement, then reads authenticated health/status. Confirmation requires matching policy revision and committed count, the requested Safe Mode state, and the corresponding filtering state. Enter requires filtering bypass; exit requires loaded policy and resumed filtering. Revision zero and the nullable revision of untrusted policy are supported without inventing a policy revision.

A failed command, failed readback, malformed acknowledgement, contradictory snapshot, or superseded revision/count returns unconfirmed state. There is no automatic mutation retry. A later explicit Test Connection can establish current observed state, without claiming the earlier command caused it.

## WPF behavior

The existing Engine panel now has explicit ENTER SAFE MODE and EXIT SAFE MODE controls, a confirmed/Unknown Safe Mode label, and an expandable read-only status detail panel. It reuses existing styling and the Phase 5D presentation cache and passive expiration timer.

Commands require current authenticated management listening state and a Running/Degraded Engine. Enter is available while Safe Mode is off; exit requires Safe Mode and loaded policy. Both CanExecute and execution guards enforce these conditions. Pending, failed, expired, or unknown state disables controls. After 30 seconds the existing cache expires; old confirmations remain historical only. The GUI awaits asynchronous commands, catches failures, and ignores responses from an obsolete connection-settings generation. No GUI thread blocking is introduced.

## Policy and runtime guarantees

Safe Mode remains runtime-only. Enter retains policy bytes, revision, and committed count while active rules are bypassed. Exit resumes retained policy without rewriting it. Valid policy is restored on restart according to the existing Engine contract. A restore fault prevents exit until explicit authorized policy replacement succeeds, followed by a separate explicit exit; replacement does not implicitly exit Safe Mode. Safe Mode cannot repair a failed host, listener, or upstream.

Actual loopback HTTPS tests prove byte-for-byte policy preservation on enter/exit, unchanged corrupt evidence on rejected exit, explicit recovery ordering, and absence of a newly invented policy file for empty-policy transitions. Existing Engine forwarding and persistence regressions are retained unchanged.

## Read-only operational details

The existing authenticated status contract already provides every S1 field; no contract extension was necessary. Details show Safe Mode reason, policy restore state/loaded flag, persistence fault category, passive latest upstream outcome, success/failure UTC timestamps, historical failure category, last-request fallback observation and fallback timestamp/configuration, and independent runtime/management/UDP/TCP states.

No traffic probes or policy operations run while rendering details. Historical upstream failure is explicitly distinguished from current outage. Unobserved fallback is labeled Not observed. Failed or expired observations display Unknown, retaining only a historical confirmation timestamp. The contract exposes listener/runtime state categories, not detailed fault explanations; the GUI does not invent unavailable error information.

## Verification and remaining acceptance

All 141 existing groups pass unchanged. The 27 S1 groups cover authenticated enter/exit request shape, acknowledgement/readback separation, both contradictory transitions, revision/count supersession, malformed acknowledgement, rejection without retry, distinct timeout/unreachable/authentication/trust failures, stale controls/details, restore restrictions/reason, passive history, fallback immutability, listener/filtering separation, pending/unavailable guards, actual HTTPS policy preservation/recovery/empty-policy handling, actual authentication/certificate rejection, and WPF asynchronous command/binding wiring.

WPF wiring is checked without launching the GUI against real hosts/network configuration. Manual WPF interaction and real Linux/LAN integration remain acceptance work. Source tests use temporary policy/security fixtures and loopback high ports; no real port 53, production credentials/certificates, Linux/Vivo access, deployment, firewall/systemd/router/network change, or Git staging/commit/push occurs.

Before real deployment, Phase 5E-2 host preflight and explicitly authorized Linux integration must establish actual listener/service conflicts, filesystem permissions, certificate/credential provisioning, upstream reachability, shutdown/restart behavior, LAN DNS paths, and manual WPF acceptance. Per-device enforcement, upstream TCP recovery, IPv6 upstream resolvers, discovery/pairing, remote protection, and a Linux monitor remain outside S1.
