# Phase 5A: committed DNS policy and Emergency Safe Mode

> Historical milestone baseline: this document records behavior and verification at that phase, not the current feature set. Preserve its original test counts. For the current architecture, completed milestones and limitations, see the [README](../README.md) and [Phase 5C baseline](phase5c-upstream-reliability.md).

## Scope and ownership

Production composition uses one `PolicyApplicationService` for authenticated management mutations. DNS requests, health/status, discovery, and Windows Test Connection never commit policy. `RuleStore` remains in-memory only. `PolicyPersistence` alone owns the policy file. No default/test domains are generated. Explicit nonexistent domains in regression tests exist only in temporary fixtures.

`HOSTSGUARDIAN_POLICY_FILE` selects the Engine-owned policy file. The default is `HostsGuardian.DnsEngine/policy.json` under the service account's local application-data directory. Configuration is validated before listener startup. The configured location must be owned by a single Engine process/account and must not be shared between competing Engine instances. No provisioning, real policy file, service configuration, or deployment is performed by this source change.

## Version 1 schema

```json
{"schemaVersion":1,"revision":1,"domains":[]}
```

The file has exactly these properties, with no duplicate/unknown properties. Revision is a positive signed 64-bit integer. Domains are normalized, unique strings sorted using ordinal ordering. Uppercase, URL-form, duplicate, invalid, and unsorted persisted domains are rejected rather than silently normalized. Maximum UTF-8 file/serialized size is 1 MiB. JSON nesting uses the framework's bounded default. No runtime listener, Safe Mode, credential, or upstream status is stored as policy.

## Commit contract

Management mutations are serialized by a service-local gate. Validate and normalize the entire candidate before writing. Write deterministic UTF-8 JSON to a unique same-directory temporary file; flush its data to disk; then replace the destination with a same-directory rename. Rename is the commit point. Only afterward publish the validated rules and revision in memory and return HTTP success. `RuleStore` locks are never held across file I/O. Failed writes keep the prior policy/rules/revision and return a sanitized typed failure, mapped to HTTP 503. Invalid requests are rejected without mutation.

This is a single-process, local-filesystem contract. Same-directory replacement prevents a partially written committed file; orphan `.policy-*.tmp` files are never loaded. File data is flushed, but directory-entry durability under abrupt power loss remains dependent on the filesystem/platform: this portable implementation does not fsync a directory or promise durability beyond the underlying filesystem. A process interruption before rename leaves the previous policy; after rename, restart restores the new complete policy even if the client never received acknowledgement. Deployment filesystem/power-loss verification remains outstanding.

On Unix, newly created policy directories request 0700 and temporary/committed policy files request 0600. Existing directory permissions are not changed. Windows uses the owning account's directory ACL inheritance; no system ACL/certificate/firewall configuration is modified. Symbolic/reparse policy files are rejected. Administrators must supply a private trusted directory; this is not a defense against a malicious local administrator or a hostile ancestor-directory owner.

## Startup ordering and restore

Validate configuration → load/validate policy → establish in-memory policy/Safe Mode → start authenticated HTTPS management → start UDP DNS → publish Running. HTTPS-first preserves startup rollback: invalid management security prevents DNS startup. Restore is complete before either management availability or policy-dependent DNS traffic. Shutdown stops UDP and awaits owned work before stopping HTTPS.

- Missing file: loaded empty policy, revision 0, no new file, no defaults.
- Valid file: exact normalized content and revision restored. InstanceId changes independently on a process restart.
- Invalid/unreadable file: policy not loaded, revision unknown/null, zero active rules, persistence/restore fault, Emergency Safe Mode. DNS still starts and forwards through the normal upstream path, provided other startup requirements succeed.

Corrupt evidence is untouched during startup. Add/remove and Safe Mode exit are rejected while policy is untrusted. An authenticated explicit replace can commit a fresh authorized policy; existing corrupt file evidence is retained as `policy.json.rejected-<unique id>` using replacement backup. Successful replacement does not automatically exit Safe Mode. A separate authenticated exit is required. Evidence is local-only and is not exposed through the API.

## Revision and result semantics

Revision 0 represents a trusted missing-file empty baseline, never a persisted revision. Every successful policy mutation, including an explicit empty replace or no-op add/remove, commits the next revision. Failure and Safe Mode changes do not increment it. Restarts retain the committed revision. An untrusted restore has null revision; explicit recovery replacement starts a fresh revision sequence at 1 because the previous file cannot be trusted. Consumers must use restore state/loaded state with revision, especially after recovery, rather than treating InstanceId as a revision.

Rule-operation responses retain `ok`, `count`/`removed` and add `revision`. Failures provide `ok:false`, sanitized `category` and `error`, plus the previous committed revision/count. No filesystem paths or sensitive details are returned. `PolicyApplicationResult` carries the typed success/failure contract for later client reporting.

## Emergency Safe Mode

Safe Mode is runtime filtering bypass, not process shutdown and not a policy deletion. The DNS processor bypasses matching/blocked-response construction and uses its existing upstream forwarder. Committed rule count/revision remain available; active filtering rule count becomes zero. Exit resumes the existing trusted committed policy. Policy may be explicitly updated while Safe Mode is active, but remains bypassed until exit.

Explicit POST `/safe-mode/enter` and `/safe-mode/exit` accept only an empty JSON object `{}`. They use the same HTTPS/bearer boundary as every management operation; no emergency HTTP or unauthenticated endpoint exists. Health, status, Test Connection, and DNS traffic do not toggle Safe Mode. Safe Mode applies to new request decisions; an already processing request can complete under its captured state.

Safe Mode is not persisted: a new process derives its state from restore (trusted/missing → normal; untrusted → Safe Mode). This phase does not add a persistent local emergency override.

## Read-only status

`DnsServiceStatus` separately reports runtime lifetime state, management listener state, UDP state, TCP implemented/listening (both false), restore state, loaded state, committed revision/count, active count, filtering enabled, Emergency Safe Mode/reason, and persistence fault. Upstream health is explicitly `NotMeasured`; forwarding functionality is not a health guarantee. Manual component startup outside EngineLifetime leaves lifetime status NotStarted rather than inferring Running from one listener.

## Recovery limits and later phases

Engine-only Safe Mode cannot recover from process crash, Linux host/network-interface failure, or a router pointing clients at an unreachable Engine. It also cannot guarantee resolution when the configured upstream is unavailable. No retries, alternative upstream fallback, TCP, or concurrency change is implemented here.

A future independent local Linux administrative command/service action may establish a safe operational override when HTTPS management is unavailable. It must be local/admin controlled, not a second policy-editing GUI or a remote authentication bypass, and must not implicitly change router/DHCP configuration. Full availability recovery may require an explicitly configured external DNS fallback if the host is unreachable. This is design documentation only.

Phase 5B/5C: TCP framing/connection lifetime, bounded processing concurrency, upstream correlation/deadlines/retry/fallback and failure responses, wider protocol/compression validation, runtime metrics, WPF typed revision/state presentation, Linux filesystem/signal/startup/deployment verification, and independently reviewed recovery tooling. No automatic continuation is authorized.

## Verification and file inventory

Complete solution rebuild: zero errors, eight existing warnings (six Core AdminService CA1416 and two Console NU1701 compatibility warnings). Full suite: 63 groups passed, comprising all 46 existing regression/security/preparation groups plus 17 Phase 5A groups. Existing fixture setup now provides explicit temporary policy files/commits rather than using direct in-memory seeding as authoritative policy. Assertions remain intact or strengthened. Tests use the existing temporary certificate/token fixture, isolated directories, and high loopback ports only.

Modified Engine files: ApiServer.cs, DnsProtocol.cs, DnsProxyServer.cs, DnsRequestProcessor.cs, EngineConfig.cs, EngineLifetime.cs, EngineRuntimeStatus.cs, EngineSettings.cs, PolicyApplicationService.cs, Program.cs.
Modified Core file: Models/DnsServiceStatus.cs.
Modified regression files: Program.cs, PreparationTests.cs, SecurityTests.cs.
Added: Engine/EnginePolicyState.cs, Engine/PolicyPersistence.cs, RegressionTests/Phase5ATests.cs, and this document.
Deleted: none.

Linux permissions, directory/rename power-loss behavior, systemd startup, and real Linux signal delivery remain unverified on this Windows host. No deployment or production policy/configuration was accessed. Phase 4 security tests pass unchanged in their expected outcomes; no WPF presentation or transport-security implementation was modified.
