# Layered policy and product insight development candidate

This is a pre-1.0 source development candidate based on the accepted v0.3.0 product
and Orchestrator M1. It is not a deployed production release. Deployment and
whole-LAN/router acceptance require explicit human action.

## Responsibilities

WPF remains the policy Control Center. Engine executes and analyzes DNS policy.
Linux Monitor shows local operational details. Core shares validated contracts,
canonicalization, preview, backup and effective decision calculation. LAN DNS
does not traverse WPF. Closing WPF does not issue Engine stop commands.

## Authoring and explicit delivery

Use **Policy workspace** for device metadata, DeviceId-based groups, service
definitions, profiles and schedules. Entries are user-authored; catalog entries
alone never block anything. Service definitions have immutable IDs and a
user-supplied definition revision. No example service domains or block rules are
seeded into production. Definitions can be edited/removed; referenced definition
removal fails validation instead of silently cascading away rules.

A profile must explicitly target devices/groups or apply globally. It must be
enabled and either always active or have an active enabled schedule. Schedules
use an explicit IANA time zone and weekdays, with start inclusive/end exclusive.
Overnight windows belong to their starting weekday. Equal start/end is rejected;
it does not secretly mean all day. DST follows the selected zone's local wall
clock. Invalid or unavailable zones are rejected.

Preview/save confirmation applies only to the local draft. Engine delivery
remains a separate explicit action with expected instance/revision and complete
canonical readback. Reading/importing Engine policy replaces local device/program
definitions only after local persistence succeeds; local global selections are
retained. Synchronization is confirmed only when a fresh status instance/revision
and the complete selected policy agree. Connectivity alone is insufficient.

## Deterministic precedence and explanation

1. Device override
2. Active Profile/Schedule
3. Device Group
4. Global rule

More specific applicable layers override less specific layers. In schema 3,
Block wins over Allow at the same layer, including a broader domain Block versus
a narrower Allow. Inherit makes no decision. Domain matching is label-boundary
parent/subdomain matching, never substring matching. Stable IDs provide
deterministic tie/provenance ordering; input enumeration is not priority.

**Why blocked? / Preview** shows a selected device/domain/UTC instant's winning
and overridden rules with rule/group/profile/schedule/service IDs. It labels the
result as local preview. The existing effective-policy readback displays the
Engine's retained chain with revision and identity/mapping evidence. Unknown or
ambiguous bindings never gain another device's group/device policy. Actual DNS
observations retain the winner and three overridden candidates with an explicit
truncation flag; full rules remain in policy/readback and full effective preview.

## Schema and compatibility

Schema 2 remains accepted and retains its existing longest-device-domain behavior.
Optional metadata/program properties are omitted from legacy payloads. Schema 3
adds metadata, groups, catalog, profiles and schedules. It preserves existing
registry, global and override contracts. Persisted outer/nested schema identities
must agree; invalid/corrupt state keeps the protective recovery path.

Schema-3 authoring is canonicalized before persistence/delivery. It has a 48 KiB
policy payload budget and a conservative 128 potential explanation-candidate
budget (including catalog/domain and group/schedule paths). Oversized programs
are rejected before mutation; conflicts are never silently discarded to fit an
API response. These conservative pre-1.0 limits can reject a large policy even
when a particular domain would match few rules. A schema-3 draft is not sent to an
Engine that does not explicitly advertise schema-3 support.

Backups contain canonical policy, product/schema identity and SHA-256, never
endpoints, bearer tokens, certificates or private keys. Duplicate/unknown fields,
bad hashes, invalid references and incompatible schemas fail before replacement.
Restore populates a reviewed local draft; it does not automatically deliver it.

## Activity, usage, audit and retention

**Health and insights** reads authenticated aggregate activity and policy audit.
It clears unavailable datasets instead of showing old values as current. Old
Engines without these endpoints report unavailable, not zero activity.

Activity uses five-minute windows, stable DeviceId where verified, service ID,
and allowed/blocked/failed counts. No raw source addresses or queried domains
are sent to this WPF view. Overlapping service definitions explicitly mark
ambiguous attribution. Usage is the number of windows with successful allowed
activity multiplied by five minutes. This is not screen time; it can overestimate
or miss real usage. Blocked/failed requests alone do not count as usage. Estimates
never create filtering rules or automatically punish a device.

| Data | Retention |
|---|---|
| Raw Engine DNS observations | 15 minutes, 64 memory entries; restart clears |
| Product service activity | 24 hours, 256 memory buckets; restart clears; oldest evicted at capacity |
| Diagnostic graph samples | Existing Monitor 10-minute memory window |
| Engine policy audit | 1,000 durable records; latest 100 exposed per read |
| WPF activity log | 4 MiB rotation trigger, retains latest 1,000 lines; messages capped at 4,096 characters |
| Authorized policy/configuration | Durable until explicit user change; existing corrupt recovery preserved |

Policy audit records management operation, UTC time, previous/effective revision,
success/rejection and policy hash. Management uses a shared bearer capability;
individual human identity is unavailable and is stated explicitly. Unreadable
audit history is preserved and reported unavailable; it does not erase or veto a
valid policy commit. Linux audit files are owner-only. Operational telemetry is
not represented as policy audit.

## Health, notification and recovery behavior

One-click health reads the existing truthful Engine/management/DNS/filtering/
policy/upstream/Safe Mode states, and exports a redacted JSON summary. It includes
a best-effort hash of active interface/gateway evidence. Wi-Fi SSID identity is
explicitly unknown; IP/gateway are not permanent authenticated identities. It
does not modify adapters, DNS, HOSTS, router, firewall or network configuration.

After a successful connection, WPF polls bounded authenticated operational
component evidence every 15 seconds, one request at a time. DNS status still
expires unless refreshed. Unsupported/invalid event reads never fabricate recovery.
Notifications use current component conditions, deduplicate repeated refreshes,
preserve critical escalation, and reuse recent flapping conditions. Desktop
delivery is rate-limited per condition/severity; native Windows toast activation
remains deferred. No raw event stream is forwarded to WPF.

UDP/TCP startup retries only transient bind failures, at most three attempts with
one/two-second backoff. Permission/security/configuration failures are not retried.
Required listener loss after startup still escalates and tears down owned
listeners; no automatic service restart loop is created. Existing bounded
upstream retries/configured fallback remain the upstream recovery mechanism.
Recovery never modifies policy, credentials or host/service configuration.

## Remaining human coverage

Production deployment/migration has not happened. Whole-LAN DHCP, multiple real
clients, populated real-device policy and natural traffic/incident evidence remain
human acceptance work. Known production NeedDaemonReload=yes is retained and must
be investigated in a separate authorized deployment gate; this program does not
run daemon-reload. Wi-Fi-specific native identity, reviewed vendor catalog packs,
native toast activation and subjective visual review are non-blocking follow-up
work, not claims of implemented production coverage.
