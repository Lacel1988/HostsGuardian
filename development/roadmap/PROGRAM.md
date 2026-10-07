# HostsGuardian roadmap program

Base product: v0.3.0 / 93d1814f7af9b1a750cde2cc96ebef14aaca9152.
Accepted tooling: a3d4c18cca0cca8d87466beea39077ef629ce7fc.
One writer owns dev/roadmap-integration in the isolated roadmap-integration
worktree. It descends from the accepted tooling candidate; master and the original
candidate remain untouched. Coherent local commits are integration candidates;
there is no automatic publication or production deployment.

## Dependency plan

| Ticket | Scope | Dependencies | Worker / verification |
|---|---|---|---|
| HG-001 | Newest-first Log, filtered view | Tooling development recipe | Windows build + real WPF bindings/order tests |
| HG-E2E | Isolated desktop automation foundation | HG-001 | Windows UI Automation + isolated authenticated Engine fixtures |
| HG-POLICY | Schema evolution, device metadata, groups, catalog, profiles, schedules | HG-E2E | Core/Engine cross-platform precedence/persistence/security tests |
| HG-PREVIEW | Shared effective decision chain, policy diff/preview, backup/restore | HG-POLICY | Core roundtrip/corrupt-input and WPF rollback tests |
| HG-UX | Integrated WPF editors/preview/restore and EN/HU presentation | HG-PREVIEW | Windows desktop/binding workflows |
| HG-ACTIVITY | Bounded activity aggregation, cautious usage estimates and retention | HG-POLICY | Engine privacy/bounds/time-window tests + Linux Monitor |
| HG-INSIGHT | Why blocked and activity/usage presentation | HG-ACTIVITY, HG-UX | WPF actionable summaries; Monitor local detail |
| HG-AUDIT | Revision-aware policy audit and retention | HG-PREVIEW | Engine/WPF history, redaction and bounds |
| HG-HEALTH | One-click redacted health, network context, actionable notifications | HG-E2E, HG-AUDIT | Existing six-state and authenticated event contracts |
| HG-RECOVERY | Bounded recovery, escalation, no policy/security mutation | HG-HEALTH | Isolated failure/recovery fixtures on both workers |
| HG-INTEGRATION | Full regression/build/schema compatibility and evidence | All above | Windows/Core/Linux/desktop |
| HG-LAN | Phase 5E-8 plan/preconditions/rollback/human steps | HG-INTEGRATION | WAITING_FOR_HUMAN; no automatic network/deployment changes |

The requested numbering is scope, not implementation order. Stable identity and
policy contracts precede groups/schedules/decision explanations. Activity/usage
shares a bounded retention model rather than adding unbounded raw telemetry.
Backup/preview protects meaningful policy changes before the new editors are
exposed. Existing six-state status, security, persistence, notifications, bindings
and Engine diagnostics are extended, not replaced.

## Existing extension points and constraints

- FullDnsPolicy schema 2, immutable DeviceId registry and expiring validated bindings.
- PolicyCanonicalization, expected-revision/instance delivery and confirmation.
- DevicePolicyEvaluator and EffectivePolicyExplanation; Engine owns decisions.
- PolicyPersistence strict versioned payloads and protective corrupt recovery.
- DnsObservationStore / DnsTelemetry / authenticated diagnostics and operational events.
- Existing WPF MainViewModel drafts, device rule editing, notification center and
  live EN/HU resource service. New editors should be separate viewmodels/services;
  avoid growing the existing large MainViewModel unnecessarily.
- Existing WPF regressions show actual controls but are not external UI Automation.
- MVP Orchestrator currently allows only read-only probes. HG-001 requires a
  narrowly scoped owned-worktree edit/build/test recipe and durable ticket evidence.
- Schema evolution must retain schema-2 input compatibility and never seed blocked
  domains. A new production Engine deployment is a separate human gate.

## Safety and acceptance

User-confirmed policy precedence: Device override → Active Profile/Schedule →
Device Group → Global rule. Same-layer conflicts retain all candidates and Block
wins over Allow. Preview/explanation exposes winning and overridden rules; conflicts
are not silently discarded. This replaces the preliminary idea of user-numbered
priorities or rejecting equal-priority conflicts.

No production commands, credentials, HOSTS/network/router/firewall/systemd/polkit
changes. Linux runs only in hgworker development directories. Every ticket has
real results/events and evidence paths; dependent tickets stop on failed invariants.
No completed count is claimed until tests and candidate evidence exist. Arbitrary
commands and production operations remain human gates.

## Source candidate scope

Layered schema-3 policy, local WPF authoring/preview/backup, effective explanation,
bounded service activity/estimates, policy audit, redacted health/network context,
actionable operational notifications and bounded transient listener startup
recovery are implemented in the isolated candidate. HG-001 remains committed.
Windows integration checks and Linux same-source verification are required before
all dependent tickets become COMPLETE. See [policy and insight behavior](../../docs/roadmap-policy-program.md)
and [the final human acceptance gate](WHOLE-LAN-ACCEPTANCE.md).

Orchestrator continuation uses an exact source-hash snapshot for owned dirty
trees, capability-routed checks and durable events. It permits no arbitrary shell
or production operation. Development failures remain FAILED attempts with evidence;
corrected attempts are recorded separately rather than relabeled as prior PASS.
