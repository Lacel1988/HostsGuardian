# HostsGuardian v0.4.0 — topology and validated network foundation

This pre-1.0 development release reconciles the accepted integration source onto
master after v0.3.0 (`93d1814f7af9b1a750cde2cc96ebef14aaca9152`). It creates a
source checkpoint; it does not deploy or change any running system.

## Scope

- Dual-stack UDP/TCP DNS; explicit authenticated policy delivery/readback.
- Registered device inventory, user-confirmed metadata authority, explicit Forget,
  safe provisional correlation and retained explainable fingerprint classification.
- WPF registration reconciliation, type selector, progressive disclosure, localized
  identity/presence/DNS/coverage states and newest-first filtered logs.
- Device-aware Engine publication and Linux Monitor identity/activity diagnostics.
- Bounded validated IPv4 binding and dedicated NetworkValidator trust boundary:
  root/PID1 listener, peer credentials, live Engine MainPID and peer-pidfd checks.
- Engine CAP_NET_BIND_SERVICE only; helper-only CAP_NET_RAW design. Active ARP
  remains OFF by default and awaits separately authorized real-LAN acceptance.
- Evidence-driven Topology, independent functional dual-stack readiness checks,
  retained candidate/rollback diagnostics and LF-only direct-launch package gates.
- Native Windows notification/schedule-warning source and deterministic coverage,
  separate from remaining real notification/schedule UX acceptance.
- Development Orchestrator and isolated desktop UI Automation tooling.

Shared/Core/Engine/WPF source was compared with the preserved accepted source
manifest before reconciliation. The only later pre-release differences were the
authorized Monitor packaging fix. Release-specific changes are version metadata,
English/Hungarian documentation and portable development configuration examples.
No production state, security material, packages, external evidence or build output
is included in the commit. Existing screenshots remain explicitly historical.

## Release verification — 2026-10-07

| Check | Result | Limits |
|---|---|---|
| Core/Engine, Windows | **302 regression groups PASS** | Isolated service/network/security fixtures; no production requests or service changes. |
| Core/Engine, Linux | **302 regression groups PASS** | Same reconciled implementation in an unprivileged development fixture. |
| WPF | **31 regression groups PASS** | Real bindings/rendering, registration lifecycle, language and notification fixtures. |
| Windows desktop UI Automation | **9 assertions PASS** | Separate fixture processes; mocked authenticated management contract, not production TLS or LAN acceptance. |
| Monitor, Linux | **82 tests PASS; no skips** | Isolated Broadway/GTK fixture, including Cairo drawing and all seven packaging regressions. |
| Monitor, Windows | **60 PASS; 22 platform tests skipped** | GTK/rendering and POSIX execution/mode tests require Linux; skips are not failures. |
| NetworkValidator/helper/installer, Linux | **35 tests PASS; no skips** | Peer credential/pidfd/readiness and synthetic exact-target packet fixtures; no raw production probing. |
| NetworkValidator/helper/installer, Windows | **34 PASS; 1 Linux test skipped** | The Linux system-bus/pidfd platform fixture is not claimed as run on Windows. |
| Orchestrator | **30 tests PASS on each platform** | Owned temporary repositories/fixtures; no production operations. |
| Dual-stack readiness | **4 tests PASS on each platform** | Local functional DNS fixtures, deadline exhaustion and family-report independence. |
| Monitor 0.4.0 Debian package | **PASS** | Unprivileged build; extracted launcher directly executed, GTK/Cairo/Topology imports pass, no window/service action. |
| Solution Release rebuild | **0 errors; 12 warning occurrences** | Existing Windows-platform analyzer and nullable warnings retained. |
| Source hygiene and diff checks | **PASS** | Explicit inventory, no credential/state/archive/output additions; LF launcher and executable modes retained. |

The seven packaging tests reject CRLF/BOM/invalid shebangs/non-executable modes,
exercise the actual Linux CRLF interpreter failure, and ensure smoke runs the
launcher directly rather than hiding the defect behind `python launcher`.
Package smoke is not human visual acceptance. Fixture network traffic does not
prove whole-LAN device coverage, real native toast appearance or live ARP safety.

## Version identity

- Product `Version`: 0.4.0; assembly/file versions: 0.4.0.0 in Directory.Build.props.
- Monitor Debian changelog: 0.4.0.
- Candidate packaging: 0.4.0+roadmap.<commit> and 0.4.0+topology.<source identity>.
- Protocol/API/schema/dependency versions and historical release records unchanged.
- Release commit: `release: HostsGuardian v0.4.0 topology and validated network foundation`.
- Annotated tag: `v0.4.0`.

## Remaining human acceptance

The accepted Engine/NetworkValidator deployment foundation is preserved. Active
ARP remains disabled. Controlled live validation, populated per-device enforcement,
randomized-MAC user-directed continuity, broader natural incident/traffic coverage,
whole-LAN/alternative resolver coverage, native notification/schedule UX, and the
Monitor-only LF repair's production launch/Topology visual review remain separate
human gates. Source tests do not imply that pending deployment/visual work occurred.

Unknown access technology/resolver path/coverage remains a valid evidence state.
Optional infrastructure integrations are not a prerequisite. Service catalog,
groups/profiles/schedules have implemented schema/editor/fixture coverage but are
not presented as fully accepted household workflows; temporary extensions remain
deferred. The earlier systemd reload caveat was investigated and cleared for the
accepted deployment; this release performs no daemon-reload, restart or deployment.

**Production Vivo was not modified by this release task.**
