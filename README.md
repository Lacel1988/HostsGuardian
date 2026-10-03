# HostsGuardian

HostsGuardian is a custom C# DNS filtering system with a Windows WPF control plane and an Engine targeting Linux x64. It combines explicit domain policy, local Windows hosts-file blocking, and network DNS filtering without depending on another filtering engine.

## Why HostsGuardian

The project explores a readable, testable DNS service with separate transport, policy, persistence, and management responsibilities. It is a portfolio project under active development, not a deployment-certified network appliance.

## Architecture

```text
Windows WPF -> Core -> local Windows hosts file
      |
      +-> authenticated HTTPS management, port 3000 -> custom Engine

LAN clients -> UDP/TCP DNS, port 53 -> HostsGuardian.DnsEngine
                                    |-> shared DnsRequestProcessor / RuleStore
                                    +-> configured upstream DNS over UDP
```

WPF is the primary user-facing management client and is outside the DNS packet path. Core supplies shared models, policy selection, Windows services, and the management client. The custom Engine owns DNS processing, committed policy, and its management API. Linux x64 is the deployment target; no particular host or ISP is required. The solution retains a legacy Console project, which is not the intended Engine control plane.

## How filtering works

- Domains must be explicitly selected for **HOSTS**, **DNS**, or both. Missing flags do not authorize filtering. Saving GUI preferences does not apply hosts changes or push DNS policy.
- Local hosts application uses only HOSTS-selected names, with IPv4 `0.0.0.0` and IPv6 `::1` entries for the exact name and its `www` alias. It preserves unrelated content, recognizes existing markers, and backs up before writes. Hosts entries have no wildcard semantics.
- Explicit DNS push replaces Engine policy with DNS-selected names. A selected name also matches its descendants; selecting a subdomain does not authorize its parent.
- Blocked A queries receive the configured blocked IPv4 address (default `0.0.0.0`). Blocked AAAA queries receive NOERROR with an empty answer. Other record types are forwarded; this is not an all-record-type policy engine.
- Allowed requests use the configured UDP upstream. Client UDP and TCP share `DnsRequestProcessor`.

Discovery is best-effort. Normalized MAC addresses are preferred persisted identities, IP addresses are current observations, and legacy IP-only policy is not automatically assigned to a different device. Saved device preferences do not constitute complete per-device Engine enforcement: the current domain ruleset is global.

## Security

Management uses HTTPS on port 3000 with bearer authentication on every endpoint. Missing or invalid credentials/certificates prevent management startup; DNS starts only after management startup succeeds. WPF protects saved credentials with Windows DPAPI and requires explicit certificate enrollment with independent SHA-256 fingerprint verification. Live checks verify enrolled identity, host identity, validity, and server-auth use. There is no HTTP downgrade or silent enrollment.

WPF is the intended client; token possession authenticates access, not executable identity. Keep management private through appropriate binding and network/firewall restrictions. The default binding is loopback. Certificates and credentials are explicit deployment inputs, not repository assets. Internet remote-management/protection workflows are not implemented.

## Reliability and Safe Mode

- Authorized management updates commit policy to disk before acknowledging success. Restart restores committed normalized policy and its revision; startup generates no blocked domains.
- Corrupt/unavailable policy enters Emergency Safe Mode with no active filtering. Explicit authenticated replacement preserves rejected evidence and requires a separate Safe Mode exit.
- Safe Mode bypasses filtering through the same upstream path without deleting policy or changing its revision. It is runtime state, not persisted across restart. It cannot recover a failed host or unreachable upstream.
- UDP work is bounded: default 16 requests, configurable from 1–64. At capacity the newest datagram is dropped. Below capacity a slow upstream request does not serialize unrelated local blocked replies. Shutdown cancels and awaits owned work.
- TCP supports sequential framed queries with a 16-connection cap and bounded frame I/O.
- Upstream retries are finite. Default: two attempts at 2.5 seconds each against the primary. Optional explicitly configured fallback follows primary failure; no fallback is silently invented. The existing primary default is `1.1.1.1` and is configurable.
- Upstream replies are checked for source endpoint, transaction ID, response/question correlation, wire-label identity, and structural bounds. Supported queries receive SERVFAIL when forwarding fails.

Health/status and Test Connection are policy read-only. Connectivity, listener state, filtering/Safe Mode, policy revision, and passive upstream observations are separate concepts. Unreachability does not prove filtering has been disabled. WPF displays confirmed runtime, listener, filtering and policy snapshots; failed/expired observations become unknown. Policy synchronization requires a matching acknowledged revision. WPF provides explicit, guarded Safe Mode enter/exit commands confirmed by authenticated status and read-only operational details. A revision history dashboard remains unimplemented. See [Safe Mode source gate S1](docs/phase5e-s1-safe-mode-gui.md).

## Development and testing

Use the .NET 8 SDK on Windows for the complete solution, including WPF:

```powershell
dotnet restore HostsGuardian.sln
dotnet restore HostsGuardian.RegressionTests/HostsGuardian.RegressionTests.csproj
dotnet build HostsGuardian.sln --no-restore -t:Rebuild
dotnet run --project HostsGuardian.RegressionTests/HostsGuardian.RegressionTests.csproj --no-restore
```

The regression executable is separate from the solution build. Tests use temporary policy/security/hosts fixtures and high loopback ports; they do not query public DNS or change real hosts/network configuration.

Verified Phase 5C baseline: **100/100 regression groups pass** (75 earlier groups preserved, 25 added). Complete rebuild: **0 errors**, **6 existing CA1416** platform warnings and **2 existing NU1701** package compatibility warnings; no new warnings.

**Automated verification does not establish real Linux/LAN deployment readiness.** Source/build verification also does not replace manual GUI review.

See [management security](docs/phase-4-review.md), [policy and Safe Mode](docs/phase5a-policy-and-safe-mode.md), [client TCP DNS](docs/phase5b-tcp-dns.md), and [current upstream configuration/reliability](docs/phase5c-upstream-reliability.md). Earlier phase documents are historical milestone records. Engine startup requires explicit credential/certificate paths; build/test commands perform no production provisioning or deployment.

Phase 5D verification: **141/141 regression groups pass** (all 100 Phase 5C groups preserved, 41 failure/status groups added). Rebuild remains **0 errors**, the same **8 existing warnings**, and no new warnings. See [runtime/status/recovery hardening](docs/phase5d-runtime-status-recovery.md). These are automated source-level checks; Phase 5E deployment verification has not begun.

## Current limitations

- Upstream is UDP only. Truncated replies produce failure/SERVFAIL; upstream TCP recovery is not implemented, including for TCP clients.
- IPv6 upstreams are unsupported by configuration; real-network IPv6 behavior is not verified. DNS listeners currently bind IPv4.
- Root-only questions and unsupported client message forms remain unsupported. Validation is not DNSSEC or a complete record-semantic validator.
- Real Linux startup, filesystem durability, service permissions, port-53 conflicts, and LAN interoperability need verification. Persistence does not promise durability beyond the underlying filesystem/platform.
- Router/DHCP control is not verified. Discovery is heuristic, includes `/24` assumptions, and is not authoritative.
- Remote DNS protection, Internet remote management, network portability/awareness, discovery/pairing, and a Linux Engine Monitor are future work.

## Roadmap and development status

| Milestone | Status |
| --- | --- |
| Phases 1–2: hosts, explicit domain policy and device identity correctness | Completed |
| Phase 3: custom Engine as sole DNS filtering implementation; dnsmasq removed from execution | Completed |
| Phase 4: HTTPS management, authentication, protected credentials and trust | Completed |
| Phase 5A: committed policy, persistence, revisions and Safe Mode | Completed |
| Phase 5B: client TCP DNS | Completed |
| Phase 5C: upstream reliability and bounded UDP concurrency | Completed |
| Phase 5D: runtime/status/recovery/failure hardening | Completed (source/automated verification) |
| Phase 5E: real Linux/LAN integration and deployment verification | Planned |

Later candidates include network portability/awareness, discovery/pairing, remote management/protection, and a [read-only Linux Engine Monitor](docs/future-linux-engine-monitor.md). They are not implemented features. HostsGuardian remains an actively developed prototype; deployment conflicts and configuration require explicit review.

## Projekt állapota: Fejlesztés alatt

A projekt jelenleg fejlesztés alatt áll, nem tekinthető kész terméknek.

Egyes funkciók hiányosak lehetnek vagy változhatnak.
