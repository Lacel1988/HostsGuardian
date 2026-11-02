# HostsGuardian — V2.3.1 RC.2

**English | [Magyar](README.hu.md)**

HostsGuardian is a DNS policy system with an independent Linux DNS Engine and a Windows WPF Control Center. It helps authorized users manage domain blocking while keeping configuration, measured DNS effects and application behavior separate.

**Production status: COMMITTED / PARTIAL GO.** The master development baseline is derived from the verified RC.2 source archive. It does not deploy a new release or claim complete production acceptance.

## Start here

- [Current State and Next Development Baseline](docs/CURRENT_STATE.md)
- [Architecture and configuration](docs/ARCHITECTURE.md)
- [Known Limitations](docs/KNOWN_LIMITATIONS.md)
- [Roadmap](docs/ROADMAP.md)
- [Release History](docs/RELEASE_HISTORY.md)
- [New validation results](docs/VALIDATION.md) · [Provenance and privacy review](docs/RELEASE_PROVENANCE.md)

## Implemented capabilities

- Linux UDP/TCP DNS processing, existing global/device policy evaluation, persistence and audit.
- Policy schema v4 with saved-domain membership distinct from enforcement.
- Engine-backed Domain Block List: scope selection, search, add, enable/disable without deleting the row, and separate deletion. Inherited global blocking is shown in device views.
- HTTPS management API, Engine-side Argon2id authentication, expiring sessions and Admin/Operator/Observer authorization checks.
- Windows WPF login, existing shield/unlock animation, Dashboard and domain management.
- Revision-aware writes and readback, diagnostic and monitoring projections.

Global block/restore has live evidence. Device-specific rules and roles are implemented, but live selective device enforcement and production Operator/Observer sessions remain separate acceptance gaps. Analyst-related contracts do not establish a deployed, fully accepted AI service.

## Architecture

The Engine executes authorized rules. WPF presents readback and user controls. Linux monitoring observes. AI analyzes and suggests. Clients send DNS directly to the Engine; WPF is not a DNS gateway. Systemd manages the independent service lifecycle. See [Architecture](docs/ARCHITECTURE.md).

## Source layout and build

The current baseline is `rc2/source`; isolated suites are `rc2/tests` and `rc2/migration-checks`. The root `HostsGuardian.sln` is the **official RC.2 solution**, containing only RC.2 projects and one current WPF. Older root-level project directories are retained historical source, explicitly marked `README.LEGACY.md`; their solution is preserved as `legacy/HostsGuardian.PreRC2.sln`. The separate AI development branch is not merged.

Use .NET 8 or a compatible SDK. WPF requires Windows desktop targeting/runtime support. Restore the package references pinned in the projects; no new application dependency was introduced by consolidation.

```sh
# Full official solution on Windows:
dotnet build HostsGuardian.sln -c Release
# Engine-only build also supported on Linux:
dotnet build rc2/source/HostsGuardian.DnsEngine/HostsGuardian.DnsEngine.csproj -c Release
dotnet build rc2/source/HostsGuardian.Wpf/HostsGuardian.DesignPrototype.csproj -c Release
dotnet run --project rc2/source/HostsGuardian.RegressionTests/HostsGuardian.RegressionTests.csproj -c Release
dotnet run --project rc2/tests/IntegrationChecks.csproj -c Release -- ./rc2/test-output/integration
```

Engine build/regressions were newly run on Windows and native Linux. WPF build and real WPF/loopback-HTTPS checks passed on Windows. Run source-inspection regressions from the complete checkout: two explicitly historical WPF checks use retained root-level files. Detailed results and the initial layout failure are in [Validation](docs/VALIDATION.md).

## Installation and configuration basics

1. Validate in isolation and keep the previous working Engine together with its matching policy backup.
2. Locally provision service ownership, private authentication storage, a management credential, TLS certificate/private key, policy and monitor paths. Never commit those files.
3. Configure the Engine using the environment variables in [Architecture](docs/ARCHITECTURE.md). For a new installation only, initialize the first Admin locally with a unique strong password. Do not reinitialize an existing store.
4. Preserve systemd sandbox restrictions and verify actual service-user access. The committed deployment uses inherited `Restart=on-failure`; finalization verified this without an Engine restart or policy write.
5. Configure WPF's HTTPS origin, enrolled certificate and protected local credential through the existing connection workflow. Authenticate with an Engine account.
6. Verify API readback, UDP/TCP DNS and rollback readiness before directing clients to the resolver. This branch neither deploys nor changes router settings.

Environment-specific installers, recovery data and credentials are deliberately excluded. These are configuration prerequisites, not a portable one-command deployment recipe.

## Limits and plans

DNS policy applies only to queries reaching the Engine. Caches, existing connections, IPv6 resolver selection and alternative DNS/DoH can affect application results. A single domain does not represent a complete multi-domain service. See [Known Limitations](docs/KNOWN_LIMITATIONS.md).

**Service-Aware DNS Policy and AiSeNa are roadmap directions, not completed production capabilities.** See [Roadmap](docs/ROADMAP.md).

The cleaned source deliberately differs from the deployed RC.2 snapshot in fixture naming and test-path infrastructure. Original release hashes remain recorded. An older personal test-display label remains in Git ancestry; history has not been rewritten. See [Provenance](docs/RELEASE_PROVENANCE.md).

## License

See [LICENSE.txt](LICENSE.txt) and the licenses of the package references declared in the projects.
