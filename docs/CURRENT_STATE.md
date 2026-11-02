# Current State — V2.3.1 RC.2 Derived Master Baseline

## Status and authority

**Production: COMMITTED / PARTIAL GO.** Master integration is explicitly approved after fresh verification gates; the official development baseline is the cleaned, tested RC.2 derivative. It does not replace production binaries. The authenticated RC.2 archive/manifests, preserved operational audits and finalization receipt establish release provenance. Environment-specific evidence remains private.

| Area | Implemented | Evidence and remaining boundary |
| --- | --- | --- |
| Linux Engine | Independent UDP/TCP DNS, HTTPS management, persistence, audit and diagnostics | Prior live DNS/API/finalization evidence; new Windows/Linux builds and isolated suites pass |
| Windows WPF | Login, existing shield/unlock animation, Dashboard and Domain Block List | Prior human acceptance; new Windows build and 44 actual WPF/loopback-HTTPS checks plus restart persistence pass |
| DNS policy | Schema v4; saved membership separate from enforcement; global/device models | Global live block/restore and final policy-content restoration evidenced; new synthetic migration checks pass |
| Device identity | Registration, validated bindings and evidence mechanisms | Storage/identity support is implemented; exclusive live device enforcement remains unproven by global tests |
| Authentication/RBAC | Engine-owned Argon2id, expiring sessions, Admin/Operator/Observer checks | Live Admin verified; new isolated role/API checks pass; production Operator/Observer NOT TESTED — no applicable accounts |
| AI integration | Analyst contracts/routes and separate development work | Full production analyst behavior/deployment not established; divergent AI branch is not merged |
| Linux monitoring | Diagnostic observations/projections | This baseline does not establish a newly accepted standalone GTK4 GUI |

## Source and publication baseline

Use the root `HostsGuardian.sln`, which references only `rc2/` projects. The official Engine project is `rc2/source/HostsGuardian.DnsEngine/HostsGuardian.DnsEngine.csproj`; the sole current WPF project is `rc2/source/HostsGuardian.Wpf/HostsGuardian.DesignPrototype.csproj`. The old solution is preserved under `legacy/`, and old project directories are explicitly historical. The source archive was verified, selected members imported byte-exactly, then explicitly approved privacy-only fixture naming and test-layout corrections applied. Original hashes and all deltas are in [Provenance](RELEASE_PROVENANCE.md). No application dependency or policy-priority change was introduced.

The original AI branch and all 69 uncommitted entries were preserved. Its newer-looking files are not presumed to be RC.2 and are not merged. Historical root projects remain explicit legacy material, including two static WPF source checks; the actual RC.2 WPF is covered separately by executable tests.

The current tip has neutral synthetic fixture names. A personal test-display label remains in existing public ancestry. It is a historical privacy residue, not a production credential; no history rewrite or force push was performed. See the separate review in [Provenance](RELEASE_PROVENANCE.md).

## Verification scope

[Validation](VALIDATION.md) records newly run builds/regressions separately from historical live acceptance. Initial isolated Linux source-root failure and the corrected retest are retained. This is source-level buildability and functional regression evidence, not bit-for-bit reproduction of shipped binaries, a native DPI acceptance rerun or new production role/device acceptance.

## Next Development Baseline

Start from the verified GitHub `master` head after the authorized fast-forward integration. Resolve and pin its real Git SHA from the remote ref; the short source-content prefix is not a commit. Pin the derived source-tree SHA-256 in `rc2/PROVENANCE.json`, retain original RC.2 identities, and carry forward COMMITTED / PARTIAL GO qualifications, device/role/monitoring/analyst gaps and historical privacy residue. The separate AI branch requires independent review. Service-Aware DNS Policy and AiSeNa remain roadmap work.
