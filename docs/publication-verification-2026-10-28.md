# Source publication verification — 28 October 2026

This is a **source candidate**, not a production release or deployment attestation. No commit, push, tag, file deletion, privileged installation, policy write or network configuration change was performed during publication preparation. Tests used an isolated source copy and temporary fixtures.

## Architecture and candidate scope

Windows WPF makes user decisions and stores drafts. Core supplies shared contracts, normalization, deterministic policy evaluation and authenticated management clients. The Linux Engine serves UDP/TCP DNS and commits policy through HTTPS. NetworkValidator supplies constrained identity evidence; Linux Monitor displays diagnostics and offers separately authorized systemd lifecycle actions. Monitor does not own device policy. The Engine is a resolver, not a mandatory LAN gateway.

The candidate includes:

- Immutable address/scope binding indexes that preserve conflicting candidates, freshness and registration checks.
- Passive capture generation/reopen/backoff and a shared IPv4 receive-only refresh with a 200 ms caller budget. No ARP probe or IPv6 identity fallback is introduced by this path.
- Correlated decision/response diagnostics: bounded queue of 512 events, 2048 retained records, 15-minute monotonic retention and observable dropped/evicted counts. Records contain query names and client/device context; keep authenticated exports private. This is bounded in-memory diagnostic history, not durable full-payload capture or a lossless audit log.
- Persisted local exact device-rule Restore, distinguishing ABSENT from explicit Inherit/Allow/Block; delivery to Engine remains a separate CAS-protected operation.
- WPF connection/settings refresh that rejects superseded endpoint results and presents connection health separately from policy readback.
- Monitor lifecycle observation and guarded Engine/helper upgrades, durable recovery dispatcher, pinned recovery-session preparation and recovery handover. These scripts are maintained source and must remain with their tests.

## Version provenance: what is and is not identical

The Git base at the start of this review was `ecb4b5c97a8981efc965070076904a080362b3dd` on `master`, with 38 modified and 16 new files. All **361** publishable files matched the earlier October 28 SHA-256 inventory before preparation edits.

A preserved October 13 source manifest identified **359** files, based on dirty HEAD `8f517c081a52385e22b182db910428d251dead45`, source identity `bd9bea27d6cf37581b039133d05ba66841e242855e5685b5f9062385509c8e78`. At the start of this review:

- **351** of those files matched byte for byte; none was missing.
- Eight differed: WPF regression `Program.cs`, `EngineConnectionWindow.cs`, both localization JSON files, `MainWindow.xaml`, `MainViewModel.cs`, and both root READMEs.
- Two were additional: `EngineSettingsSynchronizationTests.cs` and `docs/ARCHITECTURE_AND_ROADMAP.md`.

That manifest describes a **candidate**, not a deployed version. Its preserved integrity report explicitly records production preservation, no real PID1/reboot acceptance, and no installed candidate Monitor. The separately preserved functional DNS report tested four allowed UDP/TCP queries against an **older** production Engine, not this candidate. Previously documented global Block/Restore is a separate historical observation; it was not rerun or independently re-established from a complete raw evidence chain during this review.

Publication preparation adds portability, comment-example, ignore-rule, font-notice and documentation changes after these comparisons. Consequently neither the preserved candidate hash nor an old test count identifies every byte of the final working tree. A new external SHA-256 inventory identifies the proposed files without inventing a commit SHA. No current machine/service/binary hashes were obtained from the Linux host; **current source ↔ currently deployed binary equivalence remains unproven**.

## Fresh isolated verification

Environment: Windows, .NET SDK **9.0.301** targeting the existing .NET 8 projects, Python **3.12.14** bundled runtime. The source snapshot began without `bin`, `obj`, `.vs`, credentials, runtime configuration or Git metadata. Restore could use the machine's package cache; this is not an empty-cache build. Regression projects are separate from the solution and were restored/built by `dotnet run`.

| Check | Result |
|---|---|
| Release solution restore/build | PASS, exit 0; 0 errors and 12 warning occurrences |
| Core/Engine console regression | PASS, exit 0; 332 groups |
| WPF console regression | PASS, exit 0; 39 PASS messages, not a formal test-case total |
| NetworkValidator/upgrade Python | 89 discovered: 88 pass, 1 skipped |
| Linux Monitor Python | 87 discovered: 63 pass, 24 skipped |
| Roadmap/recovery Python | 36 discovered: 36 pass |

The clean build exposes existing **NU1701** legacy Console dependency compatibility warnings, **CA1416** Windows-only identity API reachability warnings, and **CS8604** possible-null MAC argument warnings in WPF. Duplicate restore/WPF compile occurrences contribute to the total. They remain visible and are not treated as a warning-free build. The earlier incremental build reporting two warnings did not exercise the same clean compilation paths.

The new bootstrap portability test initially compared Windows path separators against a POSIX literal. The assertion was corrected to compare `as_posix()`; the complete helper suite then passed. This changes the test representation, not deployment behavior.

Reproduce from a source-only directory on Windows:

```powershell
dotnet build HostsGuardian.sln -c Release
dotnet run --project HostsGuardian.RegressionTests -c Release
dotnet run --project HostsGuardian.Wpf.RegressionTests -c Release
```

Run `python -B -m unittest discover -v` separately in `network-validator`, `linux-monitor` and `development/roadmap`. These are the fixture suites, not the deployment entry points. Native GTK/Linux, raw socket, polkit/systemd and root/PID1 behavior require their target environments. A skipped GUI test proves no GUI behavior. A fixture printing a deployment status string is not deployment evidence.

## Publication security and file boundary

The entire proposed file list was scanned with **Gitleaks 8.30.1**, default rules, redacted output and inline allow comments disabled. The scanner archive was downloaded from the [official release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) and its SHA-256 matched the release asset digest. The source snapshot and all **40** locally reachable commits returned **no findings**. Additional local pattern checks covered credential assignments, embedded URL credentials, private addresses, MAC literals and operator paths. No scanner result is proof that an arbitrary secret cannot exist.

The two token-assignment matches are repeated-character mock credentials; the URL credential match is a hostile URL rejection test. MAC matches are synthetic test/comment data or zero-address rejection logic. Six private IPv4 comment examples were replaced with documentation addresses; the remaining private IPv4 literal deliberately tests rejection of an IP used as a domain. Historical device-model labels in milestone documents and the timer fixture filename are not live configuration. An example orchestrator config uses an example developer path; the actual local config remains ignored.

The bootstrap no longer embeds a personal home directory. It defaults to `/var/tmp/hostsguardian-transfer` and accepts an explicit absolute `transferDirectory` packaging input; archive names must be basenames. Operators must regenerate/review a bootstrap for the actual transfer location, rather than assume compatibility with a previous generated script.

Keep the existing font assets and the three historical UI screenshots: they are intentional product assets, not build artifacts. The screenshots were visually reviewed for credentials and identifying LAN data; none was visible. Orbitron's notice is retained and the Exo notice was copied from the existing original font archive. The root MIT license still has author/year placeholders; the owner should settle those metadata before final publication. No licensing terms or ownership were changed here.

Ignore rules now also reserve private evidence/local artifact/recovery-image directories, disk-image extensions, private-key/certificate containers and nested environment files, while retaining named environment templates. Recovery Python/C# source and the timer test fixture remain eligible. No currently tracked path became ignored. Existing build outputs, local configuration, credentials, transfer archives, disk images and raw household evidence are not part of the proposed Git file list. Nothing was deleted.

## Remaining gates

1. Review the final per-file inventory, working-tree diff and external SHA-256 manifest. Tests, source and recovery helpers must be published together.
2. Resolve the root license attribution placeholders. Review the existing build warnings before representing this as a release-quality binary.
3. Retain the source/deployment distinction above. For stronger live claims, separately authorize isolated Linux/GTK/systemd and controlled two-client Block/Restore with verified recovery. Whole-LAN coverage and IPv6 device attribution remain unproven.
4. Obtain explicit approval **before committing**. Only then create a reviewable local commit; recheck the remote and obtain the required push approval. This review itself authorizes no Git publication, cleanup, deployment or recovery activation.
