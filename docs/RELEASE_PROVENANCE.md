# Release Provenance and Privacy Review

## Distinct identities

| Object | SHA-256 / identity |
| --- | --- |
| Original pre-stamp source content | `0b501e3e0439441001601fc0b1278c1e8d3b04f84d97eadaf250760f452796e6` |
| Original source ZIP | `fd7f9dab593c814e4147a4b4762e43a6eb2546571aaaf019be23b906bb79336b` |
| Original Linux package | `a42fa4f374c0d126d92a63b53877ffd778144eb8f292dff323f382a0f878b0ba` |
| Original Windows package | `4781ee7e0d284da33cd3a8c0d3f24c0f196ca1914b44d099bbf73decd5ccee62` |
| Cleaned/test-portable derived source tree | `e88144185997c1ca79f82c4826683d84ffaa7a26d7c734ab0cf69cdefb1393ae` |
| Master base Git commit | `6038615e2cfc121dfd9c3e8682c049304c7be25f` |
| Proposed integration commit | Resolve the PR head SHA or run `git rev-parse HEAD`; this file does not embed its own containing commit hash |

The original build is `HG-2.3.1-RC2-20261102-0b501e3e0439`. Its short content-hash prefix is **not** a Git commit SHA. Package, source-tree and Git identities refer to different objects.

## Import and intentional deltas

`rc2/IMPORT_MANIFEST.csv` records 201 imported and 7 excluded archive members. Exclusions are IDE user/publish profiles and environment-owned preparation tools. `rc2/LEGACY_DISPOSITION.csv` explicitly handles all 41 release-only, 14 differing and 114 repository-only paths without blind deletion or AI-branch merging.

`rc2/SANITIZATION_DELTAS.json` records before/after SHA-256 values. Three archived WPF demo/check files and one retained historical notification test use a neutral unique synthetic label, with matching search/assertion semantics. Three archived source-inspection tests now use a new test-only source-layout resolver: the Engine check inspects RC.2, while two historical WPF checks remain labelled historical. No assertions were removed or production policy behavior changed.

`rc2/Directory.Build.props` prevents inheritance of legacy root version defaults. `rc2/.gitattributes` preserves the archived/derived bytes across checkouts. `rc2/DERIVED_SOURCE_SHA256.json` lists the derived inputs; the sorted path/NUL/hash/LF algorithm is specified in `rc2/PROVENANCE.json`. Documentation and import scaffolding are additional reviewed changes. These changes do **not** replace deployed binaries.

## History and residual privacy exposure

The complete reachable master ancestry was pattern-scanned: 17 commits and 610 blobs. A personal test-display label exists in the historical blob for `HostsGuardian.Wpf.RegressionTests/NotificationAcceptanceTests.cs`; it remains reachable in the already public history. The current file is cleaned. **This residual historical name exposure is not removed by the PR.** No history rewrite, force push or automatic master merge is performed. Removing historical data would require a separately approved repository-wide remediation.

Credential-pattern matches in regression tests are repeated synthetic values used by mock handlers. Private-address matches in older source are illustrative comments/test inputs, not imported live policy or network logs. No private-key, GitHub-token, AWS-key or JWT pattern was detected by the full-blob scan. Pattern scanning is a review aid, not a mathematical guarantee that every possible secret is absent.

The proposed change set excludes production userstores, credentials, TLS private keys, DPAPI files, policy/audit data, backups, build outputs and runtime fixtures. New documentation contains no personal names, local account paths or internal network identifiers. Source/archive hash checks, the staged allowlist and final Git-tree checks are required before push.
