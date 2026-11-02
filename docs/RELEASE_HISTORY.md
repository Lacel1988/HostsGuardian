# Release History

## V2.3.1 RC.2 — operational release

Version `2.3.1-rc.2`, build `HG-2.3.1-RC2-20261102-0b501e3e0439`. Production status: **COMMITTED / PARTIAL GO**. Original source/package identities and the derived Git baseline are distinguished in [Release Provenance](RELEASE_PROVENANCE.md).

The release introduced schema-v4 Domain Block List persistence and the Engine-backed WPF list. An initial deployment failed because effective service-user access was not fully checked; the prior Engine and matching policy were restored. Installer v2 passed targeted isolated Linux tests before the later controlled trial.

During that trial a different test domain was toggled, and the recovery guard stopped. Analysis later established the intermediate change and its restoration. The historical ROLLBACK_BLOCKED receipt/audit was retained. A subsequent WPF/global-domain test and separately approved finalization completed the deployment without Engine restart or policy write during finalization. The inherited restart rule was restored and the previous recovery workflow terminally closed using a separate receipt.

Historical acceptance remains qualified by [Known Limitations](KNOWN_LIMITATIONS.md). Operational evidence is private and is not copied into this repository.

## Derived master-baseline consolidation

The authenticated archive was imported into a separate master-based worktree. Approved synthetic-name cleanup and test source-layout corrections are explicitly recorded; they do not change deployed binaries. Bilingual READMEs and the current baseline documents replace older milestone claims as the project's entry points.

New isolated results and the initial source-layout failure are in [Validation](VALIDATION.md). The next baseline is the verified master head after the explicitly approved normal fast-forward. The original release identifiers remain intact.

## Earlier repository history

Root-level project directories and older milestone documents predate the RC.2 snapshot and remain marked historical. The divergent AI development branch is not merged. A personal test-display label remains in older public Git ancestry, disclosed in [Provenance](RELEASE_PROVENANCE.md); no history rewrite or force push has occurred. No old tag is relabeled as RC.2.

## Approved master integration

The user subsequently approved full master integration. The official root solution was updated to reference only RC.2 projects; its predecessor was preserved under `legacy/` with location-only path adjustments. No historical project source was deleted. Fresh build/regression, privacy, source identity and remote-rule checks gate a normal fast-forward from the existing master baseline; no forced update or branch-protection bypass is permitted. PR creation had been denied by the integration API, so the explicitly authorized Git CLI path is used when master has no active protection rules.
