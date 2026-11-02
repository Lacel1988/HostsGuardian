# Baseline Validation

## Newly run for this consolidation

| Check | Environment | Result |
| --- | --- | --- |
| RC.2 Engine build | Windows and native Linux | PASS; platform-analysis warnings retained, no errors |
| RC.2 WPF build | Windows | PASS |
| Corrected full source/regression suite | Windows and native Linux | 351 groups PASS in each environment |
| Isolated pinned HTTPS authentication/RBAC/Domain Block List suite | Windows and native Linux | 79 checks PASS in each environment |
| Actual WPF against isolated loopback HTTPS Engine | Windows | 44 checks PASS |
| Disabled list membership after new WPF process | Windows | PASS |
| Historical WPF regression suite, including cleaned notification fixture | Windows | PASS; separate from RC.2 WPF acceptance |
| Offline synthetic schema3→4 migration/rollback | Windows and native Linux | 7 checks PASS, 9 equivalent decisions; no source policy writes |

All mutation tests use synthetic private fixtures and loopback endpoints. No production Engine/WPF was deployed or restarted, no production policy/userstore was modified, and no router setting was changed. Raw runtime fixtures and credentials remain outside the publication tree.

## Initial failure and corrected interpretation

The first standalone Linux regression run failed at source-root discovery because archived tests searched upward for an unshipped solution. The first Windows run found the historical root solution instead. That initial result is not evidence that RC.2 source isolation was correct.

The approved consolidation adds a test-only resolver and records the affected file hashes. The Engine architecture scan now selects its own RC.2 project. Two legacy WPF static source checks explicitly use the retained historical files in the full repository checkout, and are labelled historical. Existing assertions are preserved. The corrected suites then passed on both systems; the first Linux failure remains in private evidence.

## Historical evidence, not new acceptance

Prior live evidence established Admin login, WPF animation/Dashboard, global DNS block/restore, policy-content restoration and controlled COMMIT without Engine restart or policy write during finalization. The previous failed-domain audit and polling limitation remain recorded. These were not rerun as production tests here.

New tests do not establish full LAN coverage, native DPI/multi-monitor acceptance, production Operator/Observer sessions, selective live device enforcement, a native GTK4 GUI or full production AI acceptance. Status remains **COMMITTED / PARTIAL GO**. Source buildability is verified; bit-for-bit equality with shipped binaries is not claimed.

## Archive formatting

Git whitespace review reports existing blank-at-EOF/trailing-space lines in imported archive members. Their provenance hashes confirm these are inherited formatting, not new semantic edits. They are retained rather than introducing an unrelated formatting rewrite. This does not turn whitespace review into a clean PASS; executable build/security/regression gates are reported separately.

## Final master-integration verification

The official root solution now selects only RC.2 projects. The full Windows solution build is rechecked, together with fresh Windows/native-Linux Engine regressions, pinned HTTPS/RBAC/Block List checks, synthetic migration checks, and actual Windows WPF/restart tests. Source inputs retain the same derived hashes; raw evidence is private. Remote branch protection and active rules are checked before a normal fast-forward; no forced update or protection bypass is allowed.
