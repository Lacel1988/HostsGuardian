# G3 — bounded attempts and total execution deadline

Scope: existing local managed `edit` / `diff-check` path only. Based on
`37715caae63e6622cf3bc56432a67802af3ec8b2`, isolated `codex/orchestrator-g3`
development branch. No product, deployment, SSH, cleanup or G4–G6 implementation.

## Reviewed input and behavior

Dispatch now requires a separate operator-reviewed `--budget` JSON document:

```json
{"total_timeout_seconds": 60, "max_attempts": 1, "retry_transient": false}
```

`max_attempts` is an integer 1–3 (default 1, including the first attempt).
`total_timeout_seconds` is required, numeric, finite, positive and at most 300.
`retry_transient` is a boolean, default false. Missing/invalid input blocks before
evidence-directory creation or dispatch. `--inspect` remains a read-only G1/G2
identity inspection, not dispatch permission or a G3 execution.

One monotonic deadline begins on CLI entry, before parsing/loading the profile,
request and authorization. The same budget covers preliminary evaluation, evidence
preparation, all attempt gates, source hashing, subprocess execution, edits and
successful result/evidence publication. An execution attempt is reserved before
its worker G1/G2 evaluation; the CLI's preliminary no-dispatch evaluation and the
worker's double evaluation do not count as extra attempts. Every Git probe timeout
and managed subprocess wait is capped by the remaining total budget. The immutable
approved `Operation` and its G1/G2 identity are not rewritten to adjust the timeout.

Only `diff-check` may retry, and only after the trusted subprocess runner reports
`PROCESS_START_TRANSIENT`: Popen failed with EAGAIN before a process existed,
`FAILED`, no exit code, and `dispatched is False`. All conditions are mandatory.
Other failures, launched processes (even read-only failures), edits, unknown
dispatch, cancellation, timeout, malformed results and Guard denials stop.

Retries need explicit opt-in and distinct reviewed authorization IDs, loaded
at retry time through repeated `--retry-authorization` arguments. The existing
G1/G2 checks run twice again, including source/profile/operation identity and exact
component authorization. The consumed flag is reset only inside this narrowly
classified no-process-start retry, never by an external PASS/Decision. No automatic
authorization, profile change, payload change or repair is generated. Waiting for
authorization consumes the original deadline. Reusing a successful or failed
budget cannot restart execution; there is no automatic crash resumption. A new
process still has the documented G1/G2 process-local replay limitation, not a
durable global retry ledger. Explicitly starting a separate newly approved task
is outside automatic continuation.

G3 attempt/result records use the existing ledger/notify path. Evidence failures
stop execution; finalization failures have a nonzero exit and BLOCK output. A
failure-only summary is attempted if its validated evidence directory already
exists. Storage failure can prevent even this failure publication; raw ledgers
may be partial and cannot be treated as a standalone completion certificate.
Only a successful final CLI result with intact evidence qualifies this operation
as completed. Console output is also checked after publication; blocked output can
leave provisional text visible, but an overrun has a final BLOCK and nonzero exit,
with best-effort replacement of the summary by failure evidence. G1/G2 dispatch
permission still does not certify G4/G6 acceptance.

SIGINT sets cancellation; checkpoints run before dispatch, between file writes
and after results/evidence callbacks. Late success is rejected. On exceptions in
subprocess heartbeats, termination of the direct child is requested. Existing
StateMachine/Operation/Result/ManagedDevelopmentWorker/run_operation are reused.
Result adds only a typed-use failure-code field for the narrow transient case.

## Limits

This is cooperative trusted-process enforcement, not an OS sandbox or hard
real-time interruption. Synchronous filesystem calls, process creation, process
termination, storage flushes and blocked I/O cannot be forcibly interrupted at
the exact deadline. On regaining control after expiration, no further source
operation/dispatch or successful completion is permitted. Bounded failure evidence
publication/termination requests can occur after the execution deadline; they do
not restart the operation. Descendant process lifetime is not certified. No
transactional multi-file edits, rollback, global locking, signed authorization,
ignored-input coverage or durable cross-process replay protection is added.
Existing G1/G2 trusted-operator, TOCTOU and nontransactional limitations remain.

## Verification

Run from the checkout root, without bytecode output:

```powershell
python -B development/orchestrator/run-tests.py
python -B development/orchestrator/acceptance_g3.py
git --no-optional-locks diff --check
```

The standard suite includes deterministic G3 boundary/failure tests alongside the
G1/G2 regressions. The separate acceptance driver does not import their fixture
classes: it creates its own temporary repositories and real linked worktrees and
exercises managed CLI diff/edit, actual synthetic Popen EAGAIN retry, stale/reused
authorization, missing/invalid limits and evidence failures. No product executable,
service, model, network request or deployment is invoked. Tests may commit only
inside their temporary fixture repositories, never the project repository.

Existing test assertions are retained. G1/G2 fixtures explicitly supply the new
budget, and the legacy relative-evidence test uses a same-volume temporary cwd
to avoid Windows C:/D: relpath failure. No production behavior was changed for it.

Final verification (2026-11-03):

- Full standard suite: **101 run, 100 passed, 1 skipped, zero failures/errors**,
  133.163 seconds. This includes **28 passing G3 tests** and the existing
  **72 passing G1/G2 regressions plus one historical real-symlink skip** (host
  privilege limitation). The skip is not relabeled PASS and no elevation was used.
- Separate G3 acceptance: **7/7 passed**, 12.272 seconds, zero skips/errors.
- `git --no-optional-locks diff --check`: PASS.
- **G3 scoped automated acceptance: PASS**, for the documented cooperative,
  trusted-process, local managed execution scope only. Not an OS-level security
  certification, production acceptance or G4/G6 human final-task acceptance.

## Changed files (all relative to development/orchestrator)

- Implementation: `orchestrator/budget.py` (new), `orchestrator/managed.py`,
  `orchestrator/governance.py`, `orchestrator/recipe.py`, `orchestrator/workers.py`,
  `orchestrator/workbench.py`, `orchestrator/development.py`, `orchestrator/model.py`.
- Tests: `tests/test_g3.py` and `acceptance_g3.py` (new),
  `tests/test_governance.py`, `tests/test_managed_evidence.py`,
  `tests/test_no_go_regressions.py` (fixture adaptations only).
- Documentation: `README.md` and this document (new).

The official G1/G2 worktree preservation check returned a clean porcelain status,
unchanged HEAD `37715caae63e6622cf3bc56432a67802af3ec8b2`, and the unchanged
11-file Python package SHA-256
`1b8f706f87a65b2cf6a105433bab8bf628b33490d56c3870d88df347daea85a5`.
No project commit or push is authorized or performed. Git fixture commits belong
only to disposable test repositories. The G3 branch remains at its approved base.
