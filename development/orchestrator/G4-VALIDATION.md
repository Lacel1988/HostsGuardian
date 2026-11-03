# G4 — post-execution revalidation

Scope: existing local managed `edit` and `diff-check` only, on the existing
`codex/orchestrator-g3` worktree at HEAD
`37715caae63e6622cf3bc56432a67802af3ec8b2`. The uncommitted G3 implementation is
retained and extended in place. No branch/worktree, project commit, push, product
code, deployment, cleanup, G5/G6 implementation or external dependency is added.

## What is verified

After the original double G1/G2 gate and before dispatch, a frozen operation plan
binds the very same immutable Operation object and payload hash, reviewed profile
and authorization (including exact components), root/origin/branch/HEAD baseline,
source hashes/status, index identity and linked Git directory/common directory.
Source identity is checked against the authorization again at capture. Expected
edit target SHA-256 values are derived using the existing prepare_edits/scoped_path
functions, including replacements, UTF-8 encoding and newly created files.

A worker SUCCESS is provisional. Before returning it, G4 reads each approved
target through the same canonical path/link/hardlink protection and verifies its
actual expected bytes. It takes another existing source snapshot, requires stable
workspace/origin/branch/HEAD, and compares every tracked/nonignored file outside
the approved target set with the original snapshot. Additions, deletions and
changes are rejected. Preexisting dirty, staged and untracked work is preserved
as baseline, not silently adopted as new changes. Git index/pointer identity must
remain unchanged. NUL-delimited Git status records (including rename/copy paths)
outside the approved target set must remain unchanged too.

For diff-check, the entire original source snapshot/status must remain identical.
The existing run_process function separately observes the actual argv, canonical
cwd, Result object identity, outcome, exit code and stdout/stderr hashes after
the subprocess returns. G4 requires exactly one matching observation from that
attempt. Worker text, a fabricated Result, another workspace/process or a mutated
result cannot substitute for that trusted runner observation. No second diff
execution, new worker or bypassing executor is introduced. G4 adds only bounded
read-only Git probes using the existing subprocess/snapshot pattern.

Postcondition verification must return typed, nonempty operation-bound evidence,
with G4 policy/boundary, source identity and policy version. G4_REVALIDATION is
recorded through the existing evidence/ledger callback before success is returned.
The CLI summary includes a separate revalidation decision; the existing G1/G2
dispatch decision is not relabeled as postcondition evidence. Final human/product
acceptance remains NOT_EVALUATED (G6), not inferred from source revalidation.

The same G3 ContextVar budget/deadline/cancellation covers capture, every probe,
hashing, verification and evidence publication. No deadline reset or attempt is
added by G4. Unavailable/malformed evidence, identity/post-state mismatch,
unapproved observed change, missing/tampered process observation, read/probe
failure, deadline expiration or cancellation causes terminal BLOCK. G4 never
retries, repairs or rolls back. Existing G3's narrowly classified pre-spawn retry
is retained; it precedes any possible successful execution/revalidation.

## Boundaries and remaining limitations

- Point-in-time checks reduce unnoticed drift; they are not locks or an OS
  sandbox. Changes may occur between the individual reads, and **after the last
  revalidation read or evidence observation, before final success publication**.
  ABA changes that restore observed bytes/status are not a complete write history.
- Tracked/nonignored source content, explicitly approved targets, observed Git
  status/index and pointer identity form the checked scope. Ignored unrelated
  input, executable identity, Git configuration, ACLs and all filesystem metadata
  remain outside the original source identity. No wider coverage is claimed.
- The Git executable/environment and deterministic in-process code remain trusted.
  Process observations are not signatures or protection against arbitrary Python
  mutation/direct internal calls; existing G1/G2 trusted-process/replay limits stay.
- Synchronous filesystem calls, process creation/termination and fsync cannot be
  interrupted at a hard real-time deadline. On regaining control, G3 rejects an
  overrun/late success. No transactional edits, rollback or crash resumption is
  added. A blocked edit may already have changed source; G4 leaves it for review.
- Evidence storage/publication is not transactional. A final nonzero CLI result
  or missing/failed evidence invalidates completion; isolated/provisional PASS
  text in an incomplete ledger/console is not final task acceptance.

## Tests and preservation

```powershell
python -B development/orchestrator/run-tests.py
python -B development/orchestrator/acceptance_g3.py
python -B development/orchestrator/acceptance_g4.py
git --no-optional-locks diff --check
```

G4 unit/negative tests use the real validator/managed worker in temporary linked
repositories. The independent G4 CLI driver has its own fixture construction and
does not import the unit fixture classes. Failure injection changes only temporary
source or mocks transport/evidence/failure timing, never removes the real guards
or revalidation to obtain a G4 PASS. No product/service/network operation runs.

Existing G1/G2/G3 FakeDispatcher unit fixtures explicitly mock the new G4 boundary
because their executor already returns synthetic results (including forged PASS
text). Their original guard/budget assertions remain active. They are **not** G4
evidence. Real G3 acceptance and all G4 tests exercise actual postconditions.
The inherited real-symlink privilege SKIP remains a SKIP, not a fresh security PASS.

G4-specific changes: `orchestrator/governance.py`, `orchestrator/workers.py`,
`orchestrator/managed.py`, `tests/test_governance.py`, `README.md`, plus the new
`tests/test_g4.py`, `acceptance_g4.py` and this document. The G3 budget, executor
checkpoints, Operation/Result, StateMachine/recipe and all G3 tests/acceptance are
retained.

## Final verification — 2026-11-03

- Full G1–G4 standard suite: **125 run, 124 passed, 1 inherited symlink SKIP**,
  zero failures/errors, **189.452 seconds**. All **24 new G4 tests passed**.
- Separate G4 CLI acceptance: **12/12 passed**, **30.547 seconds**, zero skips.
- Existing, byte-unchanged G3 acceptance: **7/7 passed**, **16.345 seconds**.
- `git --no-optional-locks diff --check`: PASS.
- Pre-G4 G3 content comparison: ten files byte-identical (including G3 budget,
  model/recipe/executor/checkpoints, G3 tests/acceptance and validation record),
  five incrementally extended files listed above. Original G3 assertions retained.
- **G4 scoped automated acceptance: PASS**, only for documented trusted-process
  managed edit/diff-check postconditions. No full concurrency/OS isolation or
  product/G6 human acceptance is implied. The historical SKIP remains a SKIP.
- HEAD/branch remain the original G3 base and `codex/orchestrator-g3`. G3 and G4
  changes are uncommitted/unstaged. Commit and push remain NOT AUTHORIZED.
