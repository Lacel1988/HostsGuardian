# G5 — evidence integrity and auditability

Scope: existing local managed edit/diff-check path, preserving uncommitted G3/G4
on `codex/orchestrator-g3`, HEAD `37715caae63e6622cf3bc56432a67802af3ec8b2`.
No project branch/worktree, commit, push, product change, service, dependency,
parallel ledger/framework, Independent Auditor or G6 implementation is added.

## Existing structures and added checks

The existing append-only/fsync Ledger now optionally carries managed run binding,
contiguous sequence numbers and a SHA-256 previous/event hash chain. Legacy recipes
retain their existing unsealed recording behavior; no migration/rewrite occurs.
Strict JSON rejects duplicate fields, nonfinite constants and torn records.

Run/attempt binding contains the unchanged approved Operation definition and
payload hash/identity, canonical cwd, workspace root/branch/baseline, source and
profile identities/version, reviewed authorization fields and their digest. Each
attempt records its ordinal, authorization, exact G3 limits/elapsed time and actual
Result digest. The existing recipe binds the final COMMAND_RESULT to that attempt.
No authorization is generated and no approved Operation field is modified.

Before COMPLETE, G5 reads back the existing ledger and checks it against the live
writer's in-memory chain head/count, exact raw-byte digest and initial binding.
Even a semantically equivalent reformatting before sealing blocks. It requires one managed
command; contiguous bounded attempts; distinct reviewed authorization IDs for any
allowed retry; matching G1/G2 PASS policy/version/boundary, source/profile/operation
references; consistent G3 budget/time; G4 PASS and its original operation/before/
after/target/index references; and an identical successful actual final Result.
Worker identity, task identity, state transitions, summary and result snapshots
must agree. Missing/conflicting/reordered evidence cannot be replaced by worker
PASS text. G5 never dispatches, retries, repairs or rolls back.

The existing summary is written with `completion: CERTIFICATE_REQUIRED`.
Task.COMPLETE and the G1/G2 dispatch PASS or G4 PASS are still provisional alone.
One minimal `completion.json` binds the validated task/run/attempt/result/G4 facts,
ledger file hash/count/head and summary hash. It is created exclusively, flushed,
fsynced and read back/verified. Its expected SHA-256 is computed from the intended
bytes **before publication**, not adopted from potentially modified readback.
Only intact consistent evidence, successful finalization and a final valid G3
checkpoint allow CLI exit 0. All operations including sealing/verification consume
the original G3 monotonic deadline. No new time budget is created.

Failures return BLOCK/nonzero, with best-effort FAILED summary publication in the
already validated owned evidence directory. A partial certificate is retained as
failure evidence, never silently cleaned/repaired. A valid-looking raw task
snapshot is not a completion certificate: Ledger.recover refuses managed chained
ledgers and directs callers to the verifier. A blocked edit may already be applied;
G5 does not alter source to undo it.

## Read-only verification and trust

Use the existing managed CLI with its read-only mode (from development/orchestrator):

```powershell
python -B -m orchestrator.managed --verify-evidence "<existing-run-directory>"
python -B -m orchestrator.managed --verify-evidence "<existing-run-directory>" --expected-certificate "<trusted-success-certificate-sha256>"
```

The trusted reference is `completion_certificate.certificate_sha256` from the
original CLI output **together with its successful exit 0**, retained through a
trusted caller channel. Reading a digest from the evidence being inspected does
not create a trusted reference. This is not a new authorization or G6 approval.
Python API Ledger.verify_managed also accepts an optional expected_binding for
comparison with a separately retained reviewed operation/workspace/authorization.

The reader opens only the three known evidence files, checks parents/files for
links/reparse points, and constructs no writer/worker, runs no subprocess, loads
no authorization, reads no current source and changes no evidence. Invoke with
`-B` to suppress interpreter bytecode writes. OS-managed access-time bookkeeping
is not a content-write guarantee or under the reader's control.

- **PASS / exit 0:** chain, semantics, file seals and supplied trusted reference
  match. This means integrity/consistency relative to that caller reference only.
- **BLOCK / exit 1:** missing required modern evidence/certificate, corruption,
  inconsistent binding/result/attempt/state, unsupported linked evidence or read
  failure. A raw/provisional PASS without a certificate is never completion.
- **UNKNOWN / exit 2:** internally consistent unanchored bundle, or legacy unsealed
  historical evidence whose completion cannot be established. It is not promoted
  to authenticated historical PASS.

## Remaining limitations

Hashes/chains are unkeyed integrity checks, **not cryptographic origin/signature
or operator authentication**. An actor able to rewrite the entire bundle and its
untrusted checksums can create another internally consistent bundle. The live
writer head and separately trusted completion reference detect deviation from
their respective originals; they do not identify an actor or verify human review.
The existing trusted Python/Git/operator assumptions remain.

Readback establishes observed consistency, not OS immutability. TOCTOU/concurrent
changes can occur during/after checks or after successful publication; later
verification detects changed sealed bytes relative to a trusted anchor. No file
lock, OS sandbox, transactional multi-file edit/publication or atomic end-to-end
crash protocol is claimed. Synchronous IO/fsync/process calls cannot be interrupted
at a hard real-time deadline. Late finalization/output has nonzero exit and a
best-effort failure summary; unavailable storage may prevent that failure marker.
Never trust a reference from a failed/incomplete CLI invocation. Without a trusted
successful caller record, historical completion remains UNKNOWN, including such
ambiguous publication/crash cases.

Historical verification does not re-create the original filesystem, dependencies,
ignored inputs or human authorization act. It does not re-run G1/G4, execute any
operation, provide durable cross-process replay protection, or supply G6 acceptance.
G1/G2 trusted-process, ignored-input, nontransactional and G4 last-read-to-final-
publication limitations remain. No current-source equality is implied by a past
completion certificate.

## Verification and changed files

```powershell
python -B development/orchestrator/run-tests.py
python -B development/orchestrator/acceptance_g3.py
python -B development/orchestrator/acceptance_g4.py
python -B development/orchestrator/acceptance_g5.py
git --no-optional-locks diff --check
```

G5 unit negatives use small evidence-only copies of one actually completed
isolated Git fixture run. Semantic negatives deliberately rehash corrupt packets
to distinguish protocol validation from byte-integrity checks; replacement test
hashes are not claimed to establish origin. Separate G5 CLI acceptance reuses only
the existing disposable fixture construction, with actual guards/G4/finalization.
Tests cover missing/torn/tampered evidence, wrong operation/auth/workspace/attempt,
missing G1/G4, conflicting results/transitions, provisional completion, writer/read
failures, deadline/cancellation during certificate publication and no-write/no-
subprocess historical reading. No real project repository is committed by tests;
temporary fixtures may have their own isolated branches/worktrees/commits.

Existing G1/G2/G3 unit FakeDispatcher fixtures retain explicit mock G4 evidence
for their layer-specific tests; they are not G4/G5 acceptance evidence. Original
assertions are retained. Actual G3/G4 acceptance uses the real new G5 path.

G5 changes: `orchestrator/ledger.py` (existing ledger, seal/verifier),
`orchestrator/governance.py` (binding/result observations), `orchestrator/recipe.py`
(final result binding), `orchestrator/managed.py` (completion/read-only CLI),
`tests/test_governance.py` (mock evidence fixture), `README.md`, plus new
`tests/test_g5.py`, `acceptance_g5.py` and this document: nine files in total.
G3 budget/checkpoints, Operation/Result/StateMachine, G4 validator/runner and prior
acceptance programs remain in place.

## Final verification — 2026-11-03

- Full G1–G5 suite: **151 run, 150 passed, 1 inherited symlink SKIP**, zero
  failures/errors, **192.221 s**. All **26 G5 unit/negative tests passed**.
- G3 acceptance: **7/7 passed**, **16.500 s**; G4: **12/12**, **30.194 s**;
  G5: **11/11**, **30.240 s**, with zero acceptance skips/failures/errors.
- `git --no-optional-locks diff --check`: PASS. No project staging/commit/push.
- Preservation comparison: thirteen prior G3/G4 files byte-identical, including
  budget, Operation/Result/StateMachine, executor/checkpoints, runner and prior
  G3/G4 tests/acceptance/validation records. Five prior files are incrementally
  extended; the G4 capture/revalidation/dispatch-check method bodies are unchanged.
  G1/G2 guards and the same project HEAD/branch are retained.
- **G5 scoped automated acceptance: PASS** for the documented trusted-process
  managed completion path and read-only verification relative to a separately
  trusted successful caller certificate reference. Unanchored historical origin/
  completion remains UNKNOWN, not authenticated PASS. G6 is NOT_EVALUATED.
- No new project branch/worktree, commit or push. STOP before G6.
