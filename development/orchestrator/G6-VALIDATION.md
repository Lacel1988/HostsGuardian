# G6 — post-execution human acceptance / G1–G6 scoped validation

This extends the existing `codex/orchestrator-g3` worktree in place, preserving
the uncommitted G3–G5 checkpoint based on
`37715caae63e6622cf3bc56432a67802af3ec8b2`. No new project branch/worktree,
production change, service, dependency, database, parallel ledger, Independent
Auditor or AI integration is introduced. Prior G3/G4/G5 validation documents
remain historical records; their publication restrictions describe those earlier
checkpoints, not the later conditional G3–G6 publication authorization.

## Applicability and separate states

The explicit minimal `g6-managed-v1` governance rule is:

- `owned-edits`: human post-execution acceptance REQUIRED.
- Exact read-only `git --no-optional-locks diff --check`: NOT REQUIRED.
- Other operation kinds: unsupported/blocked by the existing guards, not exempt.

This rule derives from the sealed approved Operation, not a worker-provided flag
or mutable approval marker. Internal Git probes get no extra approval step. The
existing diff-check marker is NOT_APPLICABLE; supplying an unneeded acceptance
record to that mode is rejected rather than treated as an implicit approval.

G2 authorization permits the exact future execution. It does not accept its eventual
result. The execution CLI still returns its G5 **technical** completion with exit
0 and reports `human_acceptance: PENDING` for edits, or NOT_REQUIRED for diff-check.
It does not read/issue a post-acceptance during execution. G5 summary/certificate
and previous NOT_EVALUATED human marker are not rewritten after a later review.

For required reviews, missing record means PENDING, not final acceptance. A valid
PENDING record also stays PENDING. ACCEPT passes G6; REJECT blocks without retry,
repair or rollback. Malformed/missing referenced input, uncertain G5 completion,
wrong identity or invalid decision blocks. Technical completion and G6 state are
reported separately. A technical PASS alone is never post-execution ACCEPT.

## Explicit operator action and read-only verification

After a real G5 completion exists, the operator explicitly reviews that concrete
result and records ONE decision in a separate operator-controlled file, outside
the source workspace, Git metadata and execution evidence directory. The runtime
does not provide an approval issuer, populate this record, or read worker/model
output as approval. Hardlinked or linked/reparse input is rejected. The operator
then supplies its separately reviewed SHA-256, not a reference trusted merely
because a worker/model suggested it. The original G5 certificate reference must
also come from a trusted successful execution/exit-0 record.

From `development/orchestrator`, read-only examples (placeholders, not live data):

```powershell
python -B -m orchestrator.managed --verify-human-acceptance "<run-directory>" --expected-certificate "<trusted-g5-sha256>"
python -B -m orchestrator.managed --verify-human-acceptance "<run-directory>" --expected-certificate "<trusted-g5-sha256>" --acceptance-record "<separate-reviewed-operator-file>" --expected-acceptance "<reviewed-record-sha256>"
```

The first returns PENDING/exit 2 for a completed edit, PASS/exit 0 (NOT_REQUIRED)
for diff-check. The second returns PASS/exit 0 for bound ACCEPT, BLOCK/exit 1 for
REJECT or invalid evidence, and PENDING/exit 2 for a valid pending review. It is
not a new pre-execution authorization or an execution continuation.

Minimal record packet schema (all bindings come from the already completed,
trusted G5 bundle; no executable template/real acceptance is checked in):

```json
{
  "schema": "hg-operator-acceptance-v1",
  "records": [{
    "id": "<separate-post-review-id>",
    "decision": "ACCEPT",
    "input_origin": "operator-reviewed",
    "policy_id": "g6-managed-v1",
    "completion_certificate_sha256": "<trusted-g5-sha256>",
    "task_id": "<certificate.task_id>",
    "operation_identity": "<certificate.binding.operation_identity>",
    "authorization_identity": "<certificate.attempt_binding.authorization_identity>",
    "workspace": {"root": "<original-root>", "branch": "<original-branch>", "baseline": "<original-head>"},
    "source_identity": "<certificate.attempt_binding.source_identity>",
    "post_source_identity": "<summary.revalidation.source_identity>",
    "attempt": 1,
    "g4_identity": "<certificate.g4_identity>",
    "evidence_refs": ["<specific-operator-review-reference>"]
  }]
}
```

The attempt number must match the certificate, not the illustrative 1. The actual
authorization is the successful attempt's authorization, including any G3 retry.
All operation/authorization/workspace/source/task/attempt/G4/G5 fields must match;
review ID must be nonempty and separate from the pre-authorization ID. Duplicate
JSON keys, unknown fields/states, repeated or conflicting records block. The
packet has exactly one decision. Re-reading the same valid record is idempotent
inspection, not a second acceptance action. Operators must retain and supply a
complete reviewed decision packet; this is not a durable global registry detecting
decisions omitted from input or replaced in other files/processes.

The verifier first requires valid anchored G5 evidence, then checks the record.
It reuses the existing strict JSON, file/link and hash verification functions.
It constructs no worker, writer or ExecutionBudget, spawns no process, reads no
current source content and changes no source/G5/operator file. The completed G3
budget is neither reused nor extended. Human review may occur later; it cannot
authorize another edit or restart an old attempt. Use `-B` to suppress interpreter
bytecode writes. OS-managed access-time updates are outside content-write control.

## Trust and remaining limits

This is the existing **trusted-operator / trusted-process** model, not human/RBAC
authentication, signed approval or OS isolation. The marker and checksums alone do
not prove a person reviewed the result. Supported managed edits cannot write the
separate operator input path; worker/LLM text, workspace/evidence-local records,
pre-authorization documents and missing operator references do not become ACCEPT.
Someone with arbitrary Python/shell/filesystem access under the trusted account
can forge both records and claimed trust references. The architecture cannot
cryptographically distinguish such a hostile process from the operator; no stronger
self-approval resistance or authenticated global replay protection is claimed.

All prior G1/G2 authorization/executable/environment trust, ignored-input, G3
cooperative hard-timeout/IO, G4 last-read-to-publication TOCTOU/concurrency and G5
unkeyed-hash, external-anchor and nontransactional crash/publication limits remain.
The verifier observes sealed historical facts and their binding, not current
production correctness or all concurrent writes. ACCEPT concerns one specific
completed result, never general future permission. No automatic production-ready,
deployment or unrestricted Orchestrator certification follows.

Test-generated operator records are explicitly **synthetic fixtures**, not real
human acceptance of this implementation. Automated scoped guard acceptance is
also not a real G6 decision for a production operation. Git publication below is
the user's separate conditional instruction after guard-test PASS; it neither
issues nor fabricates a runtime operator acceptance record.

## Tests / scoped matrix

```powershell
python -B development/orchestrator/run-tests.py
python -B development/orchestrator/acceptance_g3.py
python -B development/orchestrator/acceptance_g4.py
python -B development/orchestrator/acceptance_g5.py
python -B development/orchestrator/acceptance_g6.py
git --no-optional-locks diff --check
```

Unit/negative tests cover ACCEPT/REJECT/PENDING, every binding, worker/embedded
inputs, missing trust reference, pre-authorization substitution, duplicate and
conflicting records, damaged/missing G5, read-only behavior, no budget reopening
and diff-check exemption. Separate G6 acceptance exercises real G1–G5 completion
and synthetic operator review plus targeted G1/G2, G4 and G5 failure integration.
Fixture Git repositories/worktrees/commits are private/disposable, never the
project's branches or shared Git metadata. The inherited symlink SKIP remains
SKIP.

### Final verification — 2026-11-03

| Guard | Scoped automated result | Evidence |
|---|---|---|
| G1 | PASS | Preserved component governance; existing regressions |
| G2 | PASS | Unchanged evaluator, scope/path/hash/authorization regressions; inherited symlink SKIP retained |
| G3 | PASS | 28 unit/negative tests; separate acceptance 7/7 |
| G4 | PASS | 24 unit/negative tests; separate acceptance 12/12 |
| G5 | PASS | 26 unit/negative tests; separate acceptance 11/11 |
| G6 | PASS | 33 unit/negative tests; separate acceptance 14/14 |

Full standard suite: **184 run, 183 passed, one inherited symlink SKIP**, zero
failures/errors, **199.658 s**. Separate acceptance drivers: G3 **7/7**, **16.489 s**;
G4 **12/12**, **30.318 s**; G5 **11/11**, **30.456 s**; G6 **14/14**, **37.474 s**.
The G6 driver includes explicit negative G1/G2 authorization, fake G4 success,
missing G5 proof and worker/self-approval substitution integration cases. No new
skip is promoted to PASS. `git diff --check` passes.

**G1–G6 scoped automated acceptance: PASS**, only in the documented local managed,
trusted-process/operator scope. This is neither actual human acceptance of a real
production result nor production-ready certification. G6's synthetic operator
fixtures are not real project approvals. No human decision record is generated
for this project by the implementation/publication task.

Publication preflight confirms the exact 26-file allowlist, no unrelated/staged
leftovers, no generated/binary payload, no detected credential/private-key or
personal machine-path matches, and no active commit/push hooks. The G1/G2 evaluator
matches the published baseline. Every added/changed source/test/document in the
allowlist was reviewed in the implementation and targeted publication diff review.
The original remote target was absent; recheck it immediately before publication.
Only the explicitly authorized single commit/push below may proceed on this PASS.

## Exact G3–G6 publication allowlist

All paths below are relative to `development/orchestrator/`. Only these source,
test and required documentation files belong in the conditional single commit:

- `orchestrator/budget.py`
- `orchestrator/development.py`
- `orchestrator/governance.py`
- `orchestrator/human_acceptance.py`
- `orchestrator/ledger.py`
- `orchestrator/managed.py`
- `orchestrator/model.py`
- `orchestrator/recipe.py`
- `orchestrator/workbench.py`
- `orchestrator/workers.py`
- `tests/test_g3.py`
- `tests/test_g4.py`
- `tests/test_g5.py`
- `tests/test_g6.py`
- `tests/test_governance.py`
- `tests/test_managed_evidence.py`
- `tests/test_no_go_regressions.py`
- `acceptance_g3.py`
- `acceptance_g4.py`
- `acceptance_g5.py`
- `acceptance_g6.py`
- `README.md`
- `G3-VALIDATION.md`
- `G4-VALIDATION.md`
- `G5-VALIDATION.md`
- `G6-VALIDATION.md`

No generated evidence, operator record, runtime/model, secret, machine-specific
configuration or product file is included. The publication review must compare
this exact set, inspect the diff/fixtures/local-path matches and confirm no
foreign changes, no staged leftovers and the expected unchanged branch/base.

On full scoped PASS only, one commit is authorized:
`feat(orchestrator): complete G3-G6 scoped guard implementation`.
Push only `origin codex/orchestrator-g3`, without force/merge/rebase/tag/release.
Stop if the remote target differs from the initial absent-branch observation or
push would not be fast-forward. Verify remote SHA and clean worktree afterwards.
