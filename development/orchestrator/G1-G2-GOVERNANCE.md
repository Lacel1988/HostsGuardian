# G1/G2 governance MVP

Baseline: `769556d2e9a183da272e4f3a114eafe37165498b`. Development tooling only.
No product component, LLM, agent, database, service or automatic remediation is added.

## Enforced boundary

`orchestrator.managed` -> existing `recipe.run_operation` ->
`ManagedDevelopmentWorker.run` -> existing worker lifecycle and edit executor.
The profile permits hash-guarded source edits and/or Git diff whitespace checks.
Historical builds/tests and arbitrary commands are rejected, not silently adopted
as approved operations. The tooling tests run separately with temporary fixtures.

Before dispatch, the deterministic gate checks:

1. Canonical root with a linked-worktree `.git` file, exact development branch and
   full baseline HEAD. Case-insensitive master/main and detached HEAD cannot
   authorize writes. A regular primary checkout is rejected.
2. Reviewed profile digest, covering version, components, operation kinds and
   requirement applicability. Authorization must match this exact profile.
3. Current source identity: root, origin, branch, HEAD, status and hashes of all
   tracked/nonignored files. Exact operation identity includes name, argv, cwd,
   timeout, category and edit-manifest bytes. Stale source/policy/payload denies.
4. Every edit belongs to exactly one component prefix. Authorization must cover
   exactly the affected components, including legitimate cross-component work.
   Every before hash matches the existing bytes before any write.
5. Canonical relative targets only. Traversal, absolute paths, `.git`, alternate
   streams, Windows reserved names/trailing-dot/space/short-name aliases,
   links/junctions/reparse targets, hard-linked files and nested repositories deny.
6. Mandatory authorization evidence reference, finite bounded timeout and no
   cancellation before dispatch. Missing evidence returns REVISE without dispatch.
7. A second evaluation immediately before execution. A previous PASS/Decision is
   never a dispatch input. Authorization is consumed per worker instance.

Requirement records distinguish APPLICABLE and NOT_APPLICABLE by component;
they do not certify arbitrary product requirements. Unperformed G4/G6 acceptance
is NOT_EVALUATED. A core-only edit has no unrelated UX research prerequisite.

**F03:** historical local DEV/WB `run` cannot dispatch development operations
without the managed gate. Public development `execute` rejects unguarded commands.
A clean master plus matching historical `--branch master` cannot reach edits.

**F04:** approval gates raise typed ExecutionFailure instead of returning None.
`run_operation` validates results before dereferencing them. The repository guard
independently validates results and strict snapshot JSON, including duplicate
fields. Missing/malformed/inconsistent results and identity mismatches stop
dependent work and record structured decisions.

## Reviewed JSON inputs

Run from `development/orchestrator`. Keep operator-reviewed input documents outside
source. These are assertions from a trusted operator, not authenticated signatures.
The MVP does not authenticate the person who can write them or alter the process.
Never load authorization from worker output or model suggestions.

Set `HG_ORCH_EVIDENCE` to a private absolute directory outside every registered
source worktree and shared Git metadata. JSON placeholders below must be replaced
with reviewed canonical absolute paths; they are not runnable defaults.
After a worktree migration, collect a new profile and source identity; old
root-bound authorizations do not transfer automatically.

Illustrative profile schema; placeholders are not executable authorization:

```json
{
  "id": "reviewed-ticket-profile",
  "version": "g1-g2-v1",
  "root": "<canonical-linked-worktree-root>",
  "branch": "dev/reviewed-ticket",
  "baseline": "<full approved 40-character SHA>",
  "components": {"tooling": ["development/orchestrator"]},
  "operations": ["edit", "diff-check"],
  "requirements": {"TOOLING-SCOPE": ["tooling"]}
}
```

Request schema:

```json
{
  "name": "Reviewed source edit",
  "argv": ["owned-edits", "<external-evidence-root>/edits.json"],
  "cwd": "<canonical-linked-worktree-root>",
  "timeout": 20,
  "category": "owned-development"
}
```

Edits use the existing list of objects containing relative `path`, `before_sha256`
(null only for new files), and `content` or deterministic `replacements` containing
unique `old`/`new` strings. For diff check, argv must be exactly
`["git", "--no-optional-locks", "diff", "--check"]`; authorized components are
an empty list because no source edit is requested.

Inspect identities without dispatch:

```powershell
python -B -m orchestrator.managed --profile "$env:HG_ORCH_EVIDENCE/profile.json" --request "$env:HG_ORCH_EVIDENCE/request.json" --inspect
```

After reviewing these exact inputs and source, the operator supplies:

```json
{
  "id": "explicit-review-reference",
  "profile_identity": "<inspected profile SHA-256>",
  "source_identity": "<inspected source SHA-256>",
  "operation_identity": "<inspected operation SHA-256>",
  "components": ["tooling"],
  "evidence_refs": ["review:explicit-review-reference"]
}
```

Execution requires a new external evidence directory; existing evidence is never
overwritten. Source and shared Git metadata destinations are rejected.

```powershell
python -B -m orchestrator.managed --profile "$env:HG_ORCH_EVIDENCE/profile.json" --request "$env:HG_ORCH_EVIDENCE/request.json" --authorization "$env:HG_ORCH_EVIDENCE/authorization.json" --artifacts "$env:HG_ORCH_EVIDENCE/new-run" --plain
```

Fresh authorization is needed after source changes. No option grants authorization
or promotes denial to permission. Successful dispatch produces ledger JSONL and
summary JSON, separating dispatch permission from NOT_EVALUATED final acceptance.
Preflight denial emits JSON and text without executor dispatch or artifact-directory
creation. Capture stdout when durable preflight-denial evidence is needed.

## GOV-UI-01

Decision is the sole JSON/ledger/text status source. Its renderer supports Unicode,
optional terminal colors, and plain ASCII fallback (`--plain`). Display fields
escape line breaks, ANSI and bidi controls. Worker text cannot determine status.
Each PASS states exactly what was verified and cites evidence.

Illustrative output; the full renderer also supplies policy, next action and references:

- 🔴 BLOCK — AUTHORIZATION_MISSING: reviewed authorization required; no dispatch.
- 🟢 PASS — DISPATCH_AUTHORIZED: verified linked root, development branch, baseline,
  source/policy identities, exact operation/payload, paths, before hashes and
  component authorization. Evidence: review reference and identity hashes.
  This permits only the specified dispatch.
- 🟡 REVISE — EVIDENCE_MISSING: supply reviewed authorization evidence; no dispatch.
- ⚪ NOT_EVALUATED — ACCEPTANCE_NOT_EVALUATED: obtain separate test/acceptance evidence.

## Known limitations and bypass routes

- Trusted single-process gate, not an OS sandbox, user/RBAC system, signed approval
  service or repository lock. Code/filesystem access can forge assertions, mutate
  Python state, call internal `_execute_edits` or execute an external shell.
- Base local/SSH workers, `run_process`, direct SSH/scp, candidate imports and
  historical Linux recipes remain outside the protected boundary. They receive no
  G1/G2 protection PASS. Existing same-commit reads remain a distinct recipe.
- Double checking is point-in-time, not locking. External writers can race checks
  and writes. Edits are not transactional; partial I/O failure can leave partial
  changes. No rollback/remediation is implemented.
- Source hashing excludes ignored inputs, executable identity, Git configuration,
  ACLs and external dependencies. The Git executable/environment are trusted;
  the gate does not sandbox Git configuration or subprocess behavior. Large trees
  increase hashing cost.
- Consumption is per worker instance, not durable global replay prevention. A new
  process may reuse assertions if exact source/payload remain unchanged, such as
  no-op edits or repeated diff checks.
- Evidence references are required but content/signers are not authenticated.
  Requirement applicability is scope metadata, not business-rule verification.
  Task COMPLETE means operation completion, not G4 tests or G6 human acceptance.
- Only edit and diff-check dispatch are supported. Product builds/tests, deployment,
  production safety and AI roadmap completion are not certified by this MVP.

## Deferred GOV-REC-01 specification

Specification only, gated on separate G1/G2 acceptance. G2 confines any future
repair to existing authorization/scope; G3 bounds attempts/time; G4 revalidates
original conditions and acceptance; G5 records decisions, authorization, repairs
and results; G6 preserves required human approval. Future recovery records should
include reason code, confirmed cause or labeled hypothesis, next action, automation
permission, affected scope/authorization, verification and rollback requirements.
No privilege grants, security weakening, protected-branch or production repair is
authorized or implemented here.

## Validation

```powershell
python -B development/orchestrator/run-tests.py
git diff --check
```

Tests create/commit only their own temporary Git fixtures and linked worktrees.
Fake dispatchers cover denied and valid requests; actual edits target fixture files
only. A process-spy test restricts managed dispatch to read-only local Git probes.
No product scripts, production DNS/network changes, real SSH transport, service
control or deployment commands run. See G1-G2-VALIDATION.md for final measurements.

The independent 2026-11-03 review is recorded in
[G1-G2-VALIDATION.md](G1-G2-VALIDATION.md#independent-acceptance--2026-11-03).
**ACCEPTANCE PASS a dokumentált, megbízható folyamaton belüli G1/G2 managed fejlesztési scope-ra.**
The separately authorized real-symlink follow-up returned **SYMLINK_PASS**;
see [the targeted verification](G1-G2-VALIDATION.md#targeted-windows-symlink-verification).
This does not rewrite the historical suite skips or certify production, full
security or G3–G6 acceptance. Trusted-process, TOCTOU, replay, ignored-input and
nontransactional I/O limitations above remain unchanged. Runtime
`acceptance_pending()` still describes separate G4/G6 final-task acceptance;
this scoped audit result does not change its runtime status.
