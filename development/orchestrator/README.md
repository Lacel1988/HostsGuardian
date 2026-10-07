# Development Orchestrator â€” Milestone 1

A standard-library Python 3.10+ CLI for a deterministic, read-only, two-worker
same-commit verification recipe. This is development tooling, not a HostsGuardian
product component. `development/orchestrator` keeps it associated with the first
project while separating reusable code from `hostsguardian.example.json`. It has no .NET,
GTK, production Engine, service-control or deployment dependency.

## Run

From this directory, copy `hostsguardian.example.json` to the ignored
`hostsguardian.local.json` and supply your own repository paths, SSH alias and
expected commit/branch. Example paths are not a ready-to-run machine configuration:

```powershell
python -m compileall -q orchestrator tests
python -m unittest discover -s tests -v
python -m orchestrator --config hostsguardian.local.json --artifacts C:/Temp/hostsguardian-orchestrator-evidence
```

The configuration explicitly selects the clean authoritative Windows checkout,
not the development worktree or the terminal's starting directory. The Linux
checkout is restricted to the configured development root. Git calls use
`--no-optional-locks`. Repository roots, exact origin URLs, expected branch and
full base SHA are validated before proceeding. An empty configured branch means
an explicitly expected detached HEAD (the observed Linux development checkout),
not any branch. Both repositories are checked
again after collection. An invariant mismatch stops dependent operations and
ends FAILED. No checkout, fetch, commit, index write or product command is part
of ORCH-TEST-001.

## Architecture

- `model.py`: generic task, operation, typed execution result, worker states and
  explicit validated state machine. Public task state is read-only; transitions
  and invalid attempts enter the ledger.
- `ledger.py`: append-only UTF-8 JSONL with flush/fsync per event; includes UTC
  timestamps, sequence, task/worker IDs, operations, results and task snapshots.
- `workers.py`: configured local Windows and SSH Linux workers, capability router,
  bounded subprocess execution, cancellation and approval policy.
- `recipe.py`: repository guard and same-commit recipe; final summary and SHA-256
  integrity manifest. No project names/paths or expected SHAs are embedded in core.
- `snapshot.py`: fixed six-command read-only Git probe; one SSH connection per
  repository snapshot, with no remote installation. Python 3 is required on Linux.
- `__main__.py`: CLI, Ctrl+C signal, live events and elapsed time, evidence directory
  creation and persisted operator transcript.
- `hostsguardian.example.json`: project-specific roots, origin, branch, SHA, worker alias
  and advertised capability requirements. Contains no authentication material.

Routing requires exactly one configured worker for each capability. Workers
expose OFFLINE, IDLE, BUSY, WAITING_FOR_HUMAN and ERROR. There is no discovery or
daemon. A future project supplies another JSON file with its own two repositories,
worker capabilities and expected commit, and uses the same recipe. This milestone
does not define an arbitrary workflow language.

## Lifecycle and observation

Normal history: PLANNING â†’ QUEUED â†’ WAITING_FOR_WORKER â†’ RUNNING (Windows) â†’
WAITING_FOR_WORKER â†’ RUNNING (Linux) â†’ VERIFYING â†’ COMPLETE. FAILED and CANCELLED
are terminal. TESTING is available for future test steps. WAITING_FOR_HUMAN blocks
approval-required operations; a later reviewed implementation may requeue it.
There is no automatic approval/resume executor in this milestone.

Output shows task identity, state, worker, operation, actual elapsed time,
stdout/stderr/exit result, reason and final artifact path. Heartbeats report waiting
elapsed time, never a percentage. Worker/result events are durable. Test counts in
ORCH-TEST-001 are verification counts, not product regression execution.

Each run gets a unique external directory: `config.json`, `events.jsonl`,
`operator.log`, `summary.json`, `SHA256SUMS.json`. No private keys or credentials
are read or copied into these artifacts. Git origin and SSH errors can contain
internal machine details, so evidence stays outside Git; review it before sharing.

```powershell
python -m orchestrator --show-ledger <run-directory>/events.jsonl
```

History can be inspected in a new process. It never replays a command. A crash
leaves the last durable state (possibly RUNNING); this is unfinished evidence,
not COMPLETE. Torn/corrupt JSONL fails visibly; it is not silently repaired.

## SSH execution boundary

The worker uses the existing `hostsguardian-linux-worker` alias, batch mode,
strict host-key checking, a bounded connect timeout and transport keepalives.
No key, password or host-key material is embedded. No host-key acceptance/change
is automatic. Arguments and cwd are quoted for the Linux shell.

Before a repository command is sent, a harmless readiness probe may retry within
the configured small bound (default two attempts; HostsGuardian three attempts)
for recognized connection timeout/refusal/no-route failures. Host-key/authentication
failures do not retry. Connection timeout is configurable within 1â€“30 seconds
(HostsGuardian: 10 seconds); attempts are restricted to 1â€“3. Each attempt has
recorded evidence. Exhaustion is FAILED
before repository dispatch; the Linux worker becomes OFFLINE.

The actual command is framed with per-call random START/END markers. Connection
loss, missing framing, timeout or cancellation after command dispatch is
UNCERTAIN, even when START was not received: it might have run. This command is
never retried automatically. A completed remote nonzero exit is FAILED; a completed
zero exit is SUCCESS. Exit 255 remains conservative UNCERTAIN. A later explicit
new read-only task is independent of any failed task; history is retained.

## Safety, human gates and cancellation

This MVP permits only the exact read-only Git operations used by its guard.
The snapshot operation expands only to those six fixed reads; configuration
cannot supply code or commands to that expansion.
Unknown commands and all other operation categories require a human gate,
including privileged actions, installation, services, deployment, production
policy/state, systemd/polkit, networking/DNS/firewall/router/DHCP and destructive
Git/force push. Labelling an arbitrary command "repository-read" cannot bypass
the allowlist. No privileged action is implemented.

Ctrl+C requests cancellation. Local subprocesses are terminated with bounded
pipe collection; descendant lifetime is not universally proven. SSH cancellation
terminates the local client; remote process termination is not proven and the
execution result stays UNCERTAIN. The task can be CANCELLED while containing
an UNCERTAIN remote result; the result must be inspected rather than assuming
that nothing ran. This is not exactly-once distributed execution.

## Boundaries and next milestone

Single process / single writer; no concurrent tasks, database server, dashboard,
RBAC, dynamic discovery, daemon, cloud service or general remote shell recipe.
Clean/unchanged checks are point-in-time evidence, not locks against external
writers. Only this same-commit recipe executes automatically. Large-output
streaming/backpressure, cross-process ledger locking, approval identity/signing,
crash resumption and a source-modifying recipe are deferred.

Reasoning remains on Lenovo in the current coding session. Linux is a deterministic
SSH execution worker, not a model host, and requires no Linux Codex installation.
There is no remote agent daemon or model-driven shell planning on Linux.

Milestone 2 should add one narrowly reviewed development-ticket recipe for
HG-001 (WPF Log newest-first): explicit disposable worktree, bounded allowed
edit/build/test steps, diff/result evidence and a human review gate before merge.
Do not apply that feature, merge, push or deploy as part of Milestone 1.
