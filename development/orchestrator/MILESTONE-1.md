# Milestone 1 acceptance — 2026-10-06

## VERIFIED

- Python byte compilation: PASS. Automated orchestrator suite: **23 tests PASS**.
- Real ORCH-TEST-001 task `4cfcd1c2149c49948963cb9523cf8f9b`: **COMPLETE**.
- Windows and Linux HEAD both equal
  `93d1814f7af9b1a750cde2cc96ebef14aaca9152`.
- Both guards verified exact root, origin, expected branch state and clean worktree,
  twice. Windows branch: master; Linux: observed detached HEAD, explicitly configured.
- All four final snapshot operations returned SUCCESS / exit 0. Both workers IDLE.
- 39 durable events; final run approximately 2.9 seconds. Evidence directory basename:
  `run-20261006-100536-da600d96` under the external operator artifact root.
- Event sequence: PLANNING → QUEUED → WAITING_FOR_WORKER → RUNNING →
  WAITING_FOR_WORKER → RUNNING → VERIFYING → COMPLETE.
- JSONL recovery in a fresh process and SHA-256 evidence verification tested.
- Authoritative master stayed at the baseline; no product files, production paths,
  services, policy, network configuration or privileged settings were modified.

## IMPLEMENTED

Generic task/results/state machine; durable event ledger; capability routing;
LocalWindowsWorker/SshLinuxWorker; fixed read-only repository snapshots; fail-closed
guards; bounded subprocesses; conservative SSH uncertainty; cancellation; human
gate representation; CLI events/elapsed time; external per-run evidence and hashes.
See README.md for the component inventory, run commands and safety boundaries.

Intermittent SSH failures were retained as FAILED runs, not counted as passes.
One early configuration assumed a Linux master branch; the guard rejected the
actual detached state and configuration was corrected without changing the checkout.
Snapshot collection was consolidated to avoid unnecessary SSH reconnects.
An intermediate implementation exception left an unfinished ledger; it was fixed,
covered by tests, and was not represented as a completed task. The accepted run is
the explicit task ID above, not any earlier attempt.

## DEFERRED / NON-BLOCKING

- No distributed exactly-once execution or proven remote process cancellation.
- No workflow resumption, simultaneous tasks, cross-process locking, dynamic worker
  discovery, daemon, dashboard, arbitrary command recipes or approval execution.
- External writers are not locked; guard evidence is point-in-time. Large stdout
  is captured in memory. Connection availability remains an environmental caveat.
- Generic recipe registration and project extraction can wait for a second actual
  project. Model reasoning stays on Lenovo; Linux only executes deterministic SSH work.

## BLOCKING

None for Milestone 1 accepted coverage. Future runs can still fail visibly when
SSH is unavailable; a historical PASS does not claim permanent availability.

## Milestone 2 recommendation (not implemented)

Add a single narrowly reviewed development-ticket recipe for **HG-001 — WPF Log
newest-first**: isolated worktree, explicit edit/build/test steps, preservation of
ordering after severity filtering, durable diff/test evidence, and a human gate
before merge/publication. Keep production deployment and Phase 5E-8 out of scope.
