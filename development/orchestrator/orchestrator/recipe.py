"""Reusable same-commit recipe with fail-closed repository guards."""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from .model import Task, TaskState, StateMachine, Operation, Outcome, WorkerState
from .workers import requires_approval


class ExecutionFailure(RuntimeError):
    pass


def validate_config(config, artifacts):
    expected = config['expected_commit']
    if len(expected) != 40 or any(c not in '0123456789abcdef' for c in expected):
        raise ValueError('Expected commit must be a full SHA')
    if len(config['repositories']) != 2:
        raise ValueError('Same-commit recipe requires two repositories')
    for repository in config['repositories']:
        if not repository['root'] or not repository['origin']:
            raise ValueError('Explicit root and origin required')
        if repository['platform'] == 'linux':
            root = PurePosixPath(repository['root'])
            dev = PurePosixPath(repository['development_root'])
            if '..' in root.parts or not root.is_absolute() or root == dev or dev not in root.parents:
                raise ValueError('Linux repository must be inside approved development root')
        else:
            root = Path(repository['root']).resolve()
            if root == artifacts.resolve() or root in artifacts.resolve().parents:
                raise ValueError('Artifacts must be outside authoritative repository')


def run_operation(machine, ledger, worker, operation, cancel):
    task = machine.task
    task.steps.append({'worker': worker.identity, **asdict(operation)})
    if worker.approval_required(operation):
        worker.state = WorkerState.WAITING_FOR_HUMAN
        task.blocker = f'Approval required: {operation.category} / {operation.name}'
        machine.transition(TaskState.WAITING_FOR_HUMAN, task.blocker, worker.identity)
        return None
    ledger.record(task, 'COMMAND_START', operation.name, worker.identity, asdict(operation))
    result = worker.run(operation, cancel,
                        lambda kind, identity, value: ledger.record(task, kind, operation.name, identity, value))
    record = {'worker': worker.identity, 'operation': operation.name, **asdict(result)}
    task.results.append(record)
    ledger.record(task, 'COMMAND_RESULT', operation.name, worker.identity, record)
    if result.outcome != Outcome.SUCCESS:
        raise ExecutionFailure(f'{worker.identity}: {operation.name}: {result.outcome.value}: {result.reason}')
    return result


def guard(machine, ledger, worker, repository, expected, cancel):
    operation = Operation('repository identity snapshot', ('repository-snapshot',), repository['root'])
    result = run_operation(machine, ledger, worker, operation, cancel)
    try:
        evidence = json.loads(result.stdout)
        if not isinstance(evidence,dict) or set(evidence) != {'git','root','origin','branch','head','status'} or not all(isinstance(v,str) for v in evidence.values()):
            raise ValueError('Invalid snapshot fields')
    except (json.JSONDecodeError, ValueError) as exc:
        raise ExecutionFailure('Invalid repository snapshot: '+str(exc)) from exc
    if evidence['git'] != 'true':
        raise ExecutionFailure('Not a Git repository')
    actual_root = evidence['root']
    root = repository['root']
    if repository['platform'] == 'windows':
        same_root = os.path.normcase(os.path.realpath(actual_root)) == os.path.normcase(os.path.realpath(root))
    else:
        same_root = actual_root == root
    if not same_root:
        raise ExecutionFailure(f'Repository root mismatch: {actual_root}')
    if evidence['origin'] != repository['origin']:
        raise ExecutionFailure('Origin mismatch')
    branch = evidence['branch']
    if branch != repository['branch']:
        raise ExecutionFailure(f"Branch mismatch: expected {repository['branch']!r}, observed {branch!r}")
    head = evidence['head']
    if head != expected:
        raise ExecutionFailure(f'Commit mismatch: expected {expected}, observed {head}')
    if evidence['status']:
        raise ExecutionFailure('Repository is not clean')
    ledger.record(machine.task, 'REPOSITORY_VERIFIED', 'Root/origin/branch/HEAD/clean verified', worker.identity,
                  {'root': root, 'origin': repository['origin'], 'head': head, 'clean': True})
    return head


def same_commit(config, router, ledger, artifacts, cancel):
    validate_config(config, artifacts)
    task = Task('ORCH-TEST-001', 'Read-only same-commit verification',
                [r['capability'] for r in config['repositories']])
    machine = StateMachine(task, ledger)
    observed = {}
    try:
        selected = [(r, router.select(r['capability'])) for r in config['repositories']]
        ledger.record(task, 'PLAN', 'Configured capabilities routed', result=
                      [{'capability': r['capability'], 'worker': w.identity} for r, w in selected])
        machine.transition(TaskState.QUEUED, 'Plan ready')
        for repository, worker in selected:
            machine.transition(TaskState.WAITING_FOR_WORKER, 'Requesting worker', worker.identity)
            machine.transition(TaskState.RUNNING, 'Repository identity and deterministic HEAD read', worker.identity)
            observed[worker.identity] = guard(machine, ledger, worker, repository, config['expected_commit'], cancel)
        machine.transition(TaskState.VERIFYING, 'Both commit results collected')
        # Verify again after both initial reads, detecting a concurrent change.
        for repository, worker in selected:
            guard(machine, ledger, worker, repository, config['expected_commit'], cancel)
        ledger.record(task, 'INVARIANT', 'Same-commit invariant verified', result=
                      {'expected': config['expected_commit'], 'observed': observed, 'verification_count': 2})
        machine.transition(TaskState.COMPLETE, 'Both clean repositories match expected commit')
    except (ExecutionFailure, ValueError, OSError) as exc:
        task.blocker = str(exc)
        target = TaskState.CANCELLED if cancel.is_set() else TaskState.FAILED
        machine.transition(target, str(exc))
    summary = {'task': task.snapshot(), 'expected': config['expected_commit'], 'observed': observed,
               'ledger': str(ledger.path), 'events': ledger.sequence,
               'workers': [{'identity': w.identity, 'capabilities': sorted(w.capabilities), 'state': w.state} for w in router.workers]}
    summary_path = artifacts/'summary.json'
    summary_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [ledger.path, summary_path]}
    (artifacts/'SHA256SUMS.json').write_text(json.dumps(hashes, indent=2), encoding='utf-8')
    return task
