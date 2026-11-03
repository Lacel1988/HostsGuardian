"""One reviewed local operation per invocation; no automatic authorization."""
import argparse
import json
from pathlib import Path
import threading
import sys
import subprocess
from .decisions import ExecutionFailure, Status, blocked
from .development import evidence_directory
from .governance import (Authorization, ManagedDevelopmentWorker, Profile, acceptance_pending,
                         operation_identity, profile_identity, source_identity)
from .ledger import Ledger
from .model import Operation, StateMachine, Task, TaskState
from .recipe import run_operation


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--request', required=True, type=Path)
    parser.add_argument('--authorization', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--inspect', action='store_true', help='Print identities only; never dispatch')
    parser.add_argument('--plain', action='store_true')
    args = parser.parse_args(argv)
    unicode_output = not args.plain
    try:
        '🔴🟢🟡⚪'.encode(getattr(sys.stdout, 'encoding', None) or 'ascii')
    except (UnicodeEncodeError, LookupError):
        unicode_output = False
    try:
        profile = Profile.load(read_json(args.profile))
        request = read_json(args.request)
        if set(request) != {'name', 'argv', 'cwd', 'timeout', 'category'} or not isinstance(request['argv'], list) or not all(isinstance(v, str) for v in request['argv']):
            raise ValueError('Invalid operation fields')
        request['argv'] = tuple(request['argv'])
        operation = Operation(**request)
        if args.inspect:
            print(json.dumps({'profile_identity': profile_identity(profile), 'source_identity': source_identity(profile.root),
                              'operation_identity': operation_identity(operation), 'dispatch': False}))
            return 0
        authorization = Authorization.load(read_json(args.authorization)) if args.authorization else None
        worker = ManagedDevelopmentWorker('ManagedLocalDevelopment', profile, authorization)
        decision = worker.evaluate(operation)
        if decision.status != Status.PASS:
            print(json.dumps(decision.to_dict(), ensure_ascii=True))
            print(decision.render(unicode=unicode_output))
            return 1
        if args.artifacts is None:
            raise ValueError('External fresh artifacts directory required')
        run = evidence_directory(profile.root, args.artifacts)
        run.mkdir(parents=True, exist_ok=False)
        ledger = Ledger(run / 'events.jsonl')
        task = Task('G1-G2-MANAGED', 'Exact authorized local operation', ['windows-development'])
        machine = StateMachine(task, ledger)
        machine.transition(TaskState.QUEUED, 'Reviewed profile selected')
        machine.transition(TaskState.RUNNING, 'Evaluate G1/G2 at managed dispatch')
        try:
            run_operation(machine, ledger, worker, operation, threading.Event())
            machine.transition(TaskState.VERIFYING, 'Managed operation returned successfully')
            machine.transition(TaskState.COMPLETE, 'Operation complete; final acceptance is not evaluated')
        except ExecutionFailure as exc:
            machine.transition(TaskState.FAILED, str(exc))
            decision = exc.decision or blocked('EXECUTION_FAILED', 'Managed execution did not complete successfully.')
        else:
            decision = worker.last_decision
        summary = {'dispatch_decision': decision.to_dict(), 'acceptance': acceptance_pending().to_dict(), 'task': task.snapshot()}
        (run / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        print(json.dumps(summary, ensure_ascii=True))
        print(decision.render(unicode=unicode_output))
        print(acceptance_pending().render(unicode=unicode_output))
        return 0 if task.state == TaskState.COMPLETE else 1
    except (ValueError, TypeError, KeyError, AttributeError, OSError, subprocess.SubprocessError) as exc:
        decision = blocked('INVALID_INPUT', 'Managed input or evidence validation failed (' + type(exc).__name__ + ').')
        print(json.dumps(decision.to_dict(), ensure_ascii=True))
        print(decision.render(unicode=unicode_output))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
