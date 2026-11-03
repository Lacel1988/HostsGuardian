"""One reviewed local operation per invocation; no automatic authorization."""
import argparse
import json
from pathlib import Path
import threading
import sys
import subprocess
import signal
import time
from dataclasses import asdict
from .budget import ExecutionBudget, active_budget, checkpoint
from .decisions import Decision, ExecutionFailure, Status, blocked
from .development import evidence_directory
from .governance import (Authorization, ManagedDevelopmentWorker, Profile, acceptance_pending,
                         operation_identity, profile_identity, source_identity)
from .ledger import Ledger
from .model import Operation, StateMachine, Task, TaskState
from .recipe import run_operation
from .human_acceptance import human_requirement, verify_human_acceptance


def read_json(path):
    checkpoint()
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON field')
            result[key] = value
        return result
    value = json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique)
    checkpoint()
    return value


def main(argv=None):
    started = time.monotonic()  # includes parsing, authorization and evidence preparation
    effective_args = list(sys.argv[1:] if argv is None else argv)
    if '--verify-human-acceptance' in effective_args:
        reader = argparse.ArgumentParser(description='Read-only post-execution operator acceptance; never dispatches.')
        reader.add_argument('--verify-human-acceptance', type=Path, required=True)
        reader.add_argument('--expected-certificate')
        reader.add_argument('--acceptance-record', type=Path)
        reader.add_argument('--expected-acceptance', help='Separately operator-reviewed record SHA-256')
        options = reader.parse_args(effective_args)
        report = verify_human_acceptance(options.verify_human_acceptance, options.expected_certificate,
                                         options.acceptance_record, options.expected_acceptance)
        print(json.dumps(report, ensure_ascii=True))
        return {'PASS': 0, 'BLOCK': 1, 'PENDING': 2}[report['status']]
    if '--verify-evidence' in effective_args:
        reader = argparse.ArgumentParser(description='Read-only managed completion verification; never dispatches.')
        reader.add_argument('--verify-evidence', type=Path, required=True)
        reader.add_argument('--expected-certificate', help='Trusted digest captured with a successful original CLI exit')
        options = reader.parse_args(effective_args)
        report = Ledger.verify_managed(options.verify_evidence, expected_certificate=options.expected_certificate)
        print(json.dumps(report, ensure_ascii=True))
        return {'PASS': 0, 'BLOCK': 1, 'UNKNOWN': 2}[report['status']]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--request', required=True, type=Path)
    parser.add_argument('--authorization', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--inspect', action='store_true', help='Print identities only; never dispatch')
    parser.add_argument('--plain', action='store_true')
    parser.add_argument('--budget', type=Path, help='Reviewed G3 budget JSON; required for dispatch')
    parser.add_argument('--retry-authorization', type=Path, action='append', default=[],
                        help='Reviewed fresh authorization for a subsequent attempt, in order')
    args = parser.parse_args(argv)
    unicode_output = not args.plain
    try:
        '🔴🟢🟡⚪'.encode(getattr(sys.stdout, 'encoding', None) or 'ascii')
    except (UnicodeEncodeError, LookupError):
        unicode_output = False
    token = None
    budget = None
    summary_path = None
    evidence_phase = False
    previous_sigint = None
    cancel = threading.Event()
    try:
        if not args.inspect:
            if args.budget is None:
                raise ValueError('Explicit G3 budget required')
            budget = ExecutionBudget.load(read_json(args.budget), started=started)
            budget.cancel = cancel
            token = active_budget.set(budget)
            checkpoint()
            if threading.current_thread() is threading.main_thread():
                previous_sigint = signal.signal(signal.SIGINT, lambda *_: cancel.set())
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
        worker.budget = budget
        retry_inputs = iter(args.retry_authorization)
        def reauthorize(attempt):
            checkpoint()
            path = next(retry_inputs, None)
            if path is None:
                budget.stop('G3_FRESH_AUTHORIZATION', 'No reviewed authorization remains for retry.')
            return Authorization.load(read_json(path))
        worker.reauthorize = reauthorize
        checkpoint()
        decision = worker.evaluate(operation)
        checkpoint()
        if decision.status != Status.PASS:
            print(json.dumps(decision.to_dict(), ensure_ascii=True))
            print(decision.render(unicode=unicode_output))
            return 1
        if args.artifacts is None:
            raise ValueError('External fresh artifacts directory required')
        run = evidence_directory(profile.root, args.artifacts)
        checkpoint()
        run.mkdir(parents=True, exist_ok=False)
        evidence_phase = True
        summary_path = run / 'summary.json'
        checkpoint()
        ledger = Ledger(run / 'events.jsonl', binding=worker.operation_binding(operation))
        task = Task('G1-G2-MANAGED', 'Exact authorized local operation', ['windows-development'])
        machine = StateMachine(task, ledger)
        machine.transition(TaskState.QUEUED, 'Reviewed profile selected')
        machine.transition(TaskState.RUNNING, 'Evaluate G1/G2 at managed dispatch')
        try:
            result = run_operation(machine, ledger, worker, operation, cancel)
            checkpoint()
            machine.transition(TaskState.VERIFYING, 'Managed operation returned successfully')
            checkpoint()
            ledger.verify_live(result=asdict(result))
            checkpoint()
            machine.transition(TaskState.COMPLETE, 'Operation complete; final acceptance is not evaluated')
            checkpoint()
        except ExecutionFailure as exc:
            if task.state not in {TaskState.COMPLETE, TaskState.FAILED, TaskState.CANCELLED}:
                machine.transition(TaskState.CANCELLED if cancel.is_set() else TaskState.FAILED, str(exc))
            decision = exc.decision or blocked('EXECUTION_FAILED', 'Managed execution did not complete successfully.')
        else:
            decision = worker.last_decision
        checkpoint()
        summary = {'dispatch_decision': decision.to_dict(), 'acceptance': acceptance_pending(operation).to_dict(),
                   'task': task.snapshot(), 'g3': budget.snapshot(),
                   'revalidation': worker.revalidation_decision.to_dict(), 'completion': 'CERTIFICATE_REQUIRED'}
        summary_path = run / 'summary.json'
        summary_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')
        checkpoint()
        completion = ledger.finalize_managed(summary_path, summary, asdict(result))
        checkpoint()
        print(json.dumps({**summary, 'completion_certificate': completion,
                          'human_acceptance': human_requirement(worker.evidence_binding)}, ensure_ascii=True))
        print(decision.render(unicode=unicode_output))
        print(acceptance_pending(operation).render(unicode=unicode_output))
        checkpoint()  # blocked output must not turn an overrun into exit 0
        budget.finished = True
        return 0 if task.state == TaskState.COMPLETE else 1
    except (ExecutionFailure, ValueError, TypeError, KeyError, AttributeError, OSError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        decision = (exc.decision if isinstance(exc, ExecutionFailure) and exc.decision is not None else
                    budget.failure if budget is not None and budget.failure is not None else
                    Decision(Status.BLOCK, ('G5',), 'EVIDENCE_INTEGRITY_FAILED',
                             'Evidence writing, validation or completion failed (' + type(exc).__name__ + ').',
                             'Stop and inspect evidence; no retry, repair or rollback.')
                    if evidence_phase and not isinstance(exc, KeyboardInterrupt) else
                    blocked('G3_CANCELLED' if isinstance(exc, KeyboardInterrupt) else 'INVALID_INPUT',
                            'Managed input, execution or evidence failed closed (' + type(exc).__name__ + ').'))
        if budget is not None:
            budget.failure = decision
        if summary_path is not None:
            # Best-effort failure publication only, never another source operation.
            try:
                summary_path.write_text(json.dumps({'dispatch_decision': decision.to_dict(),
                    'acceptance': acceptance_pending().to_dict(), 'completion': 'FAILED'}, indent=2), encoding='utf-8')
            except OSError:
                pass  # exit status/stdout remain failure even if storage is unavailable
        print(json.dumps(decision.to_dict(), ensure_ascii=True))
        print(decision.render(unicode=unicode_output))
        return 1
    finally:
        if previous_sigint is not None:
            signal.signal(signal.SIGINT, previous_sigint)
        if token is not None:
            active_budget.reset(token)


if __name__ == '__main__':
    raise SystemExit(main())
