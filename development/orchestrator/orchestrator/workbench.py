"""Hash-guarded continuation of an owned, explicitly snapshotted development tree.

Roadmap slices share uncommitted work; a clean-only guard cannot continue them.
This recipe accepts an exact source snapshot, never arbitrary dirty state.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import uuid
from .development import DevelopmentWindowsWorker
from .ledger import Ledger
from .model import Task, TaskState, StateMachine, Operation
from .recipe import ExecutionFailure, run_operation
from .workers import Router


def snapshot(root):
    def git(*argv):
        return subprocess.check_output(['git', '--no-optional-locks', *argv], cwd=root).decode('utf-8').strip()
    paths = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root).decode('utf-8').split('\0')
    files = {}
    for name in sorted(set(paths) - {''}):
        path = root / name
        if root not in path.resolve().parents:
            raise ValueError('Source path escapes owned tree')
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return {'root': str(root.resolve()), 'branch': git('branch', '--show-current'),
            'head': git('rev-parse', 'HEAD'), 'origin': git('remote', 'get-url', 'origin'),
            'status': git('status', '--porcelain=v1', '--untracked-files=all'), 'files': files}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--edits', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--ticket', required=True)
    parser.add_argument('--checks', nargs='*', choices=['build', 'core', 'wpf', 'desktop', 'monitor'], default=[])
    args = parser.parse_args()
    root = args.root.resolve()
    expected = json.loads(args.snapshot.read_text(encoding='utf-8-sig'))
    if expected['branch'] in {'master', 'main', ''}:
        raise ValueError('An owned development branch is required')
    if root == args.artifacts.resolve() or root in args.artifacts.resolve().parents:
        raise ValueError('Evidence must be outside source')
    run = args.artifacts / (args.ticket + '-' + uuid.uuid4().hex[:8])
    run.mkdir(parents=True)
    def observe(event):
        print(f"{event['task_name']} {event['state'].value} {event['event']} {event['operation']}", flush=True)
    ledger = Ledger(run / 'events.jsonl', observe)
    task = Task(args.ticket, 'Owned snapshot continuation', ['windows-development'])
    machine = StateMachine(task, ledger)
    worker = Router([DevelopmentWindowsWorker('WindowsDevelopmentWorker', root)]).select('windows-development')
    cancel = threading.Event()
    commands = {'build': ('dotnet', 'build', 'HostsGuardian.sln'),
                'core': ('dotnet', 'run', '--project', 'HostsGuardian.RegressionTests'),
                'wpf': ('dotnet', 'run', '--project', 'HostsGuardian.Wpf.RegressionTests'),
                'desktop': ('dotnet', 'run', '--project', 'development/DesktopE2E'),
                'monitor': ('python', '-m', 'unittest', 'discover', '-s', 'linux-monitor')}
    try:
        machine.transition(TaskState.QUEUED, 'Exact owned source snapshot supplied')
        machine.transition(TaskState.RUNNING, 'Check identity and every source hash before writes')
        if snapshot(root) != expected:
            raise ExecutionFailure('Owned source snapshot mismatch')
        ledger.record(task, 'SOURCE_VERIFIED', 'Root/branch/HEAD/origin/status/source hashes matched')
        (run / 'snapshot.json').write_text(json.dumps(expected, indent=2), encoding='utf-8')
        (run / 'edits.json').write_bytes(args.edits.read_bytes())
        run_operation(machine, ledger, worker, Operation('Source edits', ('owned-edits', str(run / 'edits.json')), str(root), category='owned-development'), cancel)
        machine.transition(TaskState.TESTING, 'Run capability-routed checks')
        for check in args.checks:
            result = run_operation(machine, ledger, worker, Operation(check, commands[check], str(root), timeout=240, category='owned-development'), cancel)
            (run / (check + '.log')).write_text(result.stdout + '\n' + result.stderr, encoding='utf-8')
        machine.transition(TaskState.VERIFYING, 'Whitespace and repository identity preservation')
        run_operation(machine, ledger, worker, Operation('Diff check', ('git', '--no-optional-locks', 'diff', '--check'), str(root), category='owned-development'), cancel)
        actual = snapshot(root)
        for key in ('root', 'branch', 'head', 'origin'):
            if actual[key] != expected[key]:
                raise ExecutionFailure('Repository identity changed: ' + key)
        (run / 'result-source.json').write_text(json.dumps(actual, indent=2), encoding='utf-8')
        machine.transition(TaskState.COMPLETE, 'Slice edits and requested checks verified')
    except (ExecutionFailure, ValueError, OSError) as exc:
        task.blocker = str(exc)
        machine.transition(TaskState.FAILED, str(exc))
    (run / 'summary.json').write_text(json.dumps(task.snapshot(), indent=2), encoding='utf-8')
    (run / 'SHA256SUMS.json').write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in run.iterdir() if p.is_file()}, indent=2), encoding='utf-8')
    print(f'{task.state.value}; evidence={run}')
    return 0 if task.state == TaskState.COMPLETE else 1


if __name__ == '__main__':
    raise SystemExit(main())
