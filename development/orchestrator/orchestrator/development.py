"""Owned-worktree development recipe, introduced for HG-001."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import signal
import subprocess
import threading
import uuid
from .model import Task, StateMachine, TaskState, Operation, Result, Outcome
from .ledger import Ledger
from .workers import LocalWindowsWorker, Router, requires_approval
from .recipe import guard, run_operation, ExecutionFailure


def evidence_directory(root, artifacts, ticket=None):
    """Validate evidence before writes; no ticket means the exact managed CLI target."""
    reserved = {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)), *(f'lpt{i}' for i in range(1, 10))}
    def safe_part(part):
        return (part not in {'', '.', '..'} and part.rstrip(' .') == part and
                part.casefold() != '.git' and part.split('.')[0].casefold() not in reserved and
                not any(c in '/\\:~<>"|?*' or ord(c) < 32 or ord(c) == 127 for c in part))
    if ticket is not None and (not isinstance(ticket, str) or not safe_part(ticket)):
        raise ValueError('Ticket must be a canonical filename, not a path')
    artifacts = Path(artifacts)
    if str(artifacts).startswith(('\\\\?\\', '\\\\.\\')) or (artifacts.drive and not artifacts.is_absolute()):
        raise ValueError('Evidence base cannot use a Windows namespace or drive-relative alias')
    if any(not safe_part(p) for p in artifacts.parts if p not in {artifacts.anchor, '.', '..'}):
        raise ValueError('Evidence base contains a Windows path alias')
    base = artifacts.resolve()
    run = (base / (ticket + '-' + uuid.uuid4().hex[:8])).resolve() if ticket is not None else base
    if ticket is not None and run.parent != base:
        raise ValueError('Evidence escapes approved base')
    def git(*argv):
        return subprocess.check_output(['git', '--no-optional-locks', *argv], cwd=root, timeout=20).decode('utf-8')
    common = Path(git('rev-parse', '--path-format=absolute', '--git-common-dir').strip()).resolve()
    roots = [Path(item[len('worktree '):]).resolve() for item in
             git('worktree', 'list', '--porcelain', '-z').split('\0') if item.startswith('worktree ')]
    if not roots:
        raise ValueError('Cannot establish protected worktrees')
    for protected in [Path(root).resolve(), common, *roots]:
        if run == protected or protected in run.parents:
            raise ValueError('Evidence must be outside every source worktree and shared Git metadata')
    return run


def prepare_edits(root, edits, path_validator=None):
    """Fully validate and encode every edit before dispatch or any source write."""
    if not isinstance(edits, list) or not edits:
        raise ValueError('Nonempty edit list required')
    root = Path(root).resolve()
    prepared, seen = [], set()
    for edit in edits:
        if (not isinstance(edit, dict) or not {'path', 'before_sha256'} <= set(edit) or
                not set(edit) <= {'path', 'before_sha256', 'content', 'replacements'}):
            raise ValueError('Invalid edit fields')
        name, expected = edit['path'], edit['before_sha256']
        if not isinstance(name, str) or not name:
            raise ValueError('Edit path must be a nonempty string')
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected)):
            raise ValueError('Invalid before SHA-256')
        path = path_validator(root, name) if path_validator else root / name
        resolved = path.resolve()
        if root not in resolved.parents or any(p.casefold() == '.git' for p in path.relative_to(root).parts):
            raise ValueError('Edit escapes owned source worktree')
        key = str(resolved).casefold()
        if key in seen:
            raise ValueError('Duplicate edit path')
        seen.add(key)
        if 'content' in edit and not isinstance(edit['content'], str):
            raise ValueError('Edit content must be a string')
        replacements = edit.get('replacements', [])
        if not isinstance(replacements, list):
            raise ValueError('Replacements must be a list')
        for replacement in replacements:
            if (not isinstance(replacement, dict) or set(replacement) != {'old', 'new'} or
                    not isinstance(replacement['old'], str) or not replacement['old'] or
                    not isinstance(replacement['new'], str)):
                raise ValueError('Invalid replacement fields')
            replacement['old'].encode('utf-8')
            replacement['new'].encode('utf-8')
        if 'content' not in edit and not replacements:
            raise ValueError('Content or nonempty replacements required')
        data = path.read_bytes() if path.exists() else None
        if (hashlib.sha256(data).hexdigest() if data is not None else None) != expected:
            raise ValueError('Source hash mismatch: ' + name)
        if 'content' not in edit and data is None:
            raise ValueError('Replacement requires an existing file')
        text = edit['content'] if 'content' in edit else data.decode('utf-8-sig')
        for replacement in replacements:
            if text.count(replacement['old']) != 1:
                raise ValueError('Replacement is not unique: ' + name)
            text = text.replace(replacement['old'], replacement['new'], 1)
        prepared.append((path, text.encode('utf-8')))
    return prepared


class DevelopmentWindowsWorker(LocalWindowsWorker):
    def __init__(self, identity, root):
        super().__init__(identity, ['windows-development'])
        self.root = Path(root).resolve()

    def run(self, operation, cancel, notify):
        if operation.category == 'owned-development':
            from .decisions import ExecutionFailure, blocked
            decision = blocked('AUTHORIZATION_MISSING', 'Historical DEV/WB dispatch has no G1/G2 authorization. Use the managed entry point.')
            notify('GOVERNANCE_DECISION', self.identity, decision.to_dict())
            raise ExecutionFailure(decision.reason, decision)
        return super().run(operation, cancel, notify)

    def approval_required(self, operation):
        if Path(operation.cwd).resolve() != self.root:
            return True
        if not requires_approval(operation):
            return False
        if operation.category != 'owned-development':
            return True
        argv = operation.argv
        return not (argv[:1] == ('owned-edits',) and len(argv) == 2 or
                    argv == ('dotnet','build','HostsGuardian.sln') or
                    argv[:3] == ('dotnet','run','--project') and argv[3:] in {
                        ('HostsGuardian.Wpf.RegressionTests',), ('HostsGuardian.RegressionTests',),
                        ('development/DesktopE2E',)} or
                    argv == ('python', '-m', 'unittest', 'discover', '-s', 'linux-monitor') or
                    argv == ('git','--no-optional-locks','diff','--check'))

    def execute(self, operation, cancel, notify):
        if requires_approval(operation) and not getattr(self, '_managed_active', False):
            from .decisions import ExecutionFailure, blocked
            decision = blocked('MANAGED_ENTRY_REQUIRED', 'Development execution requires a fresh managed dispatch decision.')
            raise ExecutionFailure(decision.reason, decision)
        if operation.argv[0] != 'owned-edits':
            return super().execute(operation, cancel, notify)
        return self._execute_edits(operation, cancel, notify)

    def _execute_edits(self, operation, cancel, notify):
        # Internal edit primitive; managed callers must enter through run().
        edits = json.loads(Path(operation.argv[1]).read_text(encoding='utf-8'))
        prepared = prepare_edits(self.root, edits)
        if cancel.is_set():
            return Result(Outcome.CANCELLED,None,reason='Cancelled before source write')
        for path,content in prepared:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return Result(Outcome.SUCCESS,0,json.dumps({'edited':[str(p.relative_to(self.root)) for p,_ in prepared]}),dispatched=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',required=True,type=Path)
    parser.add_argument('--base',required=True)
    parser.add_argument('--branch',required=True)
    parser.add_argument('--ticket',required=True)
    parser.add_argument('--edits',required=True,type=Path)
    parser.add_argument('--artifacts',required=True,type=Path)
    args=parser.parse_args()
    root=args.root.resolve()
    run=evidence_directory(root,args.artifacts,args.ticket)
    run.mkdir(parents=True)
    (run/'edits.json').write_bytes(args.edits.read_bytes())
    cancel=threading.Event();signal.signal(signal.SIGINT,lambda *_:cancel.set())
    def observe(event):
        text=f"{event['task_name']} {event['state'].value} {event['worker'] or '-'} {event['event']} {event['operation']}"
        if event['result'] is not None:text+=' '+json.dumps(event['result'])
        print(text,flush=True)
        with (run/'operator.log').open('a',encoding='utf-8') as f:f.write(text+'\n')
    ledger=Ledger(run/'events.jsonl',observe)
    task=Task(args.ticket,'Owned-worktree edit/build/regression verification',['windows-development'])
    machine=StateMachine(task,ledger)
    worker=Router([DevelopmentWindowsWorker('WindowsDevelopmentWorker',root)]).select('windows-development')
    repository={'root':str(root),'origin':'https://github.com/Lacel1988/HostsGuardian.git','branch':args.branch,'platform':'windows'}
    try:
        machine.transition(TaskState.QUEUED,'Owned worktree selected')
        machine.transition(TaskState.RUNNING,'Validate candidate base before editing')
        guard(machine,ledger,worker,repository,args.base,cancel)
        run_operation(machine,ledger,worker,Operation('Hash-guarded source edits',('owned-edits',str(run/'edits.json')),str(root),category='owned-development'),cancel)
        machine.transition(TaskState.TESTING,'Build and regressions')
        for argv in [('dotnet','build','HostsGuardian.sln'),('dotnet','run','--project','HostsGuardian.Wpf.RegressionTests'),('dotnet','run','--project','HostsGuardian.RegressionTests')]:
            run_operation(machine,ledger,worker,Operation(' '.join(argv),argv,str(root),timeout=180,category='owned-development'),cancel)
        machine.transition(TaskState.VERIFYING,'Source diff and base preservation')
        run_operation(machine,ledger,worker,Operation('Diff check',('git','--no-optional-locks','diff','--check'),str(root),category='owned-development'),cancel)
        observed=subprocess.check_output(['git','--no-optional-locks','rev-parse','HEAD'],cwd=root,text=True).strip()
        if observed != args.base:raise ExecutionFailure('Candidate base changed during execution')
        (run/'source.patch').write_bytes(subprocess.check_output(['git','diff','--binary'],cwd=root))
        machine.transition(TaskState.COMPLETE,'Source edits/build/tests/diff verified')
    except (ExecutionFailure,ValueError,OSError) as exc:
        task.blocker=str(exc);machine.transition(TaskState.CANCELLED if cancel.is_set() else TaskState.FAILED,str(exc))
    (run/'summary.json').write_text(json.dumps(task.snapshot(),indent=2),encoding='utf-8')
    (run/'SHA256SUMS.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in run.iterdir() if p.is_file()},indent=2),encoding='utf-8')
    print(f'{task.state.value}; evidence={run}')
    return 0 if task.state==TaskState.COMPLETE else 1


if __name__=='__main__':
    raise SystemExit(main())
