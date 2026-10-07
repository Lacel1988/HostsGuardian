"""Owned-worktree development recipe, introduced for HG-001."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import threading
import uuid
from .model import Task, StateMachine, TaskState, Operation, Result, Outcome
from .ledger import Ledger
from .workers import LocalWindowsWorker, Router, requires_approval
from .recipe import guard, run_operation, ExecutionFailure


class DevelopmentWindowsWorker(LocalWindowsWorker):
    def __init__(self, identity, root):
        super().__init__(identity, ['windows-development'])
        self.root = Path(root).resolve()

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
        if operation.argv[0] != 'owned-edits':
            return super().execute(operation, cancel, notify)
        edits = json.loads(Path(operation.argv[1]).read_text(encoding='utf-8'))
        prepared=[]
        seen=set()
        for edit in edits:
            path = self.root/edit['path']
            if path.resolve() in seen: raise ValueError('Duplicate edit path')
            seen.add(path.resolve())
            if self.root not in path.resolve().parents or '.git' in path.relative_to(self.root).parts:
                raise ValueError('Edit escapes owned source worktree')
            data=path.read_bytes() if path.exists() else None
            digest=hashlib.sha256(data).hexdigest() if data is not None else None
            if digest != edit['before_sha256']:
                raise ValueError('Source hash mismatch: '+edit['path'])
            text=edit['content'] if 'content' in edit else data.decode('utf-8-sig')
            for replacement in edit.get('replacements', []):
                if text.count(replacement['old']) != 1:
                    raise ValueError('Replacement is not unique: '+edit['path'])
                text=text.replace(replacement['old'],replacement['new'],1)
            prepared.append((path,text))
        if cancel.is_set():
            return Result(Outcome.CANCELLED,None,reason='Cancelled before source write')
        for path,text in prepared:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text,encoding='utf-8',newline='')
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
    if root == args.artifacts.resolve() or root in args.artifacts.resolve().parents:
        raise ValueError('Evidence must be outside source')
    run=args.artifacts.resolve()/(args.ticket+'-'+uuid.uuid4().hex[:8]);run.mkdir(parents=True)
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
