"""Self-contained Git bundle handoff and scoped Linux development verification.

Only fresh directories under the configured hgworker development root are used.
Production repositories/services are never dispatched operations by this recipe.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import shlex
import subprocess
import threading
import uuid
from .ledger import Ledger
from .model import Task, TaskState, StateMachine, Operation, Outcome
from .recipe import ExecutionFailure, guard, run_operation
from .workers import SshLinuxWorker, Router, run_process, requires_approval


class LinuxDevelopmentWorker(SshLinuxWorker):
    def __init__(self, alias, root, development_root, expected, origin, branch):
        super().__init__('LinuxDevelopmentWorker', ['linux-development'], alias, connect_timeout=10, probe_attempts=3)
        self.root, self.development_root = PurePosixPath(root), PurePosixPath(development_root)
        if not self.root.is_absolute() or '..' in self.root.parts or self.development_root not in self.root.parents:
            raise ValueError('Candidate must be inside configured development root')
        self.expected, self.origin, self.branch = expected, origin, branch

    def approval_required(self, operation):
        if PurePosixPath(operation.cwd) != self.root: return True
        if not requires_approval(operation): return False
        if operation.category != 'owned-development': return True
        return operation.argv not in {
            ('dotnet', 'run', '--project', 'HostsGuardian.RegressionTests'),
            ('python3', '-m', 'unittest', 'discover', '-s', 'linux-monitor'),
            ('xvfb-run', '-a', 'python3', '-m', 'unittest', 'discover', '-s', 'linux-monitor'),
            ('python3', 'development/orchestrator/run-tests.py'),
            ('python3', 'development/roadmap/build-candidate.py'),
            ('git', '--no-optional-locks', 'diff', '--check')}


class CandidateImportWorker(SshLinuxWorker):
    def __init__(self, alias, development_root, code):
        super().__init__('LinuxArtifactHandoff', ['linux-handoff'], alias, connect_timeout=10, probe_attempts=3)
        self.development_root, self.code = development_root, code
    def approval_required(self, operation):
        return operation.cwd != self.development_root or operation.category != 'owned-development' or operation.argv != ('candidate-import',)
    def execute(self, operation, cancel, notify):
        return super().execute(Operation(operation.name, ('python3', '-c', self.code), operation.cwd, operation.timeout), cancel, notify)


def main():
    parser = argparse.ArgumentParser()
    for name in ('alias','development-root','base-root','base','commit','origin','branch'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--gtk', action='store_true')
    parser.add_argument('--prepare-deployment', action='store_true')
    args = parser.parse_args()
    if len(args.commit) != 40 or any(c not in '0123456789abcdef' for c in args.commit): raise ValueError('Full candidate SHA required')
    nonce = uuid.uuid4().hex[:8]
    dev = PurePosixPath(args.development_root)
    root = dev / ('roadmap-'+args.commit[:12]+'-'+nonce)
    upload = dev / ('candidate-'+nonce+'.bundle')
    run = args.artifacts / ('HG-LINUX-INTEGRATION-'+nonce); run.mkdir(parents=True)
    def observe(event): print(f"{event['task_name']} {event['state'].value} {event['event']} {event['operation']}", flush=True)
    ledger = Ledger(run/'events.jsonl', observe)
    task = Task('HG-LINUX-INTEGRATION', 'Verified source handoff and isolated Linux tests', ['linux-development'])
    machine = StateMachine(task, ledger); cancel = threading.Event()
    worker = Router([LinuxDevelopmentWorker(args.alias, str(root), str(dev), args.commit, args.origin, args.branch)]).select('linux-development')
    base_worker = SshLinuxWorker('LinuxBaseGuard', ['linux-git'], args.alias, connect_timeout=10, probe_attempts=3)
    base_repository = {'platform':'linux','root':args.base_root,'origin':args.origin,'branch':''}
    repository = {'platform':'linux','root':str(root),'origin':args.origin,'branch':args.branch}
    try:
        machine.transition(TaskState.QUEUED, 'Self-contained candidate bundle selected')
        machine.transition(TaskState.RUNNING, 'Protect base checkout and validate development path')
        guard(machine, ledger, base_worker, base_repository, args.base, cancel)
        digest = hashlib.sha256(args.bundle.read_bytes()).hexdigest()
        # Read-only path preflight before copying a new artifact.
        path_code = "from pathlib import Path; p=Path("+repr(str(dev))+ "); assert p.is_dir() and str(p.resolve())==str(p)"
        probe = base_worker.ssh(shlex.join(['python3','-c',path_code]),20,cancel,lambda *items: ledger.record(task,'PATH_PREFLIGHT','Development path heartbeat',result=items))
        ledger.record(task,'PATH_RESULT','Development path validation',result=asdict(probe))
        if probe.outcome != Outcome.SUCCESS: raise ExecutionFailure('Development path preflight failed')
        copied = run_process(['scp','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',
                              str(args.bundle.resolve()),args.alias+':'+str(upload)],None,60,cancel,
                              lambda elapsed:ledger.record(task,'HEARTBEAT','Artifact copy',result={'elapsed':elapsed}))
        ledger.record(task,'ARTIFACT_COPY','Self-contained source bundle',result=asdict(copied))
        if copied.outcome != Outcome.SUCCESS:
            raise ExecutionFailure('Artifact copy incomplete/uncertain; do not reuse destination blindly')
        code = """import hashlib, json, subprocess
from pathlib import Path
dev=Path(DEV); dest=Path(DEST); bundle=Path(BUNDLE)
assert str(dev.resolve())==str(dev) and dest.parent==dev and not dest.exists()
assert hashlib.sha256(bundle.read_bytes()).hexdigest()==DIGEST
subprocess.run(['git','clone','--branch',BRANCH,str(bundle),str(dest)],check=True)
subprocess.run(['git','remote','set-url','origin',ORIGIN],cwd=dest,check=True)
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=dest,text=True).strip()
assert head==EXPECTED
print(json.dumps({'root':str(dest),'head':head,'bundleSha256':DIGEST}))
"""
        for key,value in {'DEV':str(dev),'DEST':str(root),'BUNDLE':str(upload),'DIGEST':digest,'BRANCH':args.branch,'ORIGIN':args.origin,'EXPECTED':args.commit}.items():
            code=code.replace(key,repr(value))
        # Exactly one remote import dispatch. The existing SSH envelope marks uncertain outcomes; no retry.
        importer = Router([CandidateImportWorker(args.alias, str(dev), code)]).select('linux-handoff')
        imported = run_operation(machine, ledger, importer, Operation('Fresh candidate import', ('candidate-import',), str(dev), timeout=90, category='owned-development'), cancel)
        ledger.record(task,'CANDIDATE_IMPORT','Fresh development clone',result=asdict(imported))
        if imported.outcome != Outcome.SUCCESS: raise ExecutionFailure('Candidate import '+imported.outcome.value+'; inspect recorded destination before any retry')
        (run/'candidate.json').write_text(json.dumps({'root':str(root),'head':args.commit,'bundleSha256':digest,'upload':str(upload)},indent=2))
        guard(machine, ledger, worker, repository, args.commit, cancel)
        machine.transition(TaskState.TESTING, 'Capability-routed Linux tests on exact source commit')
        commands=[('core',('dotnet','run','--project','HostsGuardian.RegressionTests')),
                  ('monitor',('xvfb-run','-a','python3','-m','unittest','discover','-s','linux-monitor') if args.gtk else ('python3','-m','unittest','discover','-s','linux-monitor')),
                  ('orchestrator',('python3','development/orchestrator/run-tests.py'))]
        if args.prepare_deployment: commands.append(('package',('python3','development/roadmap/build-candidate.py')))
        for label,argv in commands:
            result=run_operation(machine,ledger,worker,Operation(label,argv,str(root),timeout=300,category='owned-development'),cancel)
            (run/(label+'.log')).write_text(result.stdout+'\n'+result.stderr,encoding='utf-8')
        machine.transition(TaskState.VERIFYING, 'Candidate and clean original Linux base preserved')
        guard(machine,ledger,worker,repository,args.commit,cancel)
        guard(machine,ledger,base_worker,base_repository,args.base,cancel)
        machine.transition(TaskState.COMPLETE,'Same-source Linux regression and repository preservation verified')
    except (ExecutionFailure,ValueError,OSError) as exc:
        task.blocker=str(exc); machine.transition(TaskState.FAILED,str(exc))
    (run/'summary.json').write_text(json.dumps(task.snapshot(),indent=2),encoding='utf-8')
    (run/'SHA256SUMS.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in run.iterdir() if p.is_file()},indent=2),encoding='utf-8')
    print(f'{task.state.value}; evidence={run}; candidate={root}')
    return 0 if task.state==TaskState.COMPLETE else 1


if __name__=='__main__': raise SystemExit(main())
