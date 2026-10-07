import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from orchestrator.model import Task, TaskState, StateMachine, Operation, Outcome, Result, WorkerState
from orchestrator.ledger import Ledger
from orchestrator.workers import Worker, Router, run_process, retry_preflight, remote_result, SshLinuxWorker, requires_approval
from orchestrator.recipe import guard, ExecutionFailure, run_operation, same_commit, validate_config
from orchestrator.snapshot import PROBES


class FakeWorker(Worker):
    def __init__(self, responses):
        super().__init__('fixture', ['git'])
        self.responses = responses
        self.calls = []

    def execute(self, operation, cancel, notify):
        self.calls.append(operation.argv[2:])
        if operation.argv == ('repository-snapshot',):
            return Result(Outcome.SUCCESS,0,json.dumps({name:self.responses[args] for name,args in PROBES.items()}),dispatched=True)
        return Result(Outcome.SUCCESS, 0, self.responses[operation.argv[2:]], dispatched=True)


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = Ledger(self.root/'events.jsonl')
        self.task = Task('test', 'fixture', ['git'])
        self.machine = StateMachine(self.task, self.ledger)
        self.cancel = threading.Event()

    def running(self):
        self.machine.transition(TaskState.QUEUED, 'queue')
        self.machine.transition(TaskState.RUNNING, 'start')

    def test_valid_transitions_and_terminal_immutability(self):
        self.running()
        self.machine.transition(TaskState.TESTING, 'tests')
        self.machine.transition(TaskState.VERIFYING, 'verify')
        self.machine.transition(TaskState.COMPLETE, 'done')
        self.assertIsNotNone(self.task.started)
        self.assertIsNotNone(self.task.ended)
        with self.assertRaises(ValueError):
            self.machine.transition(TaskState.RUNNING, 'invalid')
        with self.assertRaises(AttributeError):
            self.task.state = TaskState.RUNNING

    def test_invalid_transition_is_recorded(self):
        with self.assertRaises(ValueError):
            self.machine.transition(TaskState.COMPLETE, 'shortcut')
        self.assertEqual(self.task.state, TaskState.PLANNING)
        self.assertEqual(Ledger.read(self.ledger.path)[-1]['event'], 'INVALID_TRANSITION')

    def test_durable_recovery_after_process_restart(self):
        self.running()
        command = [sys.executable, '-m', 'orchestrator', '--show-ledger', str(self.ledger.path)]
        value = json.loads(subprocess.check_output(command, text=True))
        self.assertEqual(value['state'], 'RUNNING')
        new = Ledger(self.ledger.path)
        new.record(self.task, 'RECOVERY_INSPECTION', 'not replayed')
        self.assertEqual(Ledger.read(new.path)[-1]['sequence'], 4)

    def test_corrupt_ledger_fails_closed(self):
        with self.ledger.path.open('a') as stream:
            stream.write('{torn')
        with self.assertRaises(json.JSONDecodeError):
            Ledger(self.ledger.path)

    def test_local_success_and_failed_exit_mapping(self):
        ok = run_process([sys.executable, '-c', 'print("ok")'], self.root, 5, self.cancel)
        failed = run_process([sys.executable, '-c', 'import sys;print("bad",file=sys.stderr);sys.exit(7)'], self.root, 5, self.cancel)
        self.assertEqual((ok.outcome, ok.stdout.strip(), ok.exit_code), (Outcome.SUCCESS, 'ok', 0))
        self.assertEqual((failed.outcome, failed.exit_code, failed.stderr.strip()), (Outcome.FAILED, 7, 'bad'))

    def test_timeout(self):
        result = run_process([sys.executable, '-c', 'import time;time.sleep(5)'], self.root, .15, self.cancel)
        self.assertEqual(result.outcome, Outcome.TIMED_OUT)
        self.assertLess(result.elapsed, 3)

    def test_cancellation(self):
        self.cancel.set()
        result = run_process([sys.executable, '-c', 'import time;time.sleep(5)'], self.root, 5, self.cancel)
        self.assertEqual(result.outcome, Outcome.CANCELLED)

    def test_cancellation_during_execution(self):
        timer=threading.Timer(.15,self.cancel.set)
        timer.start()
        self.addCleanup(timer.cancel)
        result=run_process([sys.executable,'-c','import time;time.sleep(5)'],self.root,5,self.cancel)
        self.assertEqual(result.outcome,Outcome.CANCELLED)
        self.assertTrue(result.dispatched)

    def test_launch_failure(self):
        result = run_process(['nonexistent-orch-fixture-executable'], self.root, 5, self.cancel)
        self.assertEqual(result.outcome, Outcome.FAILED)
        self.assertFalse(result.dispatched)

    def test_routing(self):
        worker = FakeWorker({})
        self.assertIs(Router([worker]).select('git'), worker)
        with self.assertRaises(ValueError):
            Router([worker]).select('deployment')
        with self.assertRaises(ValueError):
            Router([worker, worker]).select('git')

    def test_human_gate_never_dispatches(self):
        self.running()
        worker = FakeWorker({})
        operation = Operation('service control', ('systemctl', 'stop', 'fixture'), str(self.root), category='service-control')
        self.assertIsNone(run_operation(self.machine, self.ledger, worker, operation, self.cancel))
        self.assertEqual(self.task.state, TaskState.WAITING_FOR_HUMAN)
        self.assertEqual(worker.state, WorkerState.WAITING_FOR_HUMAN)
        self.assertEqual(worker.calls, [])

    def test_read_label_cannot_bypass_approval(self):
        self.assertTrue(requires_approval(Operation('hidden install', ('sudo', 'apt', 'install', 'x'), '/tmp')))
        self.assertTrue(requires_approval(Operation('hidden force', ('git', '--no-optional-locks', 'push', '--force'), '/tmp')))

    def fixture(self, change=None):
        values = {('rev-parse','--is-inside-work-tree'):'true', ('rev-parse','--show-toplevel'):str(self.root),
                  ('remote','get-url','origin'):'https://example.test/project.git', ('branch','--show-current'):'master',
                  ('rev-parse','HEAD'):'a'*40, ('status','--porcelain=v1','--untracked-files=all'):''}
        if change:
            values.update(change)
        return FakeWorker(values), {'root':str(self.root),'origin':'https://example.test/project.git','branch':'master','platform':'windows'}

    def test_repository_guard_and_mismatches(self):
        self.running()
        worker, repo = self.fixture()
        self.assertEqual(guard(self.machine, self.ledger, worker, repo, 'a'*40, self.cancel), 'a'*40)
        for key, value in [(('rev-parse','--is-inside-work-tree'),'false'),
                           (('rev-parse','--show-toplevel'),str(self.root/'stale')),
                           (('remote','get-url','origin'),'wrong'),
                           (('branch','--show-current'),'wrong'),
                           (('rev-parse','HEAD'),'b'*40),
                           (('status','--porcelain=v1','--untracked-files=all'),' M source')]:
            worker, repo = self.fixture({key:value})
            with self.assertRaises(ExecutionFailure):
                guard(self.machine, self.ledger, worker, repo, 'a'*40, self.cancel)
            self.assertEqual(len(worker.calls),1)  # no further operation after guard failure

    def test_retry_policy(self):
        self.assertTrue(retry_preflight(Result(Outcome.FAILED, 255, stderr='Connection timed out')))
        self.assertTrue(retry_preflight(Result(Outcome.FAILED, 255, stderr='Connection to fixture port 22 timed out')))
        self.assertFalse(retry_preflight(Result(Outcome.FAILED, 255, stderr='REMOTE HOST IDENTIFICATION HAS CHANGED')))
        self.assertFalse(retry_preflight(Result(Outcome.FAILED, 255, stderr='Permission denied')))
        self.assertFalse(retry_preflight(Result(Outcome.TIMED_OUT, -1)))

    def test_remote_result_mapping(self):
        for result in [Result(Outcome.FAILED,255,'START\npartial'), Result(Outcome.TIMED_OUT,-1), Result(Outcome.CANCELLED,-1), Result(Outcome.SUCCESS,0,'unframed')]:
            self.assertEqual(remote_result(result,'START','END').outcome, Outcome.UNCERTAIN)
        completed = remote_result(Result(Outcome.FAILED,7,'START\nbad\nEND'),'START','END')
        self.assertEqual((completed.outcome, completed.exit_code, completed.stdout), (Outcome.FAILED,7,'bad'))
        ok = remote_result(Result(Outcome.SUCCESS,0,'START\nsha\nEND'),'START','END')
        self.assertEqual(ok.outcome,Outcome.SUCCESS)

    def test_ssh_retries_probe_only_and_never_uncertain_command(self):
        calls=[]
        def runner(argv,cwd,timeout,cancel,heartbeat):
            calls.append(argv[-1])
            if len(calls)==1:return Result(Outcome.FAILED,255,stderr='Connection timed out')
            if len(calls)==2:return Result(Outcome.SUCCESS,0,'ORCH_READY\n')
            return Result(Outcome.FAILED,255,stderr='Connection lost')
        worker=SshLinuxWorker('linux',['git'],'fixture',runner=runner)
        op=Operation('head',('git','--no-optional-locks','rev-parse','HEAD'),'/approved/path with space')
        result=worker.run(op,self.cancel,lambda *_:None)
        self.assertEqual(result.outcome,Outcome.UNCERTAIN)
        self.assertEqual(len(calls),3)
        self.assertIn("'/approved/path with space'",calls[-1])

    def test_probe_failure_does_not_dispatch(self):
        calls=[]
        def runner(*args):
            calls.append(args[0])
            return Result(Outcome.FAILED,255,stderr='Host key verification failed')
        worker=SshLinuxWorker('linux',['git'],'fixture',runner=runner)
        result=worker.run(Operation('head',('git','--no-optional-locks','rev-parse','HEAD'),'/approved'),self.cancel,lambda *_:None)
        self.assertEqual(len(calls),1)
        self.assertFalse(result.dispatched)
        self.assertEqual(worker.state,WorkerState.OFFLINE)

    def test_retry_exhaustion_is_bounded_before_dispatch(self):
        calls=[]
        def runner(*args):
            calls.append(args[0])
            return Result(Outcome.FAILED,255,stderr='Connection timed out')
        worker=SshLinuxWorker('linux',['git'],'fixture',runner=runner)
        result=worker.run(Operation('head',('git','--no-optional-locks','rev-parse','HEAD'),'/approved'),self.cancel,lambda *_:None)
        self.assertEqual(len(calls),2)
        self.assertFalse(result.dispatched)
        self.assertTrue(all('ORCH_READY' in c[-1] for c in calls))

    def test_remote_snapshot_dispatch_and_success(self):
        import re
        calls=[]
        def runner(argv,*args):
            command=argv[-1];calls.append(command)
            if 'ORCH_READY' in command:
                return Result(Outcome.SUCCESS,0,'ORCH_READY\n')
            start=re.search(r'ORCH_START_[a-f0-9]+',command).group()
            end=re.search(r'ORCH_END_[a-f0-9]+',command).group()
            return Result(Outcome.SUCCESS,0,start+'\n{}\n'+end+'\n')
        worker=SshLinuxWorker('linux',['git'],'fixture',runner=runner)
        result=worker.run(Operation('snapshot',('repository-snapshot',),'/approved'),self.cancel,lambda *_:None)
        self.assertEqual(result.outcome,Outcome.SUCCESS)
        self.assertEqual(result.stdout,'{}')
        self.assertIn('python3',calls[-1])

    def test_worker_exception_is_visible_uncertain_result(self):
        worker=FakeWorker({})
        result=worker.run(Operation('head',('git','--no-optional-locks','rev-parse','HEAD'),str(self.root)),self.cancel,lambda *_:None)
        self.assertEqual(result.outcome,Outcome.UNCERTAIN)
        self.assertIn('KeyError',result.reason)
        self.assertEqual(worker.state,WorkerState.ERROR)

    def test_fail_closed_workflow_reaches_failed(self):
        worker,repo=self.fixture({('rev-parse','HEAD'):'b'*40})
        repo['root']=str(self.root/'repository')
        worker.responses[('rev-parse','--show-toplevel')]=repo['root']
        repo['capability']='git'
        config={'expected_commit':'a'*40,'repositories':[repo,repo]}
        task=same_commit(config,Router([worker]),self.ledger,self.root,self.cancel)
        self.assertEqual(task.state,TaskState.FAILED)
        self.assertNotIn(('status','--porcelain=v1','--untracked-files=all'),worker.calls)
        self.assertEqual(Ledger.recover(self.ledger.path)['state'],'FAILED')

    def test_successful_workflow_and_evidence_hashes(self):
        import hashlib
        worker,repo=self.fixture()
        repo['root']=str(self.root/'repository')
        repo['capability']='git'
        worker.responses[('rev-parse','--show-toplevel')]=repo['root']
        config={'expected_commit':'a'*40,'repositories':[repo,repo]}
        task=same_commit(config,Router([worker]),self.ledger,self.root,self.cancel)
        self.assertEqual(task.state,TaskState.COMPLETE)
        hashes=json.loads((self.root/'SHA256SUMS.json').read_text())
        for filename,digest in hashes.items():
            self.assertEqual(hashlib.sha256((self.root/filename).read_bytes()).hexdigest(),digest)

    def test_artifacts_and_linux_root_validation(self):
        config={'expected_commit':'a'*40,'repositories':[
            {'platform':'windows','root':str(self.root),'origin':'test'},
            {'platform':'linux','root':'/production/repo','development_root':'/approved/dev','origin':'test'}]}
        with self.assertRaises(ValueError):
            validate_config(config,self.root/'artifacts')
        config['repositories'][0]['root']=str(self.root/'repo')
        with self.assertRaises(ValueError):
            validate_config(config,self.root/'artifacts')


if __name__=='__main__':
    unittest.main()
