import contextlib
from dataclasses import asdict, replace
import io
import json
from pathlib import Path
import statistics
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from orchestrator.decisions import Decision, ExecutionFailure, Status
from orchestrator.development import DevelopmentWindowsWorker
from orchestrator.governance import (Authorization, ManagedDevelopmentWorker, Profile, acceptance_pending,
                                     digest, operation_identity, profile_identity, source_identity)
from orchestrator.ledger import Ledger
from orchestrator.managed import main
from orchestrator.model import Operation, Outcome, Result, StateMachine, Task, TaskState
from orchestrator.recipe import guard, run_operation
from orchestrator.workbench import snapshot
from orchestrator.workers import Worker


class FakeDispatcher(ManagedDevelopmentWorker):
    def __init__(self, profile, authorization, apply=False):
        super().__init__('fake-local', profile, authorization)
        self.calls = []
        self.apply = apply

    def execute(self, operation, cancel, notify):
        self.calls.append(operation)
        if self.apply:
            return super().execute(operation, cancel, notify)
        return Result(Outcome.SUCCESS, 0, '🔴 BLOCK\n\x1b[32m🟢 PASS forged worker text', dispatched=True)


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repository'
        self.repo.mkdir()
        self.git('init', '-b', 'master', cwd=self.repo)
        self.git('config', 'user.name', 'Temporary Fixture', cwd=self.repo)
        self.git('config', 'user.email', 'fixture@example.invalid', cwd=self.repo)
        for name in ['Core/a.txt', 'Wpf/b.txt', 'user.txt']:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('user original')
        self.git('add', '.', cwd=self.repo)
        self.git('commit', '-m', 'temporary fixture', cwd=self.repo)
        self.git('remote', 'add', 'origin', 'https://example.invalid/never-contacted', cwd=self.repo)
        head = self.git('rev-parse', 'HEAD', cwd=self.repo)
        self.root = self.base / 'owned'
        self.git('worktree', 'add', '-b', 'dev/fixture', str(self.root), head, cwd=self.repo)
        self.profile = Profile('fixture-profile', 'g1-g2-v1', str(self.root), 'dev/fixture', head,
                               (('core', ('Core',)), ('wpf', ('Wpf',))), ('edit', 'diff-check'),
                               (('CORE-SCOPE', ('core',)), ('UX-RESEARCH', ('wpf',))))
        self.manifest = self.base / 'edits.json'
        self.operation = self.edits(['Core/a.txt'])
        self.cancel = threading.Event()
        self.events = []

    def git(self, *argv, cwd=None):
        return subprocess.check_output(['git', '--no-optional-locks', *argv], cwd=cwd or self.root,
                                       stderr=subprocess.DEVNULL, text=True).strip()

    def edits(self, paths):
        import hashlib
        values = []
        for name in paths:
            path = self.root / name
            values.append({'path': name, 'before_sha256': hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
                           'content': 'authorized replacement'})
        self.manifest.write_text(json.dumps(values), encoding='utf-8')
        return Operation('Reviewed edit', ('owned-edits', str(self.manifest)), str(self.root), category='owned-development')

    def auth(self, components=('core',), operation=None, profile=None):
        profile = profile or self.profile
        return Authorization('operator-review-1', profile_identity(profile), source_identity(profile.root),
                             operation_identity(operation or self.operation), components, ('review:fixture-1',))

    def notify(self, *items):
        self.events.append(items)

    def deny(self, worker, operation=None, status=Status.BLOCK):
        def files():
            return {name: (self.root / name).read_bytes() for name in ['Core/a.txt', 'Wpf/b.txt', 'user.txt']}
        before = files()
        git_status = self.git('status', '--porcelain=v1', '--untracked-files=all')
        with self.assertRaises(ExecutionFailure) as caught:
            worker.run(operation or self.operation, self.cancel, self.notify)
        self.assertEqual(caught.exception.decision.status, status)
        self.assertEqual(worker.calls, [])
        self.assertEqual(files(), before)
        self.assertEqual(self.git('status', '--porcelain=v1', '--untracked-files=all'), git_status)
        return caught.exception.decision

    def test_unauthorized_component_zero_dispatch(self):
        self.operation = self.edits(['user.txt'])
        self.assertEqual(self.deny(FakeDispatcher(self.profile, self.auth())).reason_code, 'COMPONENT_SCOPE')

    def test_missing_and_mismatched_authorization(self):
        for auth in [None, {'status': 'PASS'}, replace(self.auth(), id=''), replace(self.auth(), profile_identity='wrong'),
                     replace(self.auth(), operation_identity='wrong'), replace(self.auth(), components=('wpf',))]:
            with self.subTest(auth=auth):
                self.deny(FakeDispatcher(self.profile, auth))

    def test_protected_and_detached_branches(self):
        auth = self.auth()
        for branch in ['main', 'Master']:
            self.git('switch', '-C', branch)
            self.deny(FakeDispatcher(replace(self.profile, branch=branch), auth))
        self.git('switch', '--detach', self.profile.baseline)
        self.deny(FakeDispatcher(self.profile, auth))

    def test_regular_repository_is_not_an_owned_worktree(self):
        profile = replace(self.profile, root=str(self.repo), branch='dev/fixture')
        self.assertEqual(self.deny(FakeDispatcher(profile, self.auth())).reason_code, 'ISOLATED_WORKTREE_REQUIRED')

    def test_path_traversal_git_metadata_and_windows_aliases(self):
        for path in ['../outside.txt', '/absolute.txt', 'Core/../user.txt', 'Core\\a.txt', '.GiT/config',
                     'Core/a.txt:stream', 'Core/a.txt.', 'Core//a.txt', 'Core/NUL.txt', 'Core/SHORT~1.txt', 'Core/a?.txt']:
            with self.subTest(path=path):
                self.manifest.write_text(json.dumps([{'path': path, 'before_sha256': None, 'content': 'bad'}]))
                self.deny(FakeDispatcher(self.profile, self.auth()))

    def test_symlink_escape(self):
        auth = self.auth()
        outside = self.base / 'outside'
        outside.mkdir()
        target = self.root / 'Core' / 'link'
        try:
            target.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('Host does not permit unprivileged symlinks; junction test covers Windows reparse escape')
        self.operation = self.edits(['Core/link/evil.txt'])
        self.deny(FakeDispatcher(self.profile, replace(auth, operation_identity=operation_identity(self.operation))))
        self.assertFalse((outside / 'evil.txt').exists())

    @unittest.skipUnless(__import__('os').name == 'nt', 'Windows junction fixture')
    def test_junction_escape(self):
        auth = self.auth()
        outside = self.base / 'outside'
        outside.mkdir()
        junction = self.root / 'Core' / 'junction'
        # Fixed fixture paths; no user paths or destructive shell commands.
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(outside)], check=True, capture_output=True)
        self.addCleanup(lambda: junction.rmdir() if junction.exists() else None)
        self.operation = self.edits(['Core/junction/evil.txt'])
        self.deny(FakeDispatcher(self.profile, replace(auth, operation_identity=operation_identity(self.operation))))
        self.assertFalse((outside / 'evil.txt').exists())

    def test_legitimate_edit_and_user_file_preservation(self):
        worker = FakeDispatcher(self.profile, self.auth(), apply=True)
        state = snapshot(self.root)
        with patch('orchestrator.governance.snapshot', return_value=state), patch('subprocess.Popen', side_effect=AssertionError('No process effects')):
            result = worker.run(self.operation, self.cancel, self.notify)
        self.assertEqual(result.outcome, Outcome.SUCCESS)
        self.assertEqual(len(worker.calls), 1)
        self.assertEqual((self.root / 'Core/a.txt').read_text(), 'authorized replacement')
        self.assertEqual((self.root / 'Wpf/b.txt').read_text(), 'user original')
        self.assertEqual((self.root / 'user.txt').read_text(), 'user original')
        self.assertEqual((self.repo / 'Core/a.txt').read_text(), 'user original')

    def test_hardlinked_target_cannot_modify_external_user_file(self):
        import os
        outside = self.base / 'user-owned.txt'
        outside.write_text('preserve external user file')
        os.link(outside, self.root / 'Core/hardlink.txt')
        self.operation = self.edits(['Core/hardlink.txt'])
        self.deny(FakeDispatcher(self.profile, self.auth()))
        self.assertEqual(outside.read_text(), 'preserve external user file')

    def test_duplicate_and_nested_repository_targets(self):
        self.operation = self.edits(['Core/a.txt', 'Core/a.txt'])
        self.deny(FakeDispatcher(self.profile, self.auth()))
        nested = self.root / 'Core/nested'
        nested.mkdir()
        self.git('init', cwd=nested)
        self.operation = self.edits(['Core/nested/new.txt'])
        self.deny(FakeDispatcher(self.profile, self.auth()))

    def test_dispatch_runs_only_read_only_local_git_probes(self):
        worker = FakeDispatcher(self.profile, self.auth())
        original = subprocess.Popen
        calls = []
        def local_only(argv, *args, **kwargs):
            calls.append(tuple(argv))
            self.assertEqual(tuple(argv[:2]), ('git', '--no-optional-locks'))
            self.assertIn(tuple(argv[2:]), {
                ('branch', '--show-current'), ('rev-parse', 'HEAD'), ('remote', 'get-url', 'origin'),
                ('status', '--porcelain=v1', '--untracked-files=all'),
                ('ls-files', '-z', '--cached', '--others', '--exclude-standard')})
            self.assertEqual(Path(kwargs['cwd']), self.root)
            return original(argv, *args, **kwargs)
        with patch('subprocess.Popen', side_effect=local_only):
            worker.run(self.operation, self.cancel, self.notify)
        self.assertEqual(len(worker.calls), 1)
        self.assertEqual(len(calls), 10)  # two five-command snapshots, no transport or product process

    def test_cross_component_requires_explicit_authorization(self):
        self.operation = self.edits(['Core/a.txt', 'Wpf/b.txt'])
        self.deny(FakeDispatcher(self.profile, self.auth()))
        worker = FakeDispatcher(self.profile, self.auth(('core', 'wpf')), apply=True)
        worker.run(self.operation, self.cancel, self.notify)
        self.assertEqual(len(worker.calls), 1)
        for name in ['Core/a.txt', 'Wpf/b.txt']:
            self.assertEqual((self.root / name).read_text(), 'authorized replacement')

    def test_missing_evidence_revise_never_dispatches_or_accepts(self):
        self.deny(FakeDispatcher(self.profile, replace(self.auth(), evidence_refs=())), status=Status.REVISE)
        self.assertEqual(acceptance_pending().status, Status.NOT_EVALUATED)

    def test_stale_source_and_policy(self):
        auth = self.auth()
        (self.root / 'user.txt').write_text('external change')
        self.deny(FakeDispatcher(self.profile, auth))
        self.deny(FakeDispatcher(replace(self.profile, version='g1-g2-v2'), self.auth()))

    def test_stale_head(self):
        auth = self.auth()
        self.git('commit', '--allow-empty', '-m', 'changed fixture HEAD')
        self.deny(FakeDispatcher(self.profile, auth))

    def test_failed_or_timed_out_source_probe_blocks_dispatch(self):
        worker = FakeDispatcher(self.profile, self.auth())
        for error in [subprocess.CalledProcessError(1, ['git']), subprocess.TimeoutExpired(['git'], 20)]:
            with patch('orchestrator.governance.snapshot', side_effect=error):
                self.deny(worker)

    def test_payload_change_and_before_hash_mismatch(self):
        auth = self.auth()
        self.manifest.write_text('[{"path":"Core/new.txt","before_sha256":null,"content":"injected"}]')
        self.deny(FakeDispatcher(self.profile, auth))
        self.manifest.write_text('[{"path":"Core/a.txt","before_sha256":null,"content":"bad"}]')
        self.assertEqual(self.deny(FakeDispatcher(self.profile, self.auth())).reason_code, 'EDIT_HASH_MISMATCH')

    def test_reused_decision_does_not_authorize_second_dispatch(self):
        worker = FakeDispatcher(self.profile, self.auth())
        worker.run(self.operation, self.cancel, self.notify)
        with self.assertRaises(ExecutionFailure) as caught:
            worker.run(self.operation, self.cancel, self.notify)
        self.assertEqual(caught.exception.decision.reason_code, 'AUTHORIZATION_CONSUMED')
        self.assertEqual(len(worker.calls), 1)

    def test_changes_between_evaluation_and_dispatch_block(self):
        worker = FakeDispatcher(self.profile, self.auth())
        def notify(*items):
            self.manifest.write_text('[]')
        with self.assertRaises(ExecutionFailure):
            worker.run(self.operation, self.cancel, notify)
        self.assertEqual(worker.calls, [])

    def test_unknown_external_and_historical_commands(self):
        for argv in [('dotnet', 'build', 'HostsGuardian.sln'), ('systemctl', 'stop', 'dns'), ('git', 'push'), ('ssh', 'host'), ('unknown',)]:
            operation = replace(self.operation, argv=argv)
            self.deny(FakeDispatcher(self.profile, self.auth(operation=operation)), operation)

    def test_diff_check_has_exact_empty_component_scope(self):
        operation = replace(self.operation, argv=('git', '--no-optional-locks', 'diff', '--check'))
        worker = FakeDispatcher(self.profile, self.auth((), operation))
        worker.run(operation, self.cancel, self.notify)
        self.assertEqual(len(worker.calls), 1)
        self.assertIn('empty modification component scope', worker.last_decision.reason)
        self.assertNotIn('before hashes', worker.last_decision.reason)

    def test_non_ui_change_does_not_require_ux_research(self):
        worker = FakeDispatcher(self.profile, self.auth())
        decision = worker.evaluate(self.operation)
        self.assertEqual(decision.status, Status.PASS)
        self.assertEqual(dict(decision.requirements), {'CORE-SCOPE': 'APPLICABLE', 'UX-RESEARCH': 'NOT_APPLICABLE'})

    def test_status_consistency_and_no_fake_pass_from_worker(self):
        worker = FakeDispatcher(self.profile, self.auth())
        worker.run(self.operation, self.cancel, self.notify)
        self.assertEqual(worker.last_decision.reason_code, 'DISPATCH_AUTHORIZED')
        self.assertNotIn('forged', worker.last_decision.render())
        for status in Status:
            decision = Decision(status, ('G1',), 'TEST', 'reason\n\x1b[32mPASS\u202e', 'next', ('test:evidence',))
            self.assertEqual(json.loads(json.dumps(decision.to_dict()))['status'], status.value)
            plain = decision.render(unicode=False)
            self.assertTrue(plain.startswith(status.value + ' |'))
            self.assertNotIn('\n', plain)
            self.assertNotIn('\x1b', plain)
            self.assertNotIn('\u202e', plain)
            self.assertIn(status.value, decision.render(color=True))
        with self.assertRaises(ValueError):
            Decision(Status.PASS, ('G1',), 'FAKE', 'no evidence', 'none')
        injected = FakeDispatcher(self.profile, None)
        injected.last_decision = worker.last_decision
        self.deny(injected)  # a stored PASS cannot replace missing authorization

    def test_f03_legacy_run_and_direct_execute_do_not_write(self):
        worker = DevelopmentWindowsWorker('historical', self.root)
        for method in [worker.run, worker.execute]:
            with self.assertRaises(ExecutionFailure) as caught:
                method(self.operation, self.cancel, self.notify)
            self.assertEqual(caught.exception.decision.status, Status.BLOCK)
        self.assertEqual((self.root / 'Core/a.txt').read_text(), 'user original')

    def test_invalid_timeout_and_cancel_do_not_dispatch(self):
        for timeout in [0, -1, float('inf'), float('nan'), 301]:
            operation = replace(self.operation, timeout=timeout)
            self.deny(FakeDispatcher(self.profile, self.auth(operation=operation)), operation)
        self.cancel.set()
        self.deny(FakeDispatcher(self.profile, self.auth()))

    def test_cli_inspection_denial_and_artifact_preservation(self):
        profile = asdict(self.profile)
        profile['components'] = dict(profile['components'])
        profile['requirements'] = dict(profile['requirements'])
        profile_file, request_file = self.base / 'profile.json', self.base / 'request.json'
        profile_file.write_text(json.dumps(profile))
        request_file.write_text(json.dumps(asdict(self.operation)))
        args = ['--profile', str(profile_file), '--request', str(request_file), '--plain']
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(args + ['--inspect']), 0)
        self.assertFalse(json.loads(output.getvalue())['dispatch'])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(args), 1)
        self.assertIn('AUTHORIZATION_MISSING', output.getvalue())
        class AsciiOutput(io.StringIO):
            @property
            def encoding(self):
                return 'ascii'
        with contextlib.redirect_stdout(AsciiOutput()) as output:
            self.assertEqual(main(args[:-1]), 1)  # no --plain; detect terminal encoding
        output.getvalue().encode('ascii')
        auth_file = self.base / 'authorization.json'
        auth_file.write_text(json.dumps(asdict(self.auth())))
        args += ['--authorization', str(auth_file), '--artifacts', str(self.base / 'evidence')]
        with contextlib.redirect_stdout(io.StringIO()), patch('orchestrator.managed.ManagedDevelopmentWorker', lambda identity, profile, auth: FakeDispatcher(profile, auth)):
            self.assertEqual(main(args), 0)
        summary = json.loads((self.base / 'evidence/summary.json').read_text())
        self.assertEqual(summary['dispatch_decision']['status'], 'PASS')
        self.assertEqual(summary['acceptance']['status'], 'NOT_EVALUATED')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(args), 1)  # never overwrite prior evidence
        self.assertEqual(json.loads((self.base / 'evidence/summary.json').read_text()), summary)

    def test_overhead_measurement(self):
        worker = FakeDispatcher(self.profile, self.auth())
        baseline, evaluation, dispatch = [], [], []
        for _ in range(5):
            start = time.perf_counter(); source_identity(self.root); baseline.append(time.perf_counter() - start)
            start = time.perf_counter(); decision = worker.evaluate(self.operation); evaluation.append(time.perf_counter() - start)
            self.assertEqual(decision.status, Status.PASS)
            fresh = FakeDispatcher(self.profile, worker.authorization)
            start = time.perf_counter(); fresh.run(self.operation, self.cancel, lambda *_: None); dispatch.append(time.perf_counter() - start)
        print('\nG1/G2 fixture timings (5 samples, ms): ' + json.dumps({
            'source_snapshot_median': round(statistics.median(baseline) * 1000, 3),
            'evaluation_median': round(statistics.median(evaluation) * 1000, 3),
            'guarded_fake_dispatch_median': round(statistics.median(dispatch) * 1000, 3)}))


class GuardFailureTests(unittest.TestCase):
    def test_f04_none_and_malformed_results_are_typed_auditable_stops(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger = Ledger(Path(temp) / 'events.jsonl')
            task = Task('guard', 'fixture', [])
            machine = StateMachine(task, ledger)
            machine.transition(TaskState.QUEUED, 'queue')
            machine.transition(TaskState.RUNNING, 'run')
            worker = Worker('fake', [])
            worker.run = lambda *args: None
            repo = {'root': temp, 'origin': 'fixture', 'branch': 'dev/test', 'platform': 'windows'}
            for response in [None, {}, '🟢 PASS', Result(Outcome.SUCCESS, 7), Result(Outcome.SUCCESS, 0, '{}'),
                             Result(Outcome.SUCCESS, 0, 'null'), Result(Outcome.SUCCESS, 0, 'not-json'),
                             Result(Outcome.SUCCESS, 0, '{"git":"false","git":"true"}')]:
                with self.subTest(response=response):
                    worker.run = lambda *args: response
                    with self.assertRaises(ExecutionFailure) as caught:
                        guard(machine, ledger, worker, repo, 'a' * 40, threading.Event())
                    self.assertEqual(caught.exception.decision.status, Status.BLOCK)
            # Defense even if a replacement run_operation violates its return contract.
            with patch('orchestrator.recipe.run_operation', return_value=None):
                with self.assertRaises(ExecutionFailure):
                    guard(machine, ledger, worker, repo, 'a' * 40, threading.Event())
            self.assertTrue(any(e['event'] == 'GOVERNANCE_DECISION' for e in Ledger.read(ledger.path)))


if __name__ == '__main__':
    unittest.main()
