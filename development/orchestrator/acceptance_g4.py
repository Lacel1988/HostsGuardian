"""Independent G4 CLI acceptance: own fixtures, real guards and revalidation."""
import contextlib
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from orchestrator import managed
from orchestrator.budget import ExecutionBudget
from orchestrator.governance import (Authorization, ManagedDevelopmentWorker, Profile,
                                     operation_identity, profile_identity, source_identity)
from orchestrator.ledger import Ledger
from orchestrator.model import Operation, Outcome, Result


class G4Acceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hg-g4-acceptance-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repository'
        self.repo.mkdir()
        self.git('init', '-b', 'master', root=self.repo)
        self.git('config', 'user.name', 'G4 Fixture', root=self.repo)
        self.git('config', 'user.email', 'g4@example.invalid', root=self.repo)
        (self.repo / 'owned').mkdir()
        (self.repo / 'owned/source.txt').write_text('original')
        (self.repo / 'outside.txt').write_text('preserve')
        self.git('add', '.', root=self.repo)
        self.git('commit', '-m', 'temporary fixture', root=self.repo)
        self.git('remote', 'add', 'origin', 'https://example.invalid/never-contacted', root=self.repo)
        self.head = self.git('rev-parse', 'HEAD', root=self.repo)
        self.root = self.base / 'linked'
        self.git('worktree', 'add', '-b', 'dev/g4', str(self.root), self.head, root=self.repo)
        self.evidence = self.base / 'evidence'
        self.original_execute = ManagedDevelopmentWorker.execute

    def git(self, *args, root=None):
        return subprocess.check_output(['git', '--no-optional-locks', *args], cwd=root or self.root,
                                       text=True, stderr=subprocess.DEVNULL).strip()

    def inputs(self, diff=False):
        profile = Profile('reviewed', 'g1-g2-v1', str(self.root), 'dev/g4', self.head,
                          (('owned', ('owned',)),), ('edit', 'diff-check'))
        edits = self.base / 'edits.json'
        edits.write_text(json.dumps([{'path': 'owned/source.txt',
            'before_sha256': hashlib.sha256(b'original').hexdigest(), 'content': 'reviewed'}]))
        op = Operation('reviewed', ('git', '--no-optional-locks', 'diff', '--check') if diff else
                       ('owned-edits', str(edits)), str(self.root), category='owned-development')
        auth = Authorization('review-1', profile_identity(profile), source_identity(self.root),
                             operation_identity(op), () if diff else ('owned',), ('review:1',))
        value = asdict(profile)
        value['components'] = dict(value['components'])
        value['requirements'] = dict(value['requirements'])
        for name, obj in [('profile', value), ('request', asdict(op)), ('authorization', asdict(auth)),
                          ('budget', {'total_timeout_seconds': 60, 'max_attempts': 3, 'retry_transient': True})]:
            (self.base / (name + '.json')).write_text(json.dumps(obj))
        args = ['--plain', '--artifacts', str(self.evidence)]
        for name in ('profile', 'request', 'authorization', 'budget'):
            args += ['--' + name, str(self.base / (name + '.json'))]
        return args

    def invoke(self, args):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = managed.main(args)
        return code, output.getvalue()

    def assert_blocked(self, args):
        code, output = self.invoke(args)
        self.assertEqual(code, 1, output)
        summary = json.loads((self.evidence / 'summary.json').read_text())
        self.assertEqual(summary['dispatch_decision']['status'], 'BLOCK')
        self.assertEqual(summary['completion'], 'FAILED')
        events = Ledger.read(self.evidence / 'events.jsonl')
        self.assertEqual(sum(x['event'] == 'G3_ATTEMPT' for x in events), 1)
        self.assertFalse(any(x['event'] == 'G4_REVALIDATION' for x in events))

    def altered(self, action):
        original = self.original_execute
        def execute(worker, *args):
            result = original(worker, *args)
            action(worker)
            return result
        return patch.object(ManagedDevelopmentWorker, 'execute', execute)

    def test_valid_edit_has_actual_postcondition_and_recorded_g4_evidence(self):
        (self.root / 'outside.txt').write_text('existing dirty work')
        args = self.inputs()
        code, output = self.invoke(args)
        self.assertEqual(code, 0, output)
        summary = json.loads((self.evidence / 'summary.json').read_text())
        self.assertEqual(summary['revalidation']['status'], 'PASS')
        self.assertEqual(summary['revalidation']['policy_ids'], ['G4'])
        self.assertTrue(summary['revalidation']['evidence_refs'])
        self.assertEqual(summary['acceptance']['status'], 'NOT_EVALUATED')
        self.assertEqual(summary['acceptance']['policy_ids'], ['G6'])
        self.assertEqual((self.root / 'owned/source.txt').read_text(), 'reviewed')
        self.assertEqual((self.root / 'outside.txt').read_text(), 'existing dirty work')
        self.assertTrue(any(x['event'] == 'G4_REVALIDATION' for x in Ledger.read(self.evidence / 'events.jsonl')))

    def test_fake_edit_success_is_blocked(self):
        args = self.inputs()
        with patch.object(ManagedDevelopmentWorker, 'execute', return_value=Result(Outcome.SUCCESS, 0, dispatched=True)):
            self.assert_blocked(args)

    def test_wrong_postimage_is_blocked_and_not_repaired(self):
        args = self.inputs()
        with self.altered(lambda _: (self.root / 'owned/source.txt').write_text('wrong')):
            self.assert_blocked(args)
        self.assertEqual((self.root / 'owned/source.txt').read_text(), 'wrong')

    def test_unauthorized_file_change_is_blocked(self):
        args = self.inputs()
        with self.altered(lambda _: (self.root / 'outside.txt').write_text('unapproved')):
            self.assert_blocked(args)

    def test_changed_branch_is_blocked(self):
        args = self.inputs()
        with self.altered(lambda _: self.git('switch', '-c', 'dev/changed')):
            self.assert_blocked(args)

    def test_actual_diff_check_is_revalidated(self):
        code, output = self.invoke(self.inputs(diff=True))
        self.assertEqual(code, 0, output)
        self.assertEqual(json.loads((self.evidence / 'summary.json').read_text())['revalidation']['status'], 'PASS')

    def test_fake_diff_check_success_is_blocked(self):
        args = self.inputs(diff=True)
        with patch.object(ManagedDevelopmentWorker, 'execute', return_value=Result(Outcome.SUCCESS, 0, dispatched=True)):
            self.assert_blocked(args)

    def test_actual_failed_diff_check_is_blocked(self):
        (self.root / 'owned/source.txt').write_text('trailing whitespace \n')
        self.assert_blocked(self.inputs(diff=True))

    def test_source_changed_after_actual_diff_check_is_blocked(self):
        args = self.inputs(diff=True)
        with self.altered(lambda _: (self.root / 'outside.txt').write_text('concurrent')):
            self.assert_blocked(args)

    def test_expired_deadline_during_revalidation_is_blocked(self):
        args = self.inputs()
        now = [0.0]
        budget = ExecutionBudget(1, clock=lambda: now[0])
        original = ManagedDevelopmentWorker._revalidate
        def expired(worker, *a):
            now[0] = 1
            return original(worker, *a)
        with (patch('orchestrator.managed.ExecutionBudget.load', return_value=budget),
              patch.object(ManagedDevelopmentWorker, '_revalidate', expired)):
            self.assert_blocked(args)

    def test_cancellation_during_revalidation_is_blocked(self):
        args = self.inputs()
        original = ManagedDevelopmentWorker._revalidate
        def cancelled(worker, *a):
            worker.budget.cancel.set()
            return original(worker, *a)
        with patch.object(ManagedDevelopmentWorker, '_revalidate', cancelled):
            self.assert_blocked(args)

    def test_revalidation_evidence_storage_failure_is_blocked(self):
        args = self.inputs()
        original = Ledger.record
        def record(ledger, task, kind, *a, **kw):
            if kind == 'G4_REVALIDATION':
                raise OSError('synthetic evidence failure')
            return original(ledger, task, kind, *a, **kw)
        with patch.object(Ledger, 'record', record):
            self.assert_blocked(args)


if __name__ == '__main__':
    unittest.main(verbosity=2)
