"""G4 actual postconditions; unlike the G1/G3 mocks, use the real validator."""
from dataclasses import replace
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from orchestrator.budget import ExecutionBudget
from orchestrator.decisions import Decision, ExecutionFailure, Status
from orchestrator.governance import ManagedDevelopmentWorker
from orchestrator.model import Outcome, Result
from orchestrator.workers import run_process
from tests import test_governance as fixtures
from tests.test_g3 import Clock


class G4Tests(unittest.TestCase):
    setUp = fixtures.GovernanceTests.setUp
    git = fixtures.GovernanceTests.git
    edits = fixtures.GovernanceTests.edits
    auth = fixtures.GovernanceTests.auth

    def worker(self, *, diff=False):
        op = (replace(self.operation, argv=('git', '--no-optional-locks', 'diff', '--check'))
              if diff else self.operation)
        w = ManagedDevelopmentWorker('g4-real-fixture', self.profile, self.auth(() if diff else ('core',), op))
        self.clock = Clock()
        w.budget = ExecutionBudget(60, 3, True, clock=self.clock)
        w.reauthorize = Mock(side_effect=AssertionError('G4 must not retry'))
        return w, op

    def blocked(self, w, op, notify=None):
        with self.assertRaises(ExecutionFailure) as caught:
            w.run(op, self.cancel, notify or (lambda *_: None))
        self.assertEqual(caught.exception.decision.status, Status.BLOCK)
        self.assertEqual(w.budget.attempts, 1)
        self.assertIsNone(w.revalidation_decision)
        w.reauthorize.assert_not_called()
        return caught.exception.decision

    def after_execution(self, w, action):
        execute = w.execute
        def changed(*args):
            result = execute(*args)
            action()
            return result
        return patch.object(w, 'execute', side_effect=changed)

    def test_valid_edit_preserves_preexisting_dirty_and_untracked_files(self):
        (self.root / 'user.txt').write_text('preexisting dirty')
        (self.root / 'foreign.txt').write_text('preexisting untracked')
        w, op = self.worker()
        events = []
        self.assertEqual(w.run(op, self.cancel, lambda *x: events.append(x)).outcome, Outcome.SUCCESS)
        self.assertEqual((self.root / 'Core/a.txt').read_text(), 'authorized replacement')
        self.assertEqual((self.root / 'user.txt').read_text(), 'preexisting dirty')
        self.assertEqual((self.root / 'foreign.txt').read_text(), 'preexisting untracked')
        self.assertEqual(w.revalidation_decision.policy_ids, ('G4',))
        self.assertTrue(any(e[0] == 'G4_REVALIDATION' for e in events))

    def test_replacement_and_new_file_postconditions_are_derived_before_execution(self):
        import hashlib
        batch = [{'path': 'Core/a.txt', 'before_sha256': hashlib.sha256(b'user original').hexdigest(),
                  'replacements': [{'old': 'user', 'new': 'reviewed'}]},
                 {'path': 'Core/new.txt', 'before_sha256': None, 'content': 'árvíz\r\n'}]
        self.manifest.write_text(json.dumps(batch), encoding='utf-8')
        w, op = self.worker()
        w.run(op, self.cancel, lambda *_: None)
        self.assertEqual((self.root / 'Core/a.txt').read_text(), 'reviewed original')
        self.assertEqual((self.root / 'Core/new.txt').read_bytes(), 'árvíz\r\n'.encode())

    def test_fake_edit_success_without_write_is_blocked(self):
        w, op = self.worker()
        with patch.object(w, 'execute', return_value=Result(Outcome.SUCCESS, 0, dispatched=True)):
            self.blocked(w, op)
        self.assertEqual((self.root / 'Core/a.txt').read_text(), 'user original')

    def test_wrong_postimage_is_blocked_without_rollback(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: (self.root / 'Core/a.txt').write_text('wrong')):
            self.blocked(w, op)
        self.assertEqual((self.root / 'Core/a.txt').read_text(), 'wrong')

    def test_unapproved_existing_file_change_is_blocked(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: (self.root / 'user.txt').write_text('unapproved')):
            self.blocked(w, op)

    def test_unapproved_new_file_is_blocked(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: (self.root / 'extra.txt').write_text('unapproved')):
            self.blocked(w, op)

    def test_unapproved_file_deletion_is_blocked(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: (self.root / 'user.txt').unlink()):
            self.blocked(w, op)

    def test_operation_payload_change_is_blocked(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: self.manifest.write_text('[]')):
            self.blocked(w, op)

    def test_branch_change_is_blocked(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: self.git('switch', '-c', 'dev/changed')):
            self.blocked(w, op)

    def test_baseline_head_change_is_blocked(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: self.git('commit', '--allow-empty', '-m', 'fixture head change')):
            self.blocked(w, op)

    def test_workspace_change_is_blocked(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: setattr(w, 'root', self.repo)):
            self.blocked(w, op)

    def test_component_authorization_change_is_blocked(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: setattr(w, 'authorization', replace(w.authorization, components=('wpf',)))):
            self.blocked(w, op)

    def test_unapproved_staging_is_blocked(self):
        w, op = self.worker()
        with self.after_execution(w, lambda: self.git('add', 'Core/a.txt')):
            self.blocked(w, op)

    def test_actual_diff_check_passes_with_runner_observation(self):
        w, op = self.worker(diff=True)
        self.assertEqual(w.run(op, self.cancel, lambda *_: None).exit_code, 0)
        self.assertEqual(w.revalidation_decision.status, Status.PASS)
        self.assertEqual(len(w._process_receipts), 1)

    def test_fake_diff_success_has_no_trusted_observation(self):
        w, op = self.worker(diff=True)
        with patch.object(w, 'execute', return_value=Result(Outcome.SUCCESS, 0, dispatched=True)):
            self.blocked(w, op)

    def test_failed_actual_diff_check_is_terminal(self):
        (self.root / 'Core/a.txt').write_text('bad trailing whitespace \n')
        w, op = self.worker(diff=True)
        self.blocked(w, op)

    def test_source_change_after_diff_check_is_blocked(self):
        w, op = self.worker(diff=True)
        with self.after_execution(w, lambda: (self.root / 'user.txt').write_text('concurrent')):
            self.blocked(w, op)

    def test_wrong_diff_process_workspace_is_blocked(self):
        w, op = self.worker(diff=True)
        with patch.object(w, 'execute', side_effect=lambda op, cancel, notify:
                          run_process(op.argv, str(self.repo), op.timeout, cancel)):
            self.blocked(w, op)

    def test_tampered_process_result_is_blocked(self):
        w, op = self.worker(diff=True)
        execute = w.execute
        def tamper(*args):
            result = execute(*args)
            result.stdout = 'forged worker success'
            return result
        with patch.object(w, 'execute', side_effect=tamper):
            self.blocked(w, op)

    def test_deadline_expiration_during_revalidation_is_terminal(self):
        from orchestrator.governance import snapshot
        w, op = self.worker()
        def expired(root):
            if w._consumed:
                self.clock.now = 60
            return snapshot(root)
        with patch('orchestrator.governance.snapshot', side_effect=expired):
            decision = self.blocked(w, op)
        self.assertEqual(decision.reason_code, 'G3_DEADLINE')

    def test_cancellation_during_revalidation_is_terminal(self):
        from orchestrator.governance import snapshot
        w, op = self.worker()
        def cancelled(root):
            if w._consumed:
                self.cancel.set()
            return snapshot(root)
        with patch('orchestrator.governance.snapshot', side_effect=cancelled):
            decision = self.blocked(w, op)
        self.assertEqual(decision.reason_code, 'G3_CANCELLED')

    def test_unreadable_post_snapshot_is_blocked(self):
        from orchestrator.governance import snapshot
        w, op = self.worker()
        def unavailable(root):
            if w._consumed:
                raise OSError('synthetic read failure')
            return snapshot(root)
        with patch('orchestrator.governance.snapshot', side_effect=unavailable):
            self.blocked(w, op)

    def test_missing_or_malformed_revalidation_evidence_is_blocked(self):
        for value in (None, {}, Decision(Status.PASS, ('G4',), 'POSTCONDITIONS_VERIFIED',
                                         'bad evidence', 'stop', (' ',))):
            # Restore the single fixture's before-state for each independent request.
            (self.root / 'Core/a.txt').write_text('user original')
            w, op = self.worker()
            with patch.object(w, '_revalidate', return_value=value):
                self.blocked(w, op)

    def test_revalidation_evidence_storage_failure_is_blocked(self):
        w, op = self.worker()
        def notify(kind, *_):
            if kind == 'G4_REVALIDATION':
                raise OSError('synthetic ledger storage failure')
        self.blocked(w, op, notify)


if __name__ == '__main__':
    unittest.main()
