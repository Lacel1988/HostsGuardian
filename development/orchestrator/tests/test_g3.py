"""Deterministic G3 limits; all source operations target isolated fixtures."""
from dataclasses import replace
import contextlib
import errno
import io
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import Mock, patch

from orchestrator.budget import ExecutionBudget, active_budget, bounded_timeout, checkpoint
from orchestrator.decisions import ExecutionFailure, Status
from orchestrator.governance import ManagedDevelopmentWorker
from orchestrator.managed import main
from orchestrator.model import Outcome, Result, StateMachine, Task, TaskState
from orchestrator.recipe import run_operation
from orchestrator.workers import run_process
from tests import test_governance as fixtures


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class BudgetTests(unittest.TestCase):
    def test_invalid_limits_and_missing_budget(self):
        for value in ({}, None, {'total_timeout_seconds': 0}, {'total_timeout_seconds': -1},
                      {'total_timeout_seconds': float('nan')}, {'total_timeout_seconds': float('inf')},
                      {'total_timeout_seconds': 301}, {'total_timeout_seconds': True},
                      {'total_timeout_seconds': 1, 'max_attempts': True},
                      {'total_timeout_seconds': 1, 'max_attempts': 0},
                      {'total_timeout_seconds': 1, 'max_attempts': 4},
                      {'total_timeout_seconds': 1, 'max_attempts': 1.0},
                      {'total_timeout_seconds': 1, 'retry_transient': 1},
                      {'total_timeout_seconds': 1, 'extra': 0}):
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                ExecutionBudget.load(value)

    def test_defaults_boundaries_and_timeout_cap(self):
        clock = Clock()
        budget = ExecutionBudget(300, clock=clock)
        self.assertEqual(budget.max_attempts, 1)
        self.assertFalse(budget.retry_transient)
        with budget.activate():
            clock.now = 299.75
            self.assertEqual(bounded_timeout(20), .25)
            clock.now = 300
            with self.assertRaises(ExecutionFailure):
                checkpoint()
        self.assertIsNone(active_budget.get())

    def test_attempt_exhaustion_and_sticky_terminal(self):
        for limit in (1, 2, 3):
            budget = ExecutionBudget(1, max_attempts=limit, clock=Clock())
            for i in range(limit):
                budget.begin_attempt(Mock(id=str(i)))
            with self.assertRaises(ExecutionFailure) as caught:
                budget.begin_attempt(Mock(id='extra'))
            self.assertEqual(caught.exception.decision.reason_code, 'G3_ATTEMPTS')
            self.assertEqual(budget.attempts, limit)
            with self.assertRaises(ExecutionFailure):
                budget.check()

    def test_backward_or_nonfinite_clock_fails_closed(self):
        for value in (-1, float('nan'), float('inf')):
            clock = Clock()
            budget = ExecutionBudget(1, clock=clock)
            clock.now = value
            with self.assertRaises(ExecutionFailure):
                budget.check()

    def test_spawn_failure_is_retryable_only_for_eagain(self):
        for code in (errno.EAGAIN, errno.EACCES):
            with patch('orchestrator.workers.subprocess.Popen', side_effect=OSError(code, 'fixture')):
                result = run_process(('never-started',), None, 1, threading.Event())
            self.assertIs(result.dispatched, False)
            self.assertEqual(result.failure_code, 'PROCESS_START_TRANSIENT' if code == errno.EAGAIN else '')

    def test_subprocess_waits_are_capped_by_remaining_budget(self):
        clock = Clock()
        budget = ExecutionBudget(1, clock=clock)
        child = Mock(returncode=0)
        child.communicate.return_value = ('ok', '')
        def popen(*args, **kwargs):
            clock.now = .98
            return child
        with budget.activate(), patch('orchestrator.workers.subprocess.Popen', side_effect=popen):
            result = run_process(('fixture',), None, 20, threading.Event())
        self.assertLessEqual(child.communicate.call_args.kwargs['timeout'], .021)
        self.assertEqual(result.outcome, Outcome.SUCCESS)

    def test_heartbeat_exception_kills_child(self):
        import subprocess
        child = Mock(returncode=None)
        child.poll.return_value = None
        child.communicate.side_effect = subprocess.TimeoutExpired(('fixture',), .25)
        with (patch('orchestrator.workers.subprocess.Popen', return_value=child),
              self.assertRaises(OSError)):
            run_process(('fixture',), None, 20, threading.Event(),
                        Mock(side_effect=OSError('evidence unavailable')))
        child.kill.assert_called_once()


class G3WorkerTests(unittest.TestCase):
    setUp = fixtures.GovernanceTests.setUp
    git = fixtures.GovernanceTests.git
    edits = fixtures.GovernanceTests.edits
    auth = fixtures.GovernanceTests.auth

    def worker(self, *, attempts=1, retry=False, apply=False, seconds=10):
        self.clock = Clock()
        operation = replace(self.operation, argv=('git', '--no-optional-locks', 'diff', '--check'))
        worker = fixtures.FakeDispatcher(self.profile, self.auth((), operation), apply=apply)
        worker.budget = ExecutionBudget(seconds, attempts, retry, clock=self.clock)
        return worker, operation

    def stopped(self, worker, operation, code=None):
        with self.assertRaises(ExecutionFailure) as caught:
            worker.run(operation, self.cancel, lambda *_: None)
        self.assertNotEqual(worker.last_decision.status, Status.PASS)
        if code:
            self.assertEqual(caught.exception.decision.reason_code, code)
        return caught.exception.decision

    def transient(self):
        return Result(Outcome.FAILED, None, dispatched=False, failure_code='PROCESS_START_TRANSIENT')

    def test_missing_budget_does_not_dispatch(self):
        worker, op = self.worker()
        worker.budget = None
        self.stopped(worker, op, 'G3_BUDGET_REQUIRED')
        self.assertEqual(worker.calls, [])

    def test_internal_attempt_is_not_a_budgetless_entry_point(self):
        worker, op = self.worker()
        with self.assertRaises(ExecutionFailure):
            worker._run_attempt(op, self.cancel, lambda *_: None)
        with worker.budget.activate(), self.assertRaises(ExecutionFailure):
            worker._run_attempt(op, self.cancel, lambda *_: None)
        self.assertEqual(worker.calls, [])

    def test_retry_disabled_by_default(self):
        worker, op = self.worker(attempts=3)
        worker.execute = Mock(return_value=self.transient())
        self.stopped(worker, op)
        self.assertEqual(worker.execute.call_count, 1)

    def test_retry_requires_new_authorization_and_rechecks_guards(self):
        worker, op = self.worker(attempts=2, retry=True)
        worker.execute = Mock(side_effect=[self.transient(), Result(Outcome.SUCCESS, 0, dispatched=True)])
        worker.reauthorize = Mock(return_value=replace(worker.authorization, id='review-two'))
        with patch.object(worker, 'evaluate', wraps=worker.evaluate) as guard:
            result = worker.run(op, self.cancel, lambda *_: None)
        self.assertEqual(result.outcome, Outcome.SUCCESS)
        self.assertEqual(guard.call_count, 4)
        self.assertEqual(worker.budget.attempts, 2)
        worker.reauthorize.assert_called_once_with(2)

    def test_reused_authorization_stops_before_second_dispatch(self):
        worker, op = self.worker(attempts=3, retry=True)
        worker.execute = Mock(return_value=self.transient())
        worker.reauthorize = lambda _: worker.authorization
        self.stopped(worker, op, 'G3_FRESH_AUTHORIZATION')
        self.assertEqual(worker.execute.call_count, 1)

    def test_stale_source_on_retry_does_not_dispatch(self):
        worker, op = self.worker(attempts=3, retry=True)
        worker.execute = Mock(return_value=self.transient())
        def changed(_):
            (self.root / 'user.txt').write_text('foreign change')
            return replace(worker.authorization, id='review-two')
        worker.reauthorize = changed
        self.stopped(worker, op, 'STALE_AUTHORIZATION')
        self.assertEqual(worker.execute.call_count, 1)

    def test_retry_cannot_reset_total_deadline(self):
        worker, op = self.worker(attempts=3, retry=True, seconds=1)
        worker.execute = Mock(return_value=self.transient())
        def slow_authorization(_):
            self.clock.now = 1
            return replace(worker.authorization, id='review-two')
        worker.reauthorize = slow_authorization
        self.stopped(worker, op, 'G3_DEADLINE')
        self.assertEqual(worker.execute.call_count, 1)

    def test_transient_failures_exhaust_exact_attempt_limit(self):
        worker, op = self.worker(attempts=3, retry=True)
        worker.execute = Mock(return_value=self.transient())
        worker.reauthorize = lambda n: replace(worker.authorization, id='review-' + str(n))
        self.stopped(worker, op, 'G3_ATTEMPTS')
        self.assertEqual(worker.execute.call_count, 3)

    def test_cancel_or_deadline_before_dispatch(self):
        for expired in (False, True):
            self.cancel.clear()
            worker, op = self.worker(seconds=1)
            if expired:
                self.clock.now = 1
            else:
                self.cancel.set()
            self.stopped(worker, op)
            self.assertEqual(worker.calls, [])

    def test_late_success_and_cancel_during_execution_rejected(self):
        for cancel in (False, True):
            self.cancel.clear()
            worker, op = self.worker(seconds=1)
            def execute(*_):
                if cancel:
                    self.cancel.set()
                else:
                    self.clock.now = 1
                return Result(Outcome.SUCCESS, 0, dispatched=True)
            worker.execute = execute
            self.stopped(worker, op)

    def test_uncertain_partial_unknown_and_timeout_are_terminal(self):
        results = [None, Result(Outcome.UNCERTAIN, None, dispatched=None),
                   Result(Outcome.FAILED, 1, dispatched=True), Result(Outcome.TIMED_OUT, None, dispatched=True),
                   Result(Outcome.CANCELLED, None, dispatched=False), Result(Outcome.SUCCESS, 1, dispatched=True),
                   Result(Outcome.SUCCESS, 0, dispatched=None)]
        for result in results:
            worker, op = self.worker(attempts=3, retry=True)
            worker.execute = Mock(return_value=result)
            worker.reauthorize = Mock()
            self.stopped(worker, op)
            self.assertEqual(worker.execute.call_count, 1)
            worker.reauthorize.assert_not_called()

    def test_guard_denial_is_terminal(self):
        worker, op = self.worker(attempts=3, retry=True)
        worker.authorization = None
        worker.reauthorize = Mock()
        self.stopped(worker, op, 'AUTHORIZATION_MISSING')
        worker.reauthorize.assert_not_called()
        self.assertEqual(worker.calls, [])

    def test_evidence_failure_never_dispatches_or_retries(self):
        worker, op = self.worker(attempts=3, retry=True)
        with self.assertRaises(ExecutionFailure):
            worker.run(op, self.cancel, Mock(side_effect=OSError('fixture storage failed')))
        self.assertEqual(worker.last_decision.reason_code, 'G3_EVIDENCE_FAILED')
        self.assertEqual(worker.calls, [])

    def test_partial_edit_stops_before_next_file_and_does_not_retry(self):
        op = self.edits(['Core/a.txt', 'Wpf/b.txt'])
        worker = fixtures.FakeDispatcher(self.profile, self.auth(('core', 'wpf')), apply=True)
        clock = Clock()
        worker.budget = ExecutionBudget(1, 3, True, clock=clock)
        original = Path.write_bytes
        def write(path, data):
            value = original(path, data)
            if path == self.root / 'Core/a.txt':
                clock.now = 1
            return value
        with patch.object(Path, 'write_bytes', write):
            self.stopped(worker, op, 'G3_DEADLINE')
        self.assertEqual((self.root / 'Core/a.txt').read_text(), 'authorized replacement')
        self.assertEqual((self.root / 'Wpf/b.txt').read_text(), 'user original')
        self.assertEqual(len(worker.calls), 1)

    def test_recipe_evidence_failure_and_late_result_record_fail_closed(self):
        for late in (False, True):
            worker, op = self.worker(seconds=1)
            task = Task('test', 'fixture', [])
            ledger = Mock()
            machine = StateMachine(task, ledger)
            machine.transition(TaskState.QUEUED, 'fixture')
            machine.transition(TaskState.RUNNING, 'fixture')
            def record(task, kind, *a):
                if kind == 'COMMAND_RESULT':
                    if late:
                        self.clock.now = 1
                    else:
                        raise OSError('fixture disk failure')
            ledger.record.side_effect = record
            with self.assertRaises(ExecutionFailure):
                run_operation(machine, ledger, worker, op, self.cancel)
            self.assertNotEqual(worker.last_decision.status, Status.PASS)

    def test_budget_cannot_replay_success_with_a_new_worker(self):
        worker, op = self.worker(attempts=3, retry=True)
        worker.run(op, self.cancel, lambda *_: None)
        other = fixtures.FakeDispatcher(self.profile, replace(worker.authorization, id='new-id'))
        other.budget = worker.budget
        self.stopped(other, op, 'G3_FINISHED')
        self.assertEqual(other.calls, [])

    def test_edit_cannot_retry_even_a_pre_spawn_transient(self):
        worker = fixtures.FakeDispatcher(self.profile, self.auth())
        worker.budget = ExecutionBudget(10, 3, True)
        worker.execute = Mock(return_value=self.transient())
        worker.reauthorize = Mock()
        self.stopped(worker, self.operation)
        worker.execute.assert_called_once()
        worker.reauthorize.assert_not_called()

    def test_deadline_in_guard_evidence_prevents_dispatch(self):
        worker, op = self.worker(seconds=1)
        def notify(kind, *_):
            if kind == 'GOVERNANCE_DECISION':
                self.clock.now = 1
        with self.assertRaises(ExecutionFailure):
            worker.run(op, self.cancel, notify)
        self.assertEqual(worker.calls, [])

    def test_late_summary_is_replaced_by_failure_not_pass(self):
        from tests.test_managed_evidence import ManagedEvidenceTests
        destination = self.base / 'late-evidence'
        args = ManagedEvidenceTests.arguments(self, destination)
        clock = Clock()
        budget = ExecutionBudget(1, clock=clock)
        original = Path.write_text
        def write(path, *a, **kw):
            result = original(path, *a, **kw)
            if path == destination / 'summary.json':
                clock.now = 1
            return result
        with (patch('orchestrator.managed.ExecutionBudget.load', return_value=budget),
              patch.object(Path, 'write_text', write), contextlib.redirect_stdout(io.StringIO()) as out):
            self.assertEqual(main(args), 1)
        self.assertNotIn('"status": "PASS"', out.getvalue())
        result = json.loads((destination / 'summary.json').read_text())
        self.assertEqual(result['dispatch_decision']['status'], 'BLOCK')
        self.assertEqual(result['completion'], 'FAILED')

    def test_initial_input_processing_consumes_total_budget(self):
        from tests.test_managed_evidence import ManagedEvidenceTests
        from orchestrator import managed
        destination = self.base / 'late-input'
        args = ManagedEvidenceTests.arguments(self, destination)
        clock = Clock()
        budget = ExecutionBudget(1, clock=clock)
        original = managed.read_json
        def read(path):
            result = original(path)
            if path == self.base / 'profile.json':
                clock.now = 1
            return result
        with (patch('orchestrator.managed.ExecutionBudget.load', return_value=budget),
              patch('orchestrator.managed.read_json', side_effect=read),
              contextlib.redirect_stdout(io.StringIO()) as out):
            self.assertEqual(main(args), 1)
        self.assertIn('G3_DEADLINE', out.getvalue())
        self.assertFalse(destination.exists())

    def test_slow_output_cannot_return_success_after_deadline(self):
        from tests.test_managed_evidence import ManagedEvidenceTests
        destination = self.base / 'slow-output'
        args = ManagedEvidenceTests.arguments(self, destination)
        clock = Clock()
        budget = ExecutionBudget(1, clock=clock)
        class SlowOutput(io.StringIO):
            def write(self, text):
                if 'COMPLETE' in text:
                    clock.now = 1
                return super().write(text)
        with (patch('orchestrator.managed.ExecutionBudget.load', return_value=budget),
              contextlib.redirect_stdout(SlowOutput()) as out):
            self.assertEqual(main(args), 1)
        self.assertTrue(out.getvalue().splitlines()[-1].startswith('BLOCK'))
        self.assertEqual(json.loads((destination / 'summary.json').read_text())['completion'], 'FAILED')


if __name__ == '__main__':
    unittest.main()
