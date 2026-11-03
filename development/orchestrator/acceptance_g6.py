"""G6/full-chain acceptance with explicit synthetic operator fixture actions.

These records test the mechanism; they do not accept any real project change.
"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import acceptance_g4 as fixtures
from orchestrator import managed
from orchestrator.budget import ExecutionBudget
from orchestrator.governance import ManagedDevelopmentWorker
from orchestrator.human_acceptance import verify_human_acceptance
from orchestrator.ledger import Ledger
from orchestrator.model import Outcome, Result


class G6Acceptance(unittest.TestCase):
    setUp = fixtures.G4Acceptance.setUp
    git = fixtures.G4Acceptance.git
    inputs = fixtures.G4Acceptance.inputs
    invoke = fixtures.G4Acceptance.invoke

    def completed(self, diff=False):
        code, output = self.invoke(self.inputs(diff=diff))
        self.assertEqual(code, 0, output)
        published = json.loads(output.splitlines()[0])
        self.anchor = published['completion_certificate']['certificate_sha256']
        self.cert = json.loads((self.evidence / 'completion.json').read_text())
        self.summary = json.loads((self.evidence / 'summary.json').read_text())
        return published

    def review(self, decision='ACCEPT', change=None, path=None):
        # Explicit test-only operator action, after the actual completion exists.
        cert = self.cert
        record = {'id': 'synthetic-post-execution-review', 'decision': decision, 'input_origin': 'operator-reviewed',
                  'policy_id': 'g6-managed-v1', 'completion_certificate_sha256': self.anchor,
                  'task_id': cert['task_id'], 'operation_identity': cert['binding']['operation_identity'],
                  'authorization_identity': cert['attempt_binding']['authorization_identity'],
                  'workspace': cert['binding']['workspace'], 'source_identity': cert['attempt_binding']['source_identity'],
                  'post_source_identity': self.summary['revalidation']['source_identity'],
                  'attempt': cert['attempt'], 'g4_identity': cert['g4_identity'],
                  'evidence_refs': ['test:synthetic-review-not-real-project-human-approval']}
        packet = {'schema': 'hg-operator-acceptance-v1', 'records': [record]}
        if change:
            change(packet)
        self.operator = path or self.base / 'operator-reviewed.json'
        self.operator.write_text(json.dumps(packet))
        self.record_hash = hashlib.sha256(self.operator.read_bytes()).hexdigest()

    def human(self):
        return verify_human_acceptance(self.evidence, self.anchor, self.operator, self.record_hash)

    def test_full_g1_g6_chain_requires_separate_post_execution_accept(self):
        published = self.completed()
        self.assertEqual(published['human_acceptance']['status'], 'PENDING')
        self.assertEqual(verify_human_acceptance(self.evidence, self.anchor)['status'], 'PENDING')
        self.review()
        report = self.human()
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['decision'], 'ACCEPT')
        self.assertEqual(Ledger.verify_managed(self.evidence, self.anchor)['status'], 'PASS')

    def test_pending_preserves_g5_technical_completion(self):
        self.completed()
        before = {p.name: p.read_bytes() for p in self.evidence.iterdir()}
        self.review('PENDING')
        self.assertEqual(self.human()['status'], 'PENDING')
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.evidence.iterdir()})

    def test_reject_blocks_without_retry_repair_or_rollback(self):
        self.completed()
        self.review('REJECT')
        self.assertEqual(self.human()['status'], 'BLOCK')
        self.assertEqual((self.root / 'owned/source.txt').read_text(), 'reviewed')

    def test_other_operation_review_is_blocked(self):
        self.completed()
        self.review(change=lambda p: p['records'][0].update(operation_identity='f' * 64))
        self.assertEqual(self.human()['status'], 'BLOCK')

    def test_other_certificate_review_is_blocked(self):
        self.completed()
        self.review(change=lambda p: p['records'][0].update(completion_certificate_sha256='f' * 64))
        self.assertEqual(self.human()['status'], 'BLOCK')

    def test_worker_written_record_is_not_operator_input(self):
        self.completed()
        self.review(path=self.root / 'worker-approval.json')
        self.assertEqual(self.human()['status'], 'BLOCK')

    def test_missing_operator_reference_cannot_be_self_approved(self):
        self.completed()
        self.review()
        self.assertEqual(verify_human_acceptance(self.evidence, self.anchor, self.operator)['status'], 'BLOCK')

    def test_corrupted_g5_blocks_even_a_bound_operator_accept(self):
        self.completed()
        self.review()
        with (self.evidence / 'events.jsonl').open('ab') as f:
            f.write(b'corrupt')
        self.assertEqual(self.human()['status'], 'BLOCK')

    def test_g1_g2_denial_cannot_be_promoted_by_human_claim(self):
        args = self.inputs()
        auth_path = self.base / 'authorization.json'
        value = json.loads(auth_path.read_text())
        value['operation_identity'] = 'wrong'
        auth_path.write_text(json.dumps(value))
        self.assertEqual(self.invoke(args)[0], 1)
        self.assertEqual(verify_human_acceptance(self.evidence, 'f' * 64)['status'], 'BLOCK')
        self.assertEqual((self.root / 'owned/source.txt').read_text(), 'original')

    def test_g4_failure_has_no_g5_certificate_to_accept(self):
        args = self.inputs()
        with patch.object(ManagedDevelopmentWorker, 'execute', return_value=Result(Outcome.SUCCESS, 0, dispatched=True)):
            self.assertEqual(self.invoke(args)[0], 1)
        self.assertFalse((self.evidence / 'completion.json').exists())
        self.assertEqual(verify_human_acceptance(self.evidence, 'f' * 64)['status'], 'BLOCK')

    def test_g5_failure_has_no_human_acceptance_bypass(self):
        args = self.inputs()
        original = Ledger.record
        def record(ledger, task, kind, *a, **kw):
            if kind != 'G4_REVALIDATION':
                return original(ledger, task, kind, *a, **kw)
        with patch.object(Ledger, 'record', record):
            self.assertEqual(self.invoke(args)[0], 1)
        self.assertEqual(verify_human_acceptance(self.evidence, 'f' * 64)['status'], 'BLOCK')

    def test_repeated_or_conflicting_operator_records_block(self):
        self.completed()
        def duplicate(packet):
            packet['records'].append({**packet['records'][0], 'decision': 'REJECT'})
        self.review(change=duplicate)
        self.assertEqual(self.human()['status'], 'BLOCK')

    def test_read_only_review_cannot_open_a_new_execution_budget(self):
        self.completed()
        self.review()
        files = list(self.evidence.iterdir()) + [self.operator, self.root / 'owned/source.txt']
        before = {p: p.read_bytes() for p in files}
        with (patch.object(ExecutionBudget, '__init__', side_effect=AssertionError('No budget')),
              patch.object(managed, 'ManagedDevelopmentWorker', side_effect=AssertionError('No worker')),
              patch('subprocess.Popen', side_effect=AssertionError('No process')),
              patch.object(Path, 'write_text', side_effect=AssertionError('No writes')),
              contextlib.redirect_stdout(io.StringIO()) as out):
            code = managed.main(['--verify-human-acceptance', str(self.evidence), '--expected-certificate', self.anchor,
                                 '--acceptance-record', str(self.operator), '--expected-acceptance', self.record_hash])
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(before, {p: p.read_bytes() for p in files})

    def test_read_only_diff_check_has_no_artificial_human_gate(self):
        published = self.completed(diff=True)
        self.assertFalse(published['human_acceptance']['required'])
        report = verify_human_acceptance(self.evidence, self.anchor)
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['decision'], 'NOT_REQUIRED')


if __name__ == '__main__':
    unittest.main(verbosity=2)
