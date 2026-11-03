"""G6 operator decisions are synthetic fixture input, never real project approval."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import acceptance_g4 as fixtures
from orchestrator import managed
from orchestrator.budget import ExecutionBudget
from orchestrator.human_acceptance import verify_human_acceptance


class G6Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = fixtures.G4Acceptance('test_valid_edit_has_actual_postcondition_and_recorded_g4_evidence')
        cls.fixture.setUp()
        cls.bundles = {}
        for kind, diff in [('edit', False), ('diff', True)]:
            cls.fixture.evidence = cls.fixture.base / (kind + '-evidence')
            code, output = cls.fixture.invoke(cls.fixture.inputs(diff=diff))
            if code:
                cls.fixture.doCleanups()
                raise AssertionError(output)
            anchor = json.loads(output.splitlines()[0])['completion_certificate']['certificate_sha256']
            cls.bundles[kind] = ({name: (cls.fixture.evidence / name).read_bytes()
                                  for name in ('events.jsonl', 'summary.json', 'completion.json')}, anchor)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.doCleanups()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hg-g6-synthetic-review-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.run = self.base / 'evidence'
        self.run.mkdir()
        self.operator = self.base / 'operator-reviewed.json'
        self.load('edit')

    def load(self, kind):
        files, self.anchor = self.bundles[kind]
        for name, data in files.items():
            (self.run / name).write_bytes(data)
        self.cert = json.loads(files['completion.json'])
        self.summary = json.loads(files['summary.json'])

    def packet(self, decision='ACCEPT'):
        cert = self.cert
        return {'schema': 'hg-operator-acceptance-v1', 'records': [{
            'id': 'synthetic-post-review-1', 'decision': decision, 'input_origin': 'operator-reviewed',
            'policy_id': 'g6-managed-v1', 'completion_certificate_sha256': self.anchor,
            'task_id': cert['task_id'], 'operation_identity': cert['binding']['operation_identity'],
            'authorization_identity': cert['attempt_binding']['authorization_identity'],
            'workspace': cert['binding']['workspace'], 'source_identity': cert['attempt_binding']['source_identity'],
            'post_source_identity': self.summary['revalidation']['source_identity'],
            'attempt': cert['attempt'], 'g4_identity': cert['g4_identity'],
            'evidence_refs': ['test:synthetic-operator-review-not-real-human-acceptance']}]}

    def review(self, packet=None, path=None):
        path = path or self.operator
        path.write_text(json.dumps(packet if packet is not None else self.packet()), encoding='utf-8')
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def verify(self, packet=None):
        digest = self.review(packet)
        return verify_human_acceptance(self.run, self.anchor, self.operator, digest)

    def test_valid_operator_accept_is_bound_to_completed_result(self):
        report = self.verify()
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['decision'], 'ACCEPT')
        self.assertFalse(report['g3_budget_reopened'])

    def test_missing_acceptance_is_pending(self):
        self.assertEqual(verify_human_acceptance(self.run, self.anchor)['status'], 'PENDING')

    def test_explicit_pending_is_not_final_acceptance(self):
        self.assertEqual(self.verify(self.packet('PENDING'))['status'], 'PENDING')

    def test_reject_blocks_without_source_or_evidence_changes(self):
        before = {p.name: p.read_bytes() for p in self.run.iterdir()}
        self.assertEqual(self.verify(self.packet('REJECT'))['status'], 'BLOCK')
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.run.iterdir()})

    def test_unknown_or_malformed_decisions_block(self):
        for decision in (None, 'PASS', 'accept', True, {'decision': 'ACCEPT'}):
            self.assertEqual(self.verify(self.packet(decision))['status'], 'BLOCK')

    def mismatch(self, key, value):
        packet = self.packet()
        packet['records'][0][key] = value
        self.assertEqual(self.verify(packet)['status'], 'BLOCK')

    def test_other_operation_blocks(self):
        self.mismatch('operation_identity', 'f' * 64)

    def test_other_authorization_blocks(self):
        self.mismatch('authorization_identity', 'f' * 64)

    def test_other_workspace_blocks(self):
        self.mismatch('workspace', {**self.cert['binding']['workspace'], 'branch': 'dev/other'})

    def test_other_before_or_after_source_blocks(self):
        for key in ('source_identity', 'post_source_identity'):
            self.mismatch(key, 'f' * 64)

    def test_other_attempt_blocks(self):
        self.mismatch('attempt', 2)

    def test_other_g4_result_blocks(self):
        self.mismatch('g4_identity', 'f' * 64)

    def test_other_certificate_blocks(self):
        self.mismatch('completion_certificate_sha256', 'f' * 64)

    def test_other_task_blocks(self):
        self.mismatch('task_id', 'other-task')

    def test_missing_binding_blocks(self):
        packet = self.packet()
        packet['records'][0].pop('source_identity')
        self.assertEqual(self.verify(packet)['status'], 'BLOCK')

    def test_repeated_record_blocks(self):
        packet = self.packet()
        packet['records'] *= 2
        self.assertEqual(self.verify(packet)['status'], 'BLOCK')

    def test_conflicting_records_block(self):
        packet = self.packet()
        packet['records'].append(self.packet('REJECT')['records'][0])
        self.assertEqual(self.verify(packet)['status'], 'BLOCK')

    def test_worker_origin_is_not_operator_review(self):
        self.mismatch('input_origin', 'worker')

    def test_record_without_operator_trust_reference_blocks(self):
        self.review()
        self.assertEqual(verify_human_acceptance(self.run, self.anchor, self.operator)['status'], 'BLOCK')

    def test_wrong_reviewed_record_digest_blocks(self):
        self.review()
        self.assertEqual(verify_human_acceptance(self.run, self.anchor, self.operator, '0' * 64)['status'], 'BLOCK')

    def test_worker_evidence_directory_cannot_supply_approval(self):
        path = self.run / 'self-approval.json'
        digest = self.review(path=path)
        self.assertEqual(verify_human_acceptance(self.run, self.anchor, path, digest)['status'], 'BLOCK')

    def test_worker_source_directory_cannot_supply_approval(self):
        path = self.fixture.root / 'self-approval.json'
        self.addCleanup(lambda: path.unlink() if path.exists() else None)
        digest = self.review(path=path)
        self.assertEqual(verify_human_acceptance(self.run, self.anchor, path, digest)['status'], 'BLOCK')

    def test_pre_execution_authorization_is_not_post_acceptance(self):
        digest = self.review(self.cert['attempt_binding']['authorization'])
        self.assertEqual(verify_human_acceptance(self.run, self.anchor, self.operator, digest)['status'], 'BLOCK')

    def test_post_decision_id_must_be_separate_from_pre_authorization(self):
        self.mismatch('id', self.cert['attempt_binding']['authorization']['id'])

    def test_corrupted_g5_evidence_blocks_acceptance(self):
        with (self.run / 'events.jsonl').open('ab') as f:
            f.write(b'corrupt')
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_missing_g5_completion_cannot_be_human_accepted(self):
        (self.run / 'completion.json').unlink()
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_read_only_verifier_has_no_worker_writer_or_budget(self):
        digest = self.review()
        files = list(self.run.iterdir()) + [self.operator, self.fixture.root / 'owned/source.txt']
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in files}
        with (patch('subprocess.Popen', side_effect=AssertionError('No process')),
              patch.object(ExecutionBudget, '__init__', side_effect=AssertionError('No new budget')),
              patch.object(Path, 'write_bytes', side_effect=AssertionError('No writes')),
              patch.object(Path, 'write_text', side_effect=AssertionError('No writes')),
              patch.object(Path, 'mkdir', side_effect=AssertionError('No mkdir'))):
            self.assertEqual(verify_human_acceptance(self.run, self.anchor, self.operator, digest)['status'], 'PASS')
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in files})

    def test_closed_g3_budget_is_not_reopened(self):
        budget = ExecutionBudget(1)
        budget.finished = True
        budget.execution_complete = True
        before = vars(budget).copy()
        self.assertEqual(self.verify()['status'], 'PASS')
        self.assertEqual(vars(budget), before)

    def test_diff_check_needs_no_human_decision(self):
        self.load('diff')
        report = verify_human_acceptance(self.run, self.anchor)
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['decision'], 'NOT_REQUIRED')
        self.assertFalse(report['required'])

    def test_unneeded_record_is_not_treated_as_an_implicit_approval(self):
        self.load('diff')
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_repeated_read_is_idempotent_not_a_second_acceptance_action(self):
        digest = self.review()
        first = verify_human_acceptance(self.run, self.anchor, self.operator, digest)
        self.assertEqual(first['status'], 'PASS')
        self.assertEqual(first, verify_human_acceptance(self.run, self.anchor, self.operator, digest))

    def test_hardlinked_record_cannot_alias_worker_or_other_input(self):
        digest = self.review()
        os.link(self.operator, self.base / 'alias.json')
        self.assertEqual(verify_human_acceptance(self.run, self.anchor, self.operator, digest)['status'], 'BLOCK')

    def test_duplicate_json_keys_block(self):
        raw = json.dumps(self.packet()).replace('"schema":', '"schema":"duplicate","schema":', 1)
        self.operator.write_text(raw)
        digest = hashlib.sha256(self.operator.read_bytes()).hexdigest()
        self.assertEqual(verify_human_acceptance(self.run, self.anchor, self.operator, digest)['status'], 'BLOCK')

    def test_read_only_cli_needs_no_pre_authorization(self):
        digest = self.review()
        with (patch.object(managed, 'ManagedDevelopmentWorker', side_effect=AssertionError('No worker')),
              contextlib.redirect_stdout(io.StringIO()) as output):
            code = managed.main(['--verify-human-acceptance', str(self.run), '--expected-certificate', self.anchor,
                                 '--acceptance-record', str(self.operator), '--expected-acceptance', digest])
        self.assertEqual(code, 0, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['decision'], 'ACCEPT')


if __name__ == '__main__':
    unittest.main()
