"""G5 integrity/semantic negatives on copies of one real completed fixture run."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import acceptance_g4 as g4fixtures
from orchestrator.ledger import Ledger, canonical, evidence_hash
from orchestrator import managed


class G5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = g4fixtures.G4Acceptance('test_actual_diff_check_is_revalidated')
        cls.fixture.setUp()
        code, text = cls.fixture.invoke(cls.fixture.inputs(diff=True))
        if code:
            cls.fixture.doCleanups()
            raise AssertionError(text)
        cls.original = {name: (cls.fixture.evidence / name).read_bytes()
                        for name in ('events.jsonl', 'summary.json', 'completion.json')}
        cls.original_anchor = hashlib.sha256(cls.original['completion.json']).hexdigest()
        cls.binding = json.loads(cls.original['completion.json'])['binding']

    @classmethod
    def tearDownClass(cls):
        cls.fixture.doCleanups()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hg-g5-evidence-copy-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.anchor = self.original_anchor
        self.restore()

    def restore(self):
        for name, data in self.original.items():
            (self.root / name).write_bytes(data)
        self.anchor = self.original_anchor

    def verify(self, anchored=True, **kwargs):
        return Ledger.verify_managed(self.root, expected_certificate=self.anchor if anchored else None, **kwargs)

    def resign(self, mutate_events=None, mutate_summary=None):
        # Deliberately reseal corrupted test packets to exercise semantic checks,
        # not to claim authentication from caller-supplied replacement hashes.
        events = [json.loads(x) for x in (self.root / 'events.jsonl').read_text().splitlines()]
        if mutate_events:
            mutate_events(events)
        previous = '0' * 64
        for index, event in enumerate(events, 1):
            event.update(sequence=index, previous_hash=previous)
            event.pop('event_hash', None)
            previous = event['event_hash'] = evidence_hash(event)
        (self.root / 'events.jsonl').write_bytes((''.join(canonical(x) + '\n' for x in events)).encode())
        summary = json.loads((self.root / 'summary.json').read_text())
        if mutate_summary:
            mutate_summary(summary)
        (self.root / 'summary.json').write_bytes(canonical(summary).encode())
        cert = json.loads((self.root / 'completion.json').read_text())
        cert.update(ledger_sha256=hashlib.sha256((self.root / 'events.jsonl').read_bytes()).hexdigest(),
                    summary_sha256=hashlib.sha256((self.root / 'summary.json').read_bytes()).hexdigest(),
                    ledger_events=len(events), chain_head=previous)
        (self.root / 'completion.json').write_bytes(canonical(cert).encode())
        self.anchor = hashlib.sha256((self.root / 'completion.json').read_bytes()).hexdigest()

    def alter_event(self, kind, change):
        self.resign(lambda events: change(next(e for e in events if e['event'] == kind)))

    def test_valid_complete_chain_with_trusted_reference_passes(self):
        self.assertEqual(self.verify()['status'], 'PASS')

    def test_unanchored_history_is_unknown_not_authenticated_pass(self):
        report = self.verify(False)
        self.assertEqual(report['status'], 'UNKNOWN')
        self.assertEqual(report['integrity'], 'VERIFIED')
        self.assertEqual(report['origin_authentication'], 'NOT_PROVIDED')

    def test_missing_mandatory_files_block(self):
        for name in self.original:
            self.restore()
            (self.root / name).unlink()
            self.assertEqual(self.verify()['status'], 'BLOCK', name)

    def test_corrupted_files_block(self):
        for name in self.original:
            self.restore()
            with (self.root / name).open('ab') as f:
                f.write(b'corrupt')
            self.assertEqual(self.verify()['status'], 'BLOCK', name)

    def test_torn_ledger_blocks(self):
        (self.root / 'events.jsonl').write_bytes(self.original['events.jsonl'][:-7])
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_missing_g4_even_after_rehashing_blocks(self):
        self.resign(lambda events: events.__setitem__(slice(None), [e for e in events if e['event'] != 'G4_REVALIDATION']))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_missing_guard_even_after_rehashing_blocks(self):
        self.resign(lambda events: events.__setitem__(slice(None), [e for e in events if e['event'] != 'GOVERNANCE_DECISION']))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_pass_from_another_policy_is_not_g1_g2_authorization(self):
        self.alter_event('GOVERNANCE_DECISION', lambda e: e['result'].update(policy_ids=['OTHER']))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_other_operation_binding_blocks(self):
        self.alter_event('G3_ATTEMPT', lambda e: e['result']['binding'].update(operation_identity='f' * 64))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_authorization_identity_mismatch_blocks(self):
        self.alter_event('G3_ATTEMPT', lambda e: e['result']['binding']['authorization'].update(id='another-review'))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_workspace_binding_mismatch_blocks(self):
        self.alter_event('G3_ATTEMPT', lambda e: e['result']['binding']['workspace'].update(branch='dev/other'))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_attempt_identity_mismatch_blocks(self):
        self.alter_event('G4_REVALIDATION', lambda e: e['result'].update(attempt=2))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_contradictory_attempt_result_blocks(self):
        self.alter_event('G3_ATTEMPT_RESULT', lambda e: e['result'].update(outcome='FAILED'))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_contradictory_actual_result_blocks(self):
        self.alter_event('COMMAND_RESULT', lambda e: e['result'].update(stdout='forged'))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_summary_cannot_replace_g4_evidence(self):
        self.resign(mutate_summary=lambda s: s.pop('revalidation'))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_duplicated_g4_record_blocks(self):
        def duplicate(events):
            index = next(i for i, e in enumerate(events) if e['event'] == 'G4_REVALIDATION')
            events.insert(index, json.loads(json.dumps(events[index])))
        self.resign(duplicate)
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_invalid_completion_transition_blocks(self):
        self.alter_event('TRANSITION', lambda e: e['result'].update(to='COMPLETE'))
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_provisional_summary_without_certificate_blocks(self):
        (self.root / 'completion.json').unlink()
        self.assertEqual(json.loads(self.original['summary.json'])['dispatch_decision']['status'], 'PASS')
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_duplicate_json_fields_block(self):
        raw = self.original['completion.json'].decode().replace('"schema":', '"schema":"duplicate","schema":', 1)
        (self.root / 'completion.json').write_bytes(raw.encode())
        self.anchor = hashlib.sha256(raw.encode()).hexdigest()
        self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_trusted_anchor_detects_reformatted_certificate(self):
        value = json.loads(self.original['completion.json'])
        (self.root / 'completion.json').write_bytes(json.dumps(value, indent=2).encode())
        self.assertEqual(self.verify()['status'], 'BLOCK')
        self.assertEqual(self.verify(False)['status'], 'UNKNOWN')

    def test_read_error_blocks(self):
        with patch.object(Path, 'read_bytes', side_effect=OSError('fixture read error')):
            self.assertEqual(self.verify()['status'], 'BLOCK')

    def test_expected_binding_rejects_another_workspace(self):
        expected = json.loads(json.dumps(self.binding))
        expected['workspace']['root'] = 'other-workspace'
        self.assertEqual(self.verify(expected_binding=expected)['status'], 'BLOCK')

    def test_read_only_verifier_does_not_dispatch_or_write(self):
        before = {name: ((self.root / name).read_bytes(), (self.root / name).stat().st_mtime_ns) for name in self.original}
        source = self.fixture.root / 'owned/source.txt'
        source_before = source.read_bytes()
        with (patch('subprocess.Popen', side_effect=AssertionError('No subprocess allowed')),
              patch.object(Ledger, '__init__', side_effect=AssertionError('No writer allowed')),
              patch.object(Path, 'mkdir', side_effect=AssertionError('No mkdir allowed')),
              patch.object(Path, 'write_text', side_effect=AssertionError('No write allowed')),
              patch.object(Path, 'write_bytes', side_effect=AssertionError('No write allowed'))):
            self.assertEqual(self.verify()['status'], 'PASS')
        self.assertEqual(before, {name: ((self.root / name).read_bytes(), (self.root / name).stat().st_mtime_ns)
                                  for name in self.original})
        self.assertEqual(source.read_bytes(), source_before)

    def test_reader_cli_needs_no_authorization_and_never_constructs_worker(self):
        with (patch.object(managed, 'ManagedDevelopmentWorker', side_effect=AssertionError('No worker')),
              patch('subprocess.Popen', side_effect=AssertionError('No process')),
              contextlib.redirect_stdout(io.StringIO()) as out):
            self.assertEqual(managed.main(['--verify-evidence', str(self.root), '--expected-certificate', self.anchor]), 0)
        self.assertEqual(json.loads(out.getvalue())['status'], 'PASS')

    def test_legacy_unsealed_history_is_unknown(self):
        (self.root / 'completion.json').unlink()
        (self.root / 'events.jsonl').write_text(json.dumps({'sequence': 1, 'event': 'CREATED', 'result': None}) + '\n')
        self.assertEqual(self.verify(False)['status'], 'UNKNOWN')

    def test_task_snapshot_is_not_managed_completion_certificate(self):
        with self.assertRaises(ValueError):
            Ledger.recover(self.root / 'events.jsonl')


if __name__ == '__main__':
    unittest.main()
