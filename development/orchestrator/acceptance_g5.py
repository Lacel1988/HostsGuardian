"""G5 real CLI acceptance; reuse existing isolated Git fixture construction only."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import acceptance_g4 as fixtures
from orchestrator import managed
from orchestrator.budget import ExecutionBudget, active_budget
from orchestrator.ledger import Ledger


class G5Acceptance(unittest.TestCase):
    setUp = fixtures.G4Acceptance.setUp
    git = fixtures.G4Acceptance.git
    inputs = fixtures.G4Acceptance.inputs
    invoke = fixtures.G4Acceptance.invoke

    def completed(self, args):
        code, text = self.invoke(args)
        self.assertEqual(code, 0, text)
        published = json.loads(text.splitlines()[0])['completion_certificate']
        self.assertEqual(published['status'], 'PASS')
        return published['certificate_sha256']

    def failed(self, args):
        code, text = self.invoke(args)
        self.assertEqual(code, 1, text)
        summary = json.loads((self.evidence / 'summary.json').read_text())
        self.assertEqual(summary['completion'], 'FAILED')
        self.assertEqual(summary['dispatch_decision']['status'], 'BLOCK')
        self.assertEqual(Ledger.verify_managed(self.evidence)['status'], 'BLOCK')
        # G4 can already have succeeded; failure must not rerun or undo the edit.
        self.assertEqual((self.root / 'owned/source.txt').read_text(), 'reviewed')

    def test_real_edit_has_bound_and_readback_verified_completion(self):
        anchor = self.completed(self.inputs())
        cert = json.loads((self.evidence / 'completion.json').read_text())
        self.assertEqual(cert['status'], 'PASS')
        self.assertEqual(cert['attempt'], 1)
        self.assertEqual(cert['binding']['workspace']['root'], str(self.root))
        self.assertEqual(Ledger.verify_managed(self.evidence, expected_certificate=anchor)['status'], 'PASS')
        summary = json.loads((self.evidence / 'summary.json').read_text())
        self.assertEqual(summary['completion'], 'CERTIFICATE_REQUIRED')
        self.assertEqual(summary['acceptance']['status'], 'NOT_EVALUATED')

    def test_silently_missing_g4_record_blocks_completion(self):
        args = self.inputs()
        original = Ledger.record
        def record(ledger, task, kind, *a, **kw):
            if kind != 'G4_REVALIDATION':
                return original(ledger, task, kind, *a, **kw)
        with patch.object(Ledger, 'record', record):
            self.failed(args)

    def test_contradictory_recorded_result_blocks_completion(self):
        args = self.inputs()
        original = Ledger.record
        def record(ledger, task, kind, message, worker=None, result=None):
            if kind == 'COMMAND_RESULT':
                result = {**result, 'outcome': 'FAILED'}
            return original(ledger, task, kind, message, worker, result)
        with patch.object(Ledger, 'record', record):
            self.failed(args)

    def test_corrupted_ledger_before_finalization_blocks(self):
        args = self.inputs()
        original = Ledger.verify_live
        def verify(ledger, *a, **kw):
            with ledger.path.open('ab') as stream:
                stream.write(b'{torn')
            return original(ledger, *a, **kw)
        with patch.object(Ledger, 'verify_live', verify):
            self.failed(args)

    def test_reformatted_ledger_before_sealing_also_blocks(self):
        args = self.inputs()
        original = Ledger.verify_live
        def verify(ledger, *a, **kw):
            events = [json.loads(line) for line in ledger.path.read_text().splitlines()]
            # Same records and event hashes, but bytes not written by this writer.
            changed = ''.join(json.dumps(e, sort_keys=True) + '\n' for e in events).encode()
            self.assertNotEqual(changed, ledger.path.read_bytes())
            ledger.path.write_bytes(changed)
            return original(ledger, *a, **kw)
        with patch.object(Ledger, 'verify_live', verify):
            self.failed(args)

    def test_completion_write_error_blocks(self):
        args = self.inputs()
        original = Path.open
        def opened(path, mode='r', *a, **kw):
            if path == self.evidence / 'completion.json' and mode == 'x':
                raise OSError('synthetic completion write error')
            return original(path, mode, *a, **kw)
        with patch.object(Path, 'open', opened):
            self.failed(args)

    def test_completion_readback_error_blocks(self):
        args = self.inputs()
        original = Path.read_bytes
        def read(path):
            if path == self.evidence / 'completion.json':
                raise OSError('synthetic readback error')
            return original(path)
        with patch.object(Path, 'read_bytes', read):
            code, text = self.invoke(args)
        self.assertEqual(code, 1, text)
        self.assertEqual(Ledger.verify_managed(self.evidence)['status'], 'BLOCK')

    def finalization_pause(self, action):
        original = Path.open
        def opened(path, mode='r', *a, **kw):
            if path == self.evidence / 'completion.json' and mode == 'x':
                @contextlib.contextmanager
                def paused():
                    with original(path, mode, *a, **kw) as stream:
                        yield stream
                    action()
                return paused()
            return original(path, mode, *a, **kw)
        return patch.object(Path, 'open', opened)

    def test_deadline_expiring_during_certificate_publication_blocks(self):
        args = self.inputs()
        now = [0.0]
        budget = ExecutionBudget(1, 3, True, clock=lambda: now[0])
        with (patch('orchestrator.managed.ExecutionBudget.load', return_value=budget),
              self.finalization_pause(lambda: now.__setitem__(0, 1))):
            self.failed(args)

    def test_cancellation_during_certificate_publication_blocks(self):
        args = self.inputs()
        with self.finalization_pause(lambda: active_budget.get().cancel.set()):
            self.failed(args)

    def test_read_only_verifier_needs_no_authorization_or_worker(self):
        anchor = self.completed(self.inputs(diff=True))
        paths = list(self.evidence.iterdir()) + [self.root / 'owned/source.txt', self.root / 'outside.txt']
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        with (patch.object(managed, 'ManagedDevelopmentWorker', side_effect=AssertionError('No worker')),
              patch('subprocess.Popen', side_effect=AssertionError('No process')),
              patch.object(Path, 'write_text', side_effect=AssertionError('No writes')),
              contextlib.redirect_stdout(io.StringIO()) as output):
            code = managed.main(['--verify-evidence', str(self.evidence), '--expected-certificate', anchor])
        self.assertEqual(code, 0, output.getvalue())
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})

    def test_unanchored_historical_completion_remains_unknown(self):
        self.completed(self.inputs(diff=True))
        self.assertEqual(Ledger.verify_managed(self.evidence)['status'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main(verbosity=2)
