"""F01/F02 audit reproductions; all filesystem effects stay in temporary fixtures."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from tests import test_governance as fixtures
from orchestrator import development, workbench
from orchestrator.decisions import Status
from orchestrator.governance import ManagedDevelopmentWorker
from orchestrator.model import Outcome


class NoGoRegressionTests(unittest.TestCase):
    setUp = fixtures.GovernanceTests.setUp
    git = fixtures.GovernanceTests.git
    edits = fixtures.GovernanceTests.edits
    auth = fixtures.GovernanceTests.auth
    notify = fixtures.GovernanceTests.notify
    deny = fixtures.GovernanceTests.deny

    def invoke_legacy(self, module, ticket, artifacts):
        args = ['legacy', '--root', str(self.repo), '--ticket', ticket,
                '--edits', str(self.manifest), '--artifacts', str(artifacts)]
        if module is development:
            args += ['--base', self.profile.baseline, '--branch', 'master']
        else:
            # The original workbench hole used a declared development snapshot,
            # while the actual target was master; writes preceded comparison.
            source = self.base / 'snapshot.json'
            source.write_text(json.dumps({'branch': 'dev/fixture'}))
            args += ['--snapshot', str(source)]
        original_open = Path.open
        def read_only(path, mode='r', *a, **kw):
            if any(c in mode for c in 'wax+'):
                raise AssertionError('Unexpected file write')
            return original_open(path, mode, *a, **kw)
        with (patch.object(sys, 'argv', args),
              patch.object(Path, 'mkdir', side_effect=AssertionError('Unexpected mkdir')) as mkdir,
              patch.object(Path, 'write_bytes', side_effect=AssertionError('Unexpected byte write')) as byte_write,
              patch.object(Path, 'write_text', side_effect=AssertionError('Unexpected text write')) as text_write,
              patch.object(Path, 'open', read_only),
              patch.object(development.DevelopmentWindowsWorker, 'run', side_effect=AssertionError('Unexpected dispatch')) as dispatch):
            with self.assertRaises(ValueError):
                module.main()
            for call in (mkdir, byte_write, text_write, dispatch):
                call.assert_not_called()

    def test_f01_absolute_traversal_and_windows_ticket_aliases_zero_writes(self):
        tickets = [str(self.repo / 'unauthorized-evidence'), '..', '../outside', '..\\outside',
                   '/absolute', 'C:\\absolute', 'C:relative', '\\\\server\\share\\x',
                   'ticket.', 'ticket ', 'ticket:stream', 'NUL', 'COM1.txt', 'SHORT~1',
                   'nested/ticket', 'nested\\ticket', 'bad\nname']
        for module in (development, workbench):
            for ticket in tickets:
                with self.subTest(module=module.__name__, ticket=ticket):
                    self.invoke_legacy(module, ticket, self.base / 'external')
        self.assertEqual(self.git('status', '--porcelain=v1', cwd=self.repo), '')
        self.assertFalse((self.base / 'external').exists())

    def test_f01_protected_master_other_worktree_and_git_metadata_zero_writes(self):
        for module in (development, workbench):
            for destination in (self.repo, self.repo / 'nested', self.root, self.repo / '.git', self.repo / '.git/worktrees'):
                with self.subTest(module=module.__name__, destination=destination):
                    self.invoke_legacy(module, 'HG-001', destination)

    def test_f01_legitimate_ticket_preserves_naming_and_relative_base(self):
        import os
        base = self.base / 'external'
        for artifact in (base, Path(os.path.relpath(base))):
            result = development.evidence_directory(self.root, artifact, 'HG-001')
            self.assertEqual(result.parent, base)
            self.assertRegex(result.name, r'^HG-001-[0-9a-f]{8}$')
            self.assertFalse(result.exists())

    @unittest.skipUnless(sys.platform == 'win32', 'Windows evidence-base aliases')
    def test_f01_windows_evidence_base_aliases_zero_writes(self):
        for module in (development, workbench):
            for destination in (r'C:relative', '\\\\?\\' + str(self.repo), '\\\\.\\' + str(self.repo),
                                str(self.repo) + '.', str(self.repo) + ':stream'):
                with self.subTest(module=module.__name__, destination=destination):
                    self.invoke_legacy(module, 'HG-001', destination)

    def test_f01_legitimate_legacy_evidence_still_created_externally(self):
        # Existing DEV behavior remains: safe external evidence, then governance
        # denial of historical writes. No build/test dispatcher is introduced.
        self.git('remote', 'set-url', 'origin', 'https://github.com/Lacel1988/HostsGuardian.git', cwd=self.repo)
        args = ['legacy', '--root', str(self.repo), '--ticket', 'HG-001', '--edits', str(self.manifest),
                '--artifacts', str(self.base / 'external'), '--base', self.profile.baseline, '--branch', 'master']
        with patch.object(sys, 'argv', args), patch('signal.signal'), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(development.main(), 1)
        runs = list((self.base / 'external').glob('HG-001-*'))
        self.assertEqual(len(runs), 1)
        self.assertTrue((runs[0] / 'summary.json').is_file())
        self.assertEqual(self.git('status', '--porcelain=v1', cwd=self.repo), '')

    def test_f01_legitimate_workbench_evidence_still_created_externally(self):
        source = self.base / 'snapshot.json'
        source.write_text(json.dumps(workbench.snapshot(self.root)))
        args = ['legacy', '--root', str(self.root), '--ticket', 'HG-001', '--edits', str(self.manifest),
                '--snapshot', str(source), '--artifacts', str(self.base / 'external')]
        with patch.object(sys, 'argv', args), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(workbench.main(), 1)
        runs = list((self.base / 'external').glob('HG-001-*'))
        self.assertEqual(len(runs), 1)
        self.assertTrue((runs[0] / 'summary.json').is_file())
        self.assertEqual(self.git('status', '--porcelain=v1'), '')

    def malformed_batches(self):
        mutations = [
            {'content': None}, {'content': 42}, {'content': ['bad']},
            {'content': '\ud800'}, {'replacements': None}, {'replacements': 'bad'},
            {'replacements': [None]}, {'replacements': [{'old': 3, 'new': 'x'}]},
            {'replacements': [{'old': 'user', 'new': None}]},
            {'replacements': [{'old': '', 'new': 'x'}]},
            {'replacements': [{'old': 'user', 'new': '\ud800'}]},
            {'replacements': [{'old': 'user'}]},
            {'replacements': [{'old': 'user', 'new': 'x', 'extra': True}]},
        ]
        for mutation in mutations:
            self.edits(['Core/a.txt', 'Wpf/b.txt'])
            batch = json.loads(self.manifest.read_text())
            batch[1].update(mutation)
            self.manifest.write_text(json.dumps(batch), encoding='utf-8')
            yield mutation, batch

    def test_f02_invalid_second_edit_blocks_before_pass_dispatch_or_write(self):
        for mutation, _ in self.malformed_batches():
            with self.subTest(mutation=mutation):
                worker = fixtures.FakeDispatcher(self.profile, self.auth(('core', 'wpf')))
                self.assertEqual(worker.evaluate(self.operation).status, Status.BLOCK)
                with patch.object(Path, 'write_bytes', side_effect=AssertionError('Unexpected write')) as writes:
                    self.deny(worker)
                    writes.assert_not_called()

    def test_f02_internal_executor_prepares_entire_batch_before_any_write(self):
        for mutation, _ in self.malformed_batches():
            with self.subTest(mutation=mutation):
                with (patch.object(Path, 'mkdir', side_effect=AssertionError('Unexpected mkdir')) as mkdir,
                      patch.object(Path, 'write_bytes', side_effect=AssertionError('Unexpected write')) as writes):
                    with self.assertRaises(ValueError):
                        development.DevelopmentWindowsWorker('fixture', self.root)._execute_edits(self.operation, self.cancel, self.notify)
                    mkdir.assert_not_called()
                    writes.assert_not_called()
                for name in ['Core/a.txt', 'Wpf/b.txt']:
                    self.assertEqual((self.root / name).read_text(), 'user original')

    def test_f02_missing_content_bad_hash_and_replacement_only_structure(self):
        for second in [
            {'path': 'Wpf/b.txt', 'before_sha256': 'bad', 'content': 'x'},
            {'path': 'Wpf/b.txt', 'before_sha256': hashlib.sha256(b'user original').hexdigest()},
            {'path': 'Wpf/new.txt', 'before_sha256': None, 'replacements': [{'old': 'x', 'new': 'y'}]},
            {'path': 'Wpf/b.txt', 'before_sha256': hashlib.sha256(b'user original').hexdigest(),
             'replacements': [{'old': 'absent', 'new': 'x'}]},
        ]:
            self.edits(['Core/a.txt'])
            batch = json.loads(self.manifest.read_text()) + [second]
            self.manifest.write_text(json.dumps(batch))
            self.deny(fixtures.FakeDispatcher(self.profile, self.auth(('core', 'wpf'))))

    def test_f02_legitimate_multifile_content_and_replacements_dispatch_once(self):
        self.edits(['Core/a.txt', 'Wpf/b.txt'])
        batch = json.loads(self.manifest.read_text())
        batch[0]['content'] = 'árvíz\r\n'
        del batch[1]['content']
        batch[1]['replacements'] = [{'old': 'user', 'new': 'approved'}]
        self.manifest.write_text(json.dumps(batch))
        worker = fixtures.FakeDispatcher(self.profile, self.auth(('core', 'wpf')), apply=True)
        result = worker.run(self.operation, self.cancel, self.notify)
        self.assertEqual(result.outcome, Outcome.SUCCESS)
        self.assertEqual(len(worker.calls), 1)
        self.assertEqual((self.root / 'Core/a.txt').read_bytes(), 'árvíz\r\n'.encode('utf-8'))
        self.assertEqual((self.root / 'Wpf/b.txt').read_bytes(), b'approved original')
        self.assertEqual((self.root / 'user.txt').read_text(), 'user original')
