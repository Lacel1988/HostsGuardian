import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from orchestrator.development import DevelopmentWindowsWorker
from orchestrator.model import Operation
from orchestrator.workbench import snapshot


class DevelopmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.worker = DevelopmentWindowsWorker('fixture', self.root)
        self.cancel = threading.Event()

    def execute(self, edits):
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps(edits))
        return self.worker.execute(Operation('edits', ('owned-edits', str(manifest)), str(self.root), category='owned-development'), self.cancel, lambda *_: None)

    def test_allowlist_requires_exact_owned_directory_and_command(self):
        for argv in [('dotnet', 'run', '--project', 'development/DesktopE2E'), ('dotnet', 'build', 'HostsGuardian.sln')]:
            self.assertFalse(self.worker.approval_required(Operation('allowed', argv, str(self.root), category='owned-development')))
            self.assertTrue(self.worker.approval_required(Operation('outside', argv, str(self.root.parent), category='owned-development')))
        for argv in [('git', 'push'), ('powershell', 'anything'), ('dotnet', 'run', '--project', 'unknown')]:
            self.assertTrue(self.worker.approval_required(Operation('denied', argv, str(self.root), category='owned-development')))

    def test_every_hash_is_checked_before_any_write(self):
        file = self.root / 'existing.cs'; file.write_text('before')
        with self.assertRaises(ValueError):
            self.execute([{'path': 'existing.cs', 'before_sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'content': 'after'},
                          {'path': 'new.cs', 'before_sha256': 'wrong', 'content': 'new'}])
        self.assertEqual(file.read_text(), 'before')
        self.assertFalse((self.root / 'new.cs').exists())

    def test_new_files_and_cancellation_preserve_exact_content(self):
        self.cancel.set()
        self.execute([{'path': 'nested/new.cs', 'before_sha256': None, 'content': 'árvíz\n'}])
        self.assertFalse((self.root / 'nested/new.cs').exists())
        self.cancel.clear()
        self.execute([{'path': 'nested/new.cs', 'before_sha256': None, 'content': 'árvíz\n'}])
        self.assertEqual((self.root / 'nested/new.cs').read_bytes(), 'árvíz\n'.encode())

    def test_escape_git_and_duplicate_paths_fail_closed(self):
        for paths in [['../outside.cs'], ['.git/config'], ['same.cs', 'same.cs']]:
            with self.assertRaises(ValueError):
                self.execute([{'path': path, 'before_sha256': None, 'content': 'bad'} for path in paths])
        self.assertFalse((self.root / 'same.cs').exists())

    def test_snapshot_detects_untracked_edits_and_preserves_repository_identity(self):
        subprocess.run(['git', 'init', '-b', 'dev/fixture'], cwd=self.root, check=True, capture_output=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-m', 'fixture'], cwd=self.root, check=True, capture_output=True)
        subprocess.run(['git', 'remote', 'add', 'origin', 'https://example.invalid/fixture.git'], cwd=self.root, check=True, capture_output=True)
        source = self.root / 'new.cs'; source.write_text('before')
        before = snapshot(self.root); source.write_text('after'); after = snapshot(self.root)
        self.assertNotEqual(before['files'], after['files'])
        self.assertEqual(before['head'], after['head'])
        self.assertEqual(after['branch'], 'dev/fixture')


if __name__ == '__main__':
    unittest.main()
