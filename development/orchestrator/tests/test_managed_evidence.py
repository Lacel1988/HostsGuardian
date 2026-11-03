"""G2 managed evidence destinations: only temporary Git worktrees are touched."""
import contextlib
from dataclasses import asdict, replace
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from tests import test_governance as fixtures
from orchestrator import managed


class ManagedEvidenceTests(unittest.TestCase):
    setUp = fixtures.GovernanceTests.setUp
    git = fixtures.GovernanceTests.git
    edits = fixtures.GovernanceTests.edits
    auth = fixtures.GovernanceTests.auth

    def arguments(self, destination):
        operation = replace(self.operation, argv=('git', '--no-optional-locks', 'diff', '--check'))
        profile = asdict(self.profile)
        profile['components'] = dict(profile['components'])
        profile['requirements'] = dict(profile['requirements'])
        for name, value in [('profile', profile), ('request', asdict(operation)),
                            ('authorization', asdict(self.auth((), operation)))]:
            (self.base / (name + '.json')).write_text(json.dumps(value))
        (self.base / 'budget.json').write_text(json.dumps({'total_timeout_seconds': 300}))
        return ['--profile', str(self.base / 'profile.json'), '--request', str(self.base / 'request.json'),
                '--budget', str(self.base / 'budget.json'),
                '--authorization', str(self.base / 'authorization.json'), '--artifacts', str(destination), '--plain']

    def denied_without_writes(self, destination):
        args = self.arguments(destination)  # fixture inputs created before write spies
        before = {root: self.git('status', '--porcelain=v1', '--untracked-files=all', cwd=root)
                  for root in (self.repo, self.root)}
        original_open = Path.open
        def read_only(path, mode='r', *a, **kw):
            if any(c in mode for c in 'wax+'):
                raise AssertionError('Unexpected evidence write')
            return original_open(path, mode, *a, **kw)
        with (patch.object(Path, 'mkdir', side_effect=AssertionError('Unexpected mkdir')) as mkdir,
              patch.object(Path, 'write_bytes', side_effect=AssertionError('Unexpected byte write')) as byte_write,
              patch.object(Path, 'write_text', side_effect=AssertionError('Unexpected text write')) as text_write,
              patch.object(Path, 'open', read_only),
              patch.object(managed.ManagedDevelopmentWorker, 'run', side_effect=AssertionError('Unexpected dispatch')) as dispatch,
              contextlib.redirect_stdout(io.StringIO()) as output):
            self.assertEqual(managed.main(args), 1)
            for call in (mkdir, byte_write, text_write, dispatch):
                call.assert_not_called()
        decision = json.loads(output.getvalue().splitlines()[0])
        self.assertEqual(decision['status'], 'BLOCK')
        for root, status in before.items():
            self.assertEqual(self.git('status', '--porcelain=v1', '--untracked-files=all', cwd=root), status)
        self.assertFalse(Path(destination).exists())

    def test_master_and_main_worktrees_rejected_before_any_write_or_dispatch(self):
        # Exact independent-audit reproducer: authorized read-only diff request,
        # but evidence was aimed at another worktree's protected source directory.
        self.denied_without_writes(self.repo / 'master-evidence')
        main = self.base / 'main-worktree'
        self.git('worktree', 'add', '-b', 'main', str(main), self.profile.baseline, cwd=self.repo)
        self.denied_without_writes(main / 'evidence')
        self.assertEqual(self.git('status', '--porcelain=v1', cwd=main), '')

    def test_preserved_development_worktree_rejected(self):
        other = self.base / 'preserved-development'
        self.git('worktree', 'add', '-b', 'dev/preserved', str(other), self.profile.baseline, cwd=self.repo)
        user = other / 'user.txt'
        user.write_text('preserve dirty user work')
        before = self.git('status', '--porcelain=v1', '--untracked-files=all', cwd=other)
        self.denied_without_writes(other / 'evidence')
        self.assertEqual(user.read_text(), 'preserve dirty user work')
        self.assertEqual(self.git('status', '--porcelain=v1', '--untracked-files=all', cwd=other), before)

    def test_current_worktree_and_shared_git_metadata_rejected(self):
        common = Path(self.git('rev-parse', '--path-format=absolute', '--git-common-dir'))
        for destination in (self.root / 'evidence', common / 'evidence', common / 'worktrees/evidence'):
            with self.subTest(destination=destination):
                self.denied_without_writes(destination)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows junction fixture')
    def test_junction_alias_to_master_worktree_rejected(self):
        import subprocess
        alias = self.base / 'alias'
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(alias), str(self.repo)], check=True, capture_output=True)
        self.addCleanup(lambda: alias.rmdir() if alias.exists() else None)
        self.denied_without_writes(alias / 'evidence')

    def test_legitimate_external_target_keeps_exact_path_and_dispatches_once(self):
        destination = self.base / 'external-evidence'
        args = self.arguments(destination)
        before = self.git('status', '--porcelain=v1', '--untracked-files=all', cwd=self.repo)
        original_run = managed.ManagedDevelopmentWorker.run
        calls = []
        def counted(worker, *a, **kw):
            calls.append(worker.identity)
            return original_run(worker, *a, **kw)
        with patch.object(managed.ManagedDevelopmentWorker, 'run', counted), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(managed.main(args), 0)
        self.assertEqual(len(calls), 1)
        summary = json.loads((destination / 'summary.json').read_text())
        self.assertEqual(summary['dispatch_decision']['status'], 'PASS')
        self.assertEqual(summary['acceptance']['status'], 'NOT_EVALUATED')
        self.assertTrue((destination / 'events.jsonl').is_file())
        self.assertEqual(self.git('status', '--porcelain=v1', '--untracked-files=all', cwd=self.repo), before)
