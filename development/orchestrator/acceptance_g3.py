"""Separate black-box G3 acceptance. Own temporary Git fixtures, no product calls."""
import contextlib
from dataclasses import asdict
import errno
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from orchestrator import managed
from orchestrator.governance import (Authorization, Profile, operation_identity,
                                     profile_identity, source_identity)
from orchestrator.model import Operation


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hg-g3-acceptance-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repository'
        self.repo.mkdir()
        self.git('init', '-b', 'master')
        self.git('config', 'user.name', 'G3 Fixture')
        self.git('config', 'user.email', 'g3@example.invalid')
        (self.repo / 'owned').mkdir()
        (self.repo / 'owned/source.txt').write_text('original', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-m', 'isolated fixture')
        self.git('remote', 'add', 'origin', 'https://example.invalid/no-network')
        head = self.git('rev-parse', 'HEAD')
        self.root = self.base / 'linked'
        self.git('worktree', 'add', '-b', 'dev/g3-fixture', str(self.root), head)
        self.profile = Profile('g3-acceptance', 'g1-g2-v1', str(self.root), 'dev/g3-fixture', head,
                               (('owned', ('owned',)),), ('edit', 'diff-check'))
        self.operation = Operation('diff fixture', ('git', '--no-optional-locks', 'diff', '--check'),
                                   str(self.root), category='owned-development')
        self.evidence = self.base / 'evidence'

    def git(self, *args):
        return subprocess.check_output(['git', '--no-optional-locks', *args], cwd=self.repo,
                                       text=True, stderr=subprocess.DEVNULL).strip()

    def inputs(self, *, retry=False, edit=False):
        components = ()
        if edit:
            components = ('owned',)
            self.write('edits', [{'path': 'owned/source.txt',
                                 'before_sha256': hashlib.sha256(b'original').hexdigest(), 'content': 'reviewed'}])
            self.operation = Operation('edit fixture', ('owned-edits', str(self.base / 'edits.json')),
                                       str(self.root), category='owned-development')
        auth = Authorization('review-1', profile_identity(self.profile), source_identity(self.root),
                             operation_identity(self.operation), components, ('review:1',))
        profile = asdict(self.profile)
        profile['components'] = dict(profile['components'])
        profile['requirements'] = dict(profile['requirements'])
        self.write('profile', profile)
        self.write('request', asdict(self.operation))
        self.write('authorization', asdict(auth))
        self.write('budget', {'total_timeout_seconds': 60, 'max_attempts': 2 if retry else 1,
                              'retry_transient': retry})
        args = ['--profile', str(self.base / 'profile.json'), '--request', str(self.base / 'request.json'),
                '--authorization', str(self.base / 'authorization.json'), '--artifacts', str(self.evidence),
                '--budget', str(self.base / 'budget.json'), '--plain']
        if retry:
            second = asdict(auth)
            second['id'] = 'review-2'
            second['evidence_refs'] = ['review:2']
            self.write('second', second)
            args += ['--retry-authorization', str(self.base / 'second.json')]
        return args

    def write(self, name, value):
        (self.base / (name + '.json')).write_text(json.dumps(value), encoding='utf-8')

    def invoke(self, args):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            result = managed.main(args)
        return result, out.getvalue()

    def test_real_diff_uses_existing_path_and_retains_separate_acceptance(self):
        code, text = self.invoke(self.inputs())
        self.assertEqual(code, 0, text)
        summary = json.loads((self.evidence / 'summary.json').read_text())
        self.assertEqual(summary['g3']['attempts'], 1)
        self.assertEqual(summary['task']['state'], 'COMPLETE')
        self.assertEqual(summary['acceptance']['status'], 'NOT_EVALUATED')
        self.assertEqual((self.root / 'owned/source.txt').read_text(), 'original')

    def test_real_authorized_edit_is_single_attempt(self):
        code, text = self.invoke(self.inputs(edit=True))
        self.assertEqual(code, 0, text)
        self.assertEqual((self.root / 'owned/source.txt').read_text(), 'reviewed')

    def test_missing_and_invalid_budgets_do_not_create_evidence(self):
        args = self.inputs()
        index = args.index('--budget')
        code, text = self.invoke(args[:index] + args[index+2:])
        self.assertEqual(code, 1, text)
        for value in ({}, {'total_timeout_seconds': 0}, {'total_timeout_seconds': 301}):
            self.write('budget', value)
            self.assertEqual(self.invoke(args)[0], 1)
        self.assertFalse(self.evidence.exists())

    def test_guard_denial_has_no_dispatch_or_evidence_directory(self):
        args = self.inputs()
        auth = json.loads((self.base / 'authorization.json').read_text())
        auth['source_identity'] = 'stale'
        self.write('authorization', auth)
        code, text = self.invoke(args)
        self.assertEqual(code, 1)
        self.assertIn('STALE_AUTHORIZATION', text)
        self.assertFalse(self.evidence.exists())

    def test_actual_spawn_transient_retries_with_new_authorization(self):
        args = self.inputs(retry=True)
        original = subprocess.Popen
        calls = []
        def spawn(argv, *a, **kw):
            if tuple(argv) == self.operation.argv:
                calls.append(tuple(argv))
                if len(calls) == 1:
                    raise OSError(errno.EAGAIN, 'synthetic transient before spawn')
            return original(argv, *a, **kw)
        with patch('subprocess.Popen', side_effect=spawn):
            code, text = self.invoke(args)
        self.assertEqual(code, 0, text)
        self.assertEqual(len(calls), 2)
        self.assertEqual(json.loads((self.evidence / 'summary.json').read_text())['g3']['attempts'], 2)

    def test_reused_retry_authorization_is_blocked(self):
        args = self.inputs(retry=True)
        self.write('second', json.loads((self.base / 'authorization.json').read_text()))
        original = subprocess.Popen
        calls = []
        def spawn(argv, *a, **kw):
            if tuple(argv) == self.operation.argv:
                calls.append(tuple(argv))
                raise OSError(errno.EAGAIN, 'synthetic transient before spawn')
            return original(argv, *a, **kw)
        with patch('subprocess.Popen', side_effect=spawn):
            code, text = self.invoke(args)
        self.assertEqual(code, 1)
        self.assertIn('G3_FRESH_AUTHORIZATION', text)
        self.assertEqual(len(calls), 1)
        summary = json.loads((self.evidence / 'summary.json').read_text())
        self.assertEqual(summary['dispatch_decision']['status'], 'BLOCK')

    def test_summary_storage_failure_cannot_report_success(self):
        args = self.inputs()
        original = Path.write_text
        def write(path, *a, **kw):
            if path == self.evidence / 'summary.json':
                raise OSError('synthetic evidence failure')
            return original(path, *a, **kw)
        with patch.object(Path, 'write_text', write):
            code, text = self.invoke(args)
        self.assertEqual(code, 1)
        self.assertNotIn('"status": "PASS"', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
