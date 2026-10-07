"""Packaging regressions use temporary files; never install or operate services."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from build_monitor_package import validate_linux_script, copy_package_file, validate_staging, smoke_launcher


class PackagingTests(unittest.TestCase):
    def test_source_launcher_rules_and_git_attributes_require_lf(self):
        root=Path(__file__).parent
        for path in (root/'packaging/hostsguardian-monitor',root/'debian/rules'):
            validate_linux_script(path.read_bytes());self.assertNotIn(b'\r',path.read_bytes())
        attrs=(root.parent/'.gitattributes').read_text()
        self.assertIn('linux-monitor/packaging/* text eol=lf',attrs)
        self.assertIn('linux-monitor/debian/rules text eol=lf',attrs)

    def test_crlf_bom_missing_newline_and_relative_shebang_are_rejected(self):
        for data in (b'#!/usr/bin/python3\r\nprint(1)\r\n',b'#!/usr/bin/python3\nprint(1)\r\n',
                     b'\xef\xbb\xbf#!/usr/bin/python3\n',b'#!/usr/bin/python3',b'#!python3\n',b'print(1)\n'):
            with self.subTest(data=data),self.assertRaises(ValueError):validate_linux_script(data)
        validate_linux_script(b'#!/usr/bin/python3\nprint(1)\n')

    def test_executable_copy_rejects_bad_bytes_before_writing_package(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'source';target=root/'package/usr/bin/launcher'
            source.write_bytes(b'#!/usr/bin/python3\r\n')
            with self.assertRaises(ValueError):copy_package_file(source,target,executable=True)
            self.assertFalse(target.exists())
            source.write_bytes(b'#!/usr/bin/python3\n')
            copy_package_file(source,target,executable=True)
            self.assertEqual(target.read_bytes(),source.read_bytes())

    def test_smoke_calls_executable_directly_never_python_bypass(self):
        path=Path('/fixture/usr/bin/hostsguardian-monitor').resolve()
        evidence=dict(status='MONITOR_LAUNCH_SMOKE_PASS',uid=1000,launcher=str(path),
                      library=str(path.parents[1]/'lib/hostsguardian-monitor'),applicationStarted=False,
                      serviceActions=False,cairo=True,topology=True)
        with patch('build_monitor_package.subprocess.run',return_value=subprocess.CompletedProcess([],0,json.dumps(evidence),'')) as run:
            self.assertEqual(smoke_launcher(path),evidence)
            self.assertEqual(run.call_args.args[0],[str(path),'--smoke-check'])
        evidence['serviceActions']=True
        with patch('build_monitor_package.subprocess.run',return_value=subprocess.CompletedProcess([],0,json.dumps(evidence),'')):
            with self.assertRaises(ValueError):smoke_launcher(path)

    @unittest.skipUnless(os.name=='posix','Linux kernel shebang execution required')
    def test_direct_execution_detects_actual_crlf_kernel_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            launcher=Path(folder)/'launcher';launcher.write_bytes(b'#!/usr/bin/python3\r\nprint(1)\r\n');launcher.chmod(0o755)
            with self.assertRaises(FileNotFoundError):smoke_launcher(launcher)

    @unittest.skipUnless(os.name=='posix','Linux normal-user execution required')
    def test_smoke_does_not_construct_app_or_operate_service(self):
        with tempfile.TemporaryDirectory() as folder:
            prefix=Path(folder)/'usr';library=prefix/'lib/hostsguardian-monitor';library.mkdir(parents=True)
            # If app construction is attempted the child process must fail.
            (library/'monitor.py').write_text('class Monitor:\n def __init__(self): raise RuntimeError("no app construction")\n')
            (library/'gi.py').write_text('def require_foreign(name): pass\n')
            (library/'cairo.py').write_text('')
            (library/'topology_ui.py').write_text('CAIRO_AVAILABLE=True\n')
            launcher=prefix/'bin/hostsguardian-monitor'
            copy_package_file(Path(__file__).parent/'packaging/hostsguardian-monitor',launcher,True)
            value=smoke_launcher(launcher);self.assertFalse(value['applicationStarted']);self.assertFalse(value['serviceActions'])
            (library/'topology_ui.py').write_text('CAIRO_AVAILABLE=False\n')
            with self.assertRaises(subprocess.CalledProcessError):smoke_launcher(launcher)

    @unittest.skipUnless(os.name=='posix','POSIX executable modes required')
    def test_staging_rejects_non_executable_launcher_and_other_crlf_script(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);launcher=root/'usr/bin/hostsguardian-monitor'
            copy_package_file(Path(__file__).parent/'packaging/hostsguardian-monitor',launcher,True)
            validate_staging(root)
            launcher.chmod(0o644)
            with self.assertRaises(ValueError):validate_staging(root)
            launcher.chmod(0o755);other=root/'usr/bin/other';other.write_bytes(b'#!/bin/sh\r\n');other.chmod(0o755)
            with self.assertRaises(ValueError):validate_staging(root)