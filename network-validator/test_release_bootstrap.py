"""Unprivileged fixtures only. No real systemd/installer execution."""
import hashlib,io,tarfile,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from release_bootstrap import render

class BootstrapTests(unittest.TestCase):
    def test_transfer_location_is_portable_and_rejects_path_escape(self):
        pins=dict(archive='candidate.tar.gz',archiveSha256='a'*64,attempt='a'*16,
                  manifestSha256='b'*64,baselineSha256='c'*64)
        for directory in (None,'/srv/hostsguardian-transfer'):
            configured=dict(pins)
            if directory is not None:configured['transferDirectory']=directory
            module=types.ModuleType('fixture');exec(render(configured,['payload']),module.__dict__)
            self.assertEqual(module.ARCHIVE.as_posix(),
                             (directory or '/var/tmp/hostsguardian-transfer')+'/candidate.tar.gz')
        for patch_values in ({'transferDirectory':'relative'}, {'transferDirectory':'/srv/../private'},
                             {'archive':'../candidate.tar.gz'}, {'archive':'/candidate.tar.gz'}):
            with self.subTest(values=patch_values),self.assertRaises(ValueError):
                render(dict(pins,**patch_values),['payload'])

    def test_pid1_worker_has_independent_runtime_no_parent_kill_timeout(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);archive=root/'candidate.tar.gz'
            with tarfile.open(archive,'w:gz') as t:
                info=tarfile.TarInfo('payload');info.size=1;info.mode=0o600;t.addfile(info,io.BytesIO(b'x'))
            pins=dict(archive=archive.name,archiveSha256=hashlib.sha256(archive.read_bytes()).hexdigest(),attempt='a'*16,manifestSha256='b'*64,baselineSha256='c'*64)
            module=types.ModuleType('fixture');exec(render(pins,['payload']),module.__dict__)
            module.ARCHIVE=archive;module.STAGE=root/'stage'
            with patch.object(module,'protected'),patch.object(module.os,'geteuid',return_value=0,create=True),patch.object(module.subprocess,'run') as run:
                module.main();args=run.call_args.args[0]
                self.assertEqual(args[0],'systemd-run');self.assertIn('--property=RuntimeMaxSec=900s',args)
                self.assertIn('--property=KillMode=control-group',args);self.assertNotIn('timeout',run.call_args.kwargs)
                self.assertIn('--apply',args)
            with patch.object(module,'protected'),patch.object(module.os,'geteuid',return_value=0,create=True),patch.object(module.subprocess,'run') as run:
                with self.assertRaises(RuntimeError):module.main()
                run.assert_not_called()
