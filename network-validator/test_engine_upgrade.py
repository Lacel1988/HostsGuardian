import json
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import engine_upgrade as upgrade


class EngineOnlyTests(unittest.TestCase):
    def operation(self,root):
        obj=upgrade.EngineUpgrade(root,dict(sourceIdentity='a'*64,sourceCommit='b'*40),{})
        obj.backup=root/'backup';obj.backup.mkdir();obj.release=root/'release'
        obj.stable_components=lambda:True;obj.old_engine_unchanged=lambda:True
        obj.collect=lambda remaining,candidate: {'candidate':candidate}
        return obj

    def test_activate_off_only_changes_engine_and_rollback_restores_original_unit_layout(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);obj=self.operation(root);dropin=root/'override';commands=[]
            obj.run=lambda *args:commands.append(args)
            with patch.object(upgrade,'UPGRADE_DROPIN',dropin),patch.object(upgrade,'wait_ready') as ready:
                obj.activate();content=dropin.read_text()
                self.assertIn('HOSTSGUARDIAN_ACTIVE_VALIDATION=0',content)
                self.assertIn('HOSTSGUARDIAN_ACTIVE_VALIDATION_DEVICE_IDS=\n',content)
                self.assertNotIn('CAP_NET_RAW',content)
                self.assertEqual(ready.call_args.args[2],'candidate')
                obj.rollback();self.assertFalse(dropin.exists())
                self.assertEqual(ready.call_args.args[2],'rollback')
            self.assertTrue(all(upgrade.HELPER not in c and upgrade.SOCKET not in c and 'dpkg' not in c for c in commands))
            self.assertEqual(commands,[('systemctl','stop',upgrade.UNIT),('systemctl','daemon-reload'),('systemctl','start',upgrade.UNIT)]*2)

    def test_partial_write_reload_start_and_readiness_failures_remain_rollback_owned(self):
        for failure in ('write','daemon-reload','start','readiness'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);obj=self.operation(root);dropin=root/'override'
                def run(*args):
                    if args[1]==failure:raise RuntimeError('fixture failure')
                obj.run=run
                with patch.object(upgrade,'UPGRADE_DROPIN',dropin),patch.object(upgrade,'wait_ready',side_effect=RuntimeError('readiness') if failure=='readiness' else None):
                    if failure=='write':
                        with patch.object(Path,'write_bytes',side_effect=RuntimeError('partial write')):
                            with self.assertRaises(RuntimeError):obj.activate()
                    else:
                        with self.assertRaises(RuntimeError):obj.activate()
                    self.assertTrue(obj.touched)
                    obj.run=lambda *args:None
                    with patch.object(upgrade,'wait_ready'):obj.rollback()
                    self.assertFalse(dropin.exists())

    def test_rollback_failure_never_writes_success_marker(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);obj=self.operation(root);obj.run=lambda *args:None
            with patch.object(upgrade,'wait_ready',side_effect=RuntimeError('DNS rollback failure')):
                with self.assertRaises(RuntimeError):obj.rollback()
            self.assertFalse((obj.backup/'rollback-result.json').exists())

    def test_preparation_failure_does_not_call_activate(self):
        with tempfile.TemporaryDirectory() as folder:
            obj=self.operation(Path(folder));obj.preflight=lambda:None
            obj.prepare=lambda:(_ for _ in ()).throw(RuntimeError('payload integrity'))
            obj.activate=lambda:self.fail('Engine touched before integrity')
            with self.assertRaises(RuntimeError):obj.apply()
            self.assertFalse(obj.changed)

    def test_modified_original_publication_refuses_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            obj=self.operation(Path(folder));obj.old_engine_unchanged=lambda:False
            obj.run=lambda *args:self.fail('Altered original executed')
            with self.assertRaises(RuntimeError):obj.rollback()

    def test_existing_helper_and_monitor_are_preservation_checks_only(self):
        with tempfile.TemporaryDirectory() as folder:
            obj=self.operation(Path(folder));obj.baseline=dict(helperFiles={},helperPid=99,monitorVersion='fixture')
            obj.preserved=lambda:True;commands=[]
            def output(*args,**kwargs):
                commands.append(args)
                if args[1]=='is-enabled':return 'enabled'
                if args[0]=='dpkg-query':return 'fixture'
                return '99' if 'MainPID' in args else 'active'
            obj.output=output
            self.assertTrue(upgrade.EngineUpgrade.stable_components(obj))
            self.assertTrue(all(c[0] in ('systemctl','dpkg-query') for c in commands))
            self.assertFalse(any(any(x in c for x in ('stop','start','disable','enable','restart','--install')) for c in commands))

    def test_authenticated_policy_readback_must_match_exact_registered_semantics(self):
        for changed in (False,True):
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);obj=self.operation(root);token=root/'token';token.write_text('fixture-not-secret')
                policy={'devices':[{'deviceId':'a'}],'globalBlockedDomains':[],'overrides':[]}
                obj.baseline=dict(certificatePath='/fixture/cert',credentialPath=str(token),managementUrl='https://fixture.invalid/dns/status',policyRevision=23,
                    canonicalPolicySha256=hashlib.sha256(json.dumps(policy,sort_keys=True,separators=(',',':')).encode()).hexdigest(),registrationIds=['a'])
                obj.stable_components=lambda *args:True
                response=io.StringIO(json.dumps(dict(revision=23,policy=policy if not changed else {**policy,'devices':[]})))
                from types import SimpleNamespace
                base=dict(preservation=True,helper=True,validator=dict(mode='Passive',approvedTargetCount=0,modeReason='Disabled'))
                with patch.object(upgrade.Deployment,'collect',return_value=base),patch.object(upgrade.ssl,'create_default_context'),patch.object(upgrade.urllib.request,'build_opener',return_value=SimpleNamespace(open=lambda *a,**k:response)):
                    result=upgrade.EngineUpgrade.collect(obj,5,True)
                self.assertEqual(result['preservation'],not changed)
                self.assertNotIn('fixture-not-secret',json.dumps(result))

    def test_repeat_upgrade_and_partial_failure_restore_exact_bytes(self):
        for fail in (False,True):
            with self.subTest(fail=fail),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);obj=self.operation(root);dropin=root/'override'
                original=b'[Service]\n# baseline\nExecStart=\nExecStart=/old\nWorkingDirectory=/old\nEnvironment=EXTRA=kept\n'
                dropin.write_bytes(original);dropin.chmod(0o644)
                obj.baseline={'unitFiles':{str(dropin):hashlib.sha256(original).hexdigest()}}
                obj.run=lambda *args:None
                with patch.object(upgrade,'UPGRADE_DROPIN',dropin),patch.object(upgrade,'protected'),patch.object(upgrade.stat,'S_IMODE',return_value=0o644),patch.object(upgrade,'wait_ready'):
                    obj.save_override()
                    if fail:
                        with patch.object(Path,'write_bytes',side_effect=RuntimeError('partial write')):
                            with self.assertRaises(RuntimeError):obj.activate()
                    else:
                        obj.activate();self.assertIn(b'Environment=EXTRA=kept',dropin.read_bytes())
                    obj.rollback();self.assertEqual(dropin.read_bytes(),original)
                    if __import__('os').name!='nt':self.assertEqual(dropin.stat().st_mode & 0o777,0o644)

    def test_changed_override_or_saved_backup_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);obj=self.operation(root);dropin=root/'override';dropin.write_bytes(b'[Service]\nExecStart=\nExecStart=/old\nWorkingDirectory=/old\n')
            obj.baseline={'unitFiles':{str(dropin):hashlib.sha256(dropin.read_bytes()).hexdigest()}}
            with patch.object(upgrade,'UPGRADE_DROPIN',dropin),patch.object(upgrade,'protected'),patch.object(upgrade.stat,'S_IMODE',return_value=0o644):
                obj.save_override();(obj.backup/'engine-override.original').write_bytes(b'corrupt')
                with self.assertRaises(RuntimeError):obj.restore_override()
                dropin.write_bytes(b'unreviewed')
                with self.assertRaises(RuntimeError):obj.save_override()

    def test_preservation_accepts_only_exact_attempt_override(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);obj=self.operation(root);dropin=root/'override';dropin.write_bytes(b'[Service]\nExecStart=\nExecStart=/old\nWorkingDirectory=/old\n')
            policy=root/'policy';policy.write_bytes(b'policy')
            obj.baseline={'unitFiles':{str(dropin):hashlib.sha256(dropin.read_bytes()).hexdigest()},'policyPath':str(policy),'policySha256':hashlib.sha256(b'policy').hexdigest(),'securityFiles':{}}
            with patch.object(upgrade,'UPGRADE_DROPIN',dropin):
                self.assertTrue(obj.preserved());(obj.backup/'engine-override.original').write_bytes(dropin.read_bytes());obj.touched=True;dropin.write_bytes(obj.override_content());self.assertTrue(obj.preserved())
                dropin.write_bytes(b'unrelated');self.assertFalse(obj.preserved())

    def test_manual_retry_retains_failed_rollback_readiness_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            obj=self.operation(Path(folder));obj.run=lambda *a:None
            previous=obj.backup/'rollback-readiness.jsonl';previous.write_text('original failure evidence')
            with patch.object(upgrade,'wait_ready') as ready:
                obj.rollback()
                new=ready.call_args.args[1]
            self.assertNotEqual(new,obj.backup);self.assertTrue(new.is_dir())
            self.assertEqual(previous.read_text(),'original failure evidence')
            self.assertEqual(json.loads((obj.backup/'rollback-result.json').read_text())['readinessDirectory'],str(new))
