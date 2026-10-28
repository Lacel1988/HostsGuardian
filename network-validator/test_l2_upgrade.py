"""Isolated file transactions and mocked systemd only; never deployment."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import l2_upgrade as upgrade


class L2UpgradeTests(unittest.TestCase):
    def setUp(self):
        isolated=tempfile.TemporaryDirectory();self.addCleanup(isolated.cleanup)
        root=Path(isolated.name)/'recovery';root.mkdir()
        for name,value in [('ROOT',root),('PENDING',root/'pending.json')]:
            replacement=patch.object(upgrade.durable,name,value);replacement.start();self.addCleanup(replacement.stop)

    def fixture(self,root):
        engine=root/'engine.conf';helper=root/'helper.service';other=root/'monitor.conf'
        original=b'[Service]\nExecStart=\nExecStart=/old/engine\nWorkingDirectory=/old\nEnvironment=HOSTSGUARDIAN_ACTIVE_VALIDATION=0\nEnvironment=HOSTSGUARDIAN_ACTIVE_VALIDATION_DEVICE_IDS=\nEnvironment=HOSTSGUARDIAN_ACTIVE_VALIDATION_SECONDS=\n'
        helper_bytes=b'[Service]\nUser=fixture\nExecStart=/usr/bin/python3 -I -B /old/helper.py --socket /run/hostsguardian-validator/validator.sock --interface fixture0 --engine-uid 1000 --engine-executable /old/engine\nAmbientCapabilities=CAP_NET_RAW\nCapabilityBoundingSet=CAP_NET_RAW\nNoNewPrivileges=yes\n'
        engine.write_bytes(original);helper.write_bytes(helper_bytes);other.write_bytes(b'untouched monitor')
        baseline={'unitFiles':{str(p):upgrade.sha(p) for p in (engine,helper,other)},'helperScript':'/old/helper.py','helperProtectedExecutable':'/old/engine','allowedInterface':'fixture0','engineUid':1000}
        obj=upgrade.L2Upgrade(root,{'sourceIdentity':'a'*64,'sourceCommit':'b'*40},baseline)
        obj.backup=root/'backup';obj.backup.mkdir();obj.release=root/'candidate'
        (obj.backup/'engine-override.original').write_bytes(original);(obj.backup/'helper-unit.original').write_bytes(helper_bytes)
        obj.old_engine_unchanged=lambda:True;obj.preserved=lambda:True;obj.invariants=lambda:True;obj.collect=lambda remaining,candidate:{'candidate':candidate}
        obj.arm_watchdog=lambda:None
        obj.assert_recovery_owner=lambda:None;obj.disarm_recovery=lambda:None
        return obj,engine,helper,other

    def test_selectors_change_only_execution_and_receive_only_optins(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'):
            obj,engine,helper,other=self.fixture(Path(folder))
            with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper):
                result=obj.helper_content().decode();original=helper.read_text()
                self.assertEqual([line for line in result.splitlines() if not line.startswith('ExecStart=')],[line for line in original.splitlines() if not line.startswith('ExecStart=')])
                self.assertIn('--passive-dns',result);self.assertNotIn('CAP_NET_ADMIN',result)
                content=obj.engine_content().decode();self.assertIn('HOSTSGUARDIAN_ACTIVE_VALIDATION=0',content);self.assertIn('HOSTSGUARDIAN_PASSIVE_DNS_L2=1',content)
                self.assertNotIn('CAP_NET_RAW',content);self.assertEqual(other.read_bytes(),b'untouched monitor')

    def test_successful_transaction_and_exact_rollback_preserve_other_units(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'),patch.object(upgrade,'wait_ready'):
            obj,engine,helper,other=self.fixture(Path(folder));old=(engine.read_bytes(),helper.read_bytes());commands=[]
            obj.preflight=lambda:None;obj.prepare=lambda:None;obj.run=lambda *args:commands.append(args)
            with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper):
                obj.apply();self.assertTrue(obj.changed and obj.touched);obj.rollback()
                self.assertEqual((engine.read_bytes(),helper.read_bytes()),old)
                self.assertEqual(other.read_bytes(),b'untouched monitor');self.assertFalse(obj.touched)
                self.assertEqual(json.loads((obj.backup/'rollback-result.json').read_text())['status'],'ROLLBACK_VERIFIED')
            self.assertFalse(any(upgrade.SOCKET in command or 'dpkg' in command or 'setcap' in command for command in commands))
            self.assertEqual(commands.count(('systemctl','daemon-reload')),2)

    def test_stop_write_reload_start_and_readiness_failures_are_rollback_owned(self):
        for failure in ('stop','write','daemon-reload','start','readiness'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'):
                obj,engine,helper,_=self.fixture(Path(folder));old=(engine.read_bytes(),helper.read_bytes())
                obj.preflight=lambda:None;obj.prepare=lambda:None
                def run(*args):
                    if args[1]==failure:raise RuntimeError('fixture failure')
                obj.run=run
                with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper),patch.object(upgrade,'wait_ready',side_effect=RuntimeError('readiness') if failure=='readiness' else None):
                    if failure=='write':
                        original_write=upgrade.atomic_write
                        def fail_selector(path,data,mode=0o644):
                            if path==engine:raise RuntimeError('selector publication failure')
                            return original_write(path,data,mode)
                        with patch.object(upgrade,'atomic_write',side_effect=fail_selector):
                            with self.assertRaises(RuntimeError):obj.apply()
                    else:
                        with self.assertRaises(RuntimeError):obj.apply()
                    self.assertTrue(obj.changed)
                    obj.run=lambda *args:None
                    with patch.object(upgrade,'wait_ready'):obj.rollback()
                    self.assertEqual((engine.read_bytes(),helper.read_bytes()),old)

    def test_receipt_owned_truncation_missing_and_conflicting_selector(self):
        for state in ('truncated','empty','missing','malformed','conflicting','symlink'):
            with self.subTest(state=state),tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'):
                obj,engine,helper,other=self.fixture(Path(folder))
                with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper):
                    obj.receipt('mutating');original=obj.original(engine)
                    if state=='missing':engine.unlink()
                    elif state=='symlink':
                        # A replacement inode is not owned by the receipt even when bytes resemble ours.
                        engine.unlink();engine.write_bytes(original[:10])
                        receipt=json.loads((obj.backup/'transaction.json').read_text());receipt['targets'][str(engine)]['inode']=[-1,-1]
                        (obj.backup/'transaction.json').write_text(json.dumps(receipt))
                    else:engine.write_bytes(original[:20] if state=='truncated' else b'' if state=='empty' else b'unrelated override')
                    if state in ('malformed','conflicting','symlink'):
                        with self.assertRaises(RuntimeError):obj.validate_restore_targets()
                    else:obj.validate_restore_targets()
                    self.assertEqual(other.read_bytes(),b'untouched monitor')

    def test_atomic_publication_failure_preserves_bytes_and_removes_temp(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'selector';path.write_bytes(b'original')
            with patch.object(upgrade.os,'replace',side_effect=OSError('interrupted')):
                with self.assertRaises(OSError):upgrade.atomic_write(path,b'candidate')
            self.assertEqual(path.read_bytes(),b'original');self.assertEqual(len(list(Path(folder).iterdir())),1)

    def test_watchdog_has_durable_total_attempt_limit_and_preserves_ownership(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'):
            obj,engine,helper,_=self.fixture(Path(folder));calls=[]
            with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper):
                obj.receipt('mutating');path=obj.backup/'transaction.json'
                targets=json.loads(path.read_text())['targets']
                def fail():
                    calls.append(1)
                    if len(calls)==3:
                        self.assertEqual(json.loads(path.read_text())['watchdogStatus'],'FINAL_ATTEMPT_REQUIRES_HUMAN_UNLESS_VERIFIED')
                    raise RuntimeError('fixture rollback failure')
                obj.rollback=fail
                for _ in range(4):
                    with self.assertRaises(RuntimeError):obj.watchdog()
                state=json.loads(path.read_text())
                self.assertEqual(len(calls),3);self.assertEqual(state['watchdogAttempts'],3)
                self.assertEqual(state['watchdogStatus'],'EXHAUSTED_REQUIRES_HUMAN')
                self.assertEqual(state['targets'],targets);self.assertIn('watchdogFailure',state)
                for phase in ('prepared','committed','rolledBack'):
                    obj.receipt(phase);obj.watchdog()
                self.assertEqual(len(calls),3)

    def test_unverified_watchdog_never_stops_engine_and_leaves_prepared_receipt(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'):
            obj,engine,helper,_=self.fixture(Path(folder));commands=[]
            obj.preflight=lambda:None;obj.prepare=lambda:None;obj.run=lambda *args:commands.append(args)
            def fail_guard():raise RuntimeError('unscheduled independent guard')
            obj.arm_watchdog=fail_guard
            with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper):
                with self.assertRaises(RuntimeError):obj.apply()
                self.assertFalse(obj.changed);self.assertEqual(commands,[])
                self.assertEqual(json.loads((obj.backup/'transaction.json').read_text())['phase'],'prepared')

    def test_corrupt_backup_refuses_rollback_before_stopping_services(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'):
            obj,engine,helper,_=self.fixture(Path(folder));(obj.backup/'helper-unit.original').write_bytes(b'corrupt')
            obj.run=lambda *args:self.fail('Stopped service before backup integrity check')
            with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper):
                with self.assertRaises(RuntimeError):obj.rollback()

    def test_rollback_timeout_never_reports_verified_and_retry_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'):
            obj,engine,helper,_=self.fixture(Path(folder));obj.run=lambda *args:None
            (obj.backup/'rollback-readiness.jsonl').write_bytes(b'first attempt evidence')
            with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper),patch.object(upgrade,'wait_ready',side_effect=RuntimeError('timeout')):
                with self.assertRaises(RuntimeError):obj.rollback()
                self.assertFalse((obj.backup/'rollback-result.json').exists())
                self.assertEqual((obj.backup/'rollback-readiness.jsonl').read_bytes(),b'first attempt evidence')
                self.assertEqual(len(list(obj.backup.glob('rollback-retry-*'))),1)

    def test_invalid_helper_scope_or_existing_l2_setting_refused(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'):
            obj,engine,helper,_=self.fixture(Path(folder))
            with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper):
                original=(obj.backup/'helper-unit.original').read_bytes();bad=original.replace(b'--interface fixture0',b'--interface other')
                (obj.backup/'helper-unit.original').write_bytes(bad);obj.baseline['unitFiles'][str(helper)]=hashlib.sha256(bad).hexdigest()
                with self.assertRaises(RuntimeError):obj.helper_content()
                bad=(obj.backup/'engine-override.original').read_bytes()+b'Environment=HOSTSGUARDIAN_PASSIVE_DNS_L2=0\n'
                (obj.backup/'engine-override.original').write_bytes(bad);obj.baseline['unitFiles'][str(engine)]=hashlib.sha256(bad).hexdigest()
                with self.assertRaises(RuntimeError):obj.engine_content()

    def test_repeat_upgrade_preserves_existing_passive_optin_and_exact_rollback(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(upgrade,'protected'):
            obj,engine,helper,_=self.fixture(Path(folder))
            with patch.object(upgrade,'ENGINE_OVERRIDE',engine),patch.object(upgrade,'HELPER_UNIT',helper):
                original=engine.read_bytes()+b'Environment=HOSTSGUARDIAN_PASSIVE_DNS_L2=1\n'
                engine.write_bytes(original);(obj.backup/'engine-override.original').write_bytes(original)
                obj.baseline['unitFiles'][str(engine)]=hashlib.sha256(original).hexdigest()
                old=helper.read_bytes().replace(b'--engine-executable /old/engine',b'--engine-executable /old/engine --passive-dns')
                helper.write_bytes(old);(obj.backup/'helper-unit.original').write_bytes(old)
                obj.baseline['unitFiles'][str(helper)]=hashlib.sha256(old).hexdigest()
                self.assertEqual(obj.engine_content().count(b'HOSTSGUARDIAN_PASSIVE_DNS_L2=1'),1)
                self.assertEqual(obj.helper_content().count(b'--passive-dns'),1)
                obj.run=lambda *args:None
                with patch.object(upgrade,'wait_ready'):obj.rollback()
                self.assertEqual(engine.read_bytes(),original);self.assertEqual(helper.read_bytes(),old)

    def test_prepare_failure_never_marks_runtime_changed(self):
        with tempfile.TemporaryDirectory() as folder:
            obj,_,_,_=self.fixture(Path(folder));obj.preflight=lambda:None
            obj.prepare=lambda:(_ for _ in ()).throw(RuntimeError('payload mismatch'));obj.run=lambda *args:self.fail('Runtime touched')
            with self.assertRaises(RuntimeError):obj.apply()
            self.assertFalse(obj.changed)


if __name__=='__main__':unittest.main()
