"""Persistent files and fresh object simulate reboot; no root, real systemd or reboot."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import durable_recovery as durable
import l2_upgrade as upgrade
import test_l2_upgrade as fixtures

class DurableTests(unittest.TestCase):
    def setup_fixture(self, folder):
        root=Path(folder);stage=root/'staging'/('reliability-'+'a'*16);stage.mkdir(parents=True)
        recovery=root/'recovery';recovery.mkdir();(recovery/'multi-user.target.wants').mkdir()
        obj,engine,helper,other=fixtures.L2UpgradeTests().fixture(root)
        obj.stage=stage;obj.assert_recovery_owner=upgrade.L2Upgrade.assert_recovery_owner.__get__(obj)
        obj.disarm_recovery=upgrade.L2Upgrade.disarm_recovery.__get__(obj)
        for name,data in [('l2-manifest.json',json.dumps(obj.manifest).encode()),('baseline.json',b'{}'),('l2_upgrade.py',b'fixture'),('durable_recovery.py',Path(durable.__file__).read_bytes())]:(stage/name).write_bytes(data)
        pending=dict(identity='a'*64,stage=str(stage),manifestSha256=upgrade.sha(stage/'l2-manifest.json'),baselineSha256=upgrade.sha(stage/'baseline.json'),installerSha256=upgrade.sha(stage/'l2_upgrade.py'))
        return obj,engine,helper,other,recovery,pending

    def patches(self,obj,engine,helper,recovery):
        from contextlib import ExitStack
        stack=ExitStack()
        for target,value in [('ROOT',recovery),('PENDING',recovery/'pending.json'),('STAGING',obj.stage.parent),('UNIT_PATH',recovery/'boot.service')]:stack.enter_context(patch.object(durable,target,value))
        stack.enter_context(patch.object(durable,'protected'));stack.enter_context(patch.object(upgrade,'protected'))
        stack.enter_context(patch.object(upgrade,'ENGINE_OVERRIDE',engine));stack.enter_context(patch.object(upgrade,'HELPER_UNIT',helper));stack.enter_context(patch.object(upgrade,'wait_ready'))
        return stack

    def arm(self,obj,pending):
        obj.receipt('mutating');upgrade.atomic_write(durable.PENDING,json.dumps(pending).encode(),0o600)

    def fresh(self,obj):
        new=upgrade.L2Upgrade(obj.stage,obj.manifest,obj.baseline);new.backup=obj.backup;new.release=obj.release
        new.old_engine_unchanged=lambda:True;new.preserved=lambda:True;new.invariants=lambda:True;new.collect=lambda left,candidate:{};new.run=lambda *args:None
        return new

    def test_reboot_before_after_switch_and_during_rollback_resumes_exactly(self):
        for interruption in ('prepared','before-switch','after-switch','during-rollback'):
            with self.subTest(interruption=interruption),tempfile.TemporaryDirectory() as folder:
                obj,engine,helper,other,recovery,pending=self.setup_fixture(folder)
                with self.patches(obj,engine,helper,recovery):
                    originals=(engine.read_bytes(),helper.read_bytes());self.arm(obj,pending)
                    if interruption=='prepared':obj.receipt('prepared')
                    if interruption in ('after-switch','during-rollback'):
                        upgrade.atomic_write(engine,obj.engine_content());upgrade.atomic_write(helper,obj.helper_content());obj.receipt('mutating')
                    if interruption=='during-rollback':upgrade.atomic_write(engine,originals[0])
                    self.assertEqual(durable.read_pending(),pending)
                    cmd=durable.command(pending);self.assertEqual(cmd[-1],'--watchdog')
                    boot=self.fresh(obj);boot.watchdog()
                    self.assertEqual((engine.read_bytes(),helper.read_bytes()),originals)
                    self.assertEqual(other.read_bytes(),b'untouched monitor');self.assertFalse(durable.PENDING.exists())
                    boot.watchdog() # duplicate terminal invocation is harmless

    def test_corrupt_missing_pins_duplicate_fields_and_newer_owner_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            obj,engine,helper,other,recovery,pending=self.setup_fixture(folder)
            with self.patches(obj,engine,helper,recovery):
                obj.run=lambda *args:self.fail('Unexpected service mutation')
                with self.assertRaises(FileNotFoundError):durable.read_pending()
                for change in (dict(stage='/tmp/untrusted'),dict(identity='b'*64),dict(installerSha256='0'*64),dict(extra=1)):
                    upgrade.atomic_write(durable.PENDING,json.dumps(pending|change).encode(),0o600)
                    with self.assertRaises(RuntimeError):durable.read_pending()
                upgrade.atomic_write(durable.PENDING,b'{"identity":"x","identity":"y"}',0o600)
                with self.assertRaises(RuntimeError):durable.read_pending()
                self.arm(obj,pending);durable.PENDING.unlink()
                upgrade.atomic_write(recovery/'latest.json',json.dumps(dict(identity='b'*64,phase='committed')).encode())
                with self.assertRaises(RuntimeError):obj.rollback()

    def test_install_durable_consumer_precedes_switch_and_refuses_unknown_unit(self):
        with tempfile.TemporaryDirectory() as folder:
            obj,engine,helper,other,recovery,pending=self.setup_fixture(folder)
            with self.patches(obj,engine,helper,recovery):
                commands=[];obj.run=lambda *args:commands.append(args)
                def output(*args):
                    if 'is-enabled' in args:return 'enabled'
                    values={'DropInPaths':'','User':'root','Type':'oneshot','TimeoutStartUSec':'10min 50s','Restart':'on-failure',
                            'NoNewPrivileges':'yes','CapabilityBoundingSet':'cap_dac_read_search','AmbientCapabilities':'cap_dac_read_search','ProtectSystem':'strict',
                            'ProtectHome':'read-only','PrivateTmp':'yes','NeedDaemonReload':'no','FragmentPath':str(durable.UNIT_PATH)}
                    key=args[args.index('-p')+1]
                    return values[key] if key in values else '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B /var/lib/hostsguardian-deployment/recovery/consumer.py ; ignore_errors=no ; }'
                obj.output=output
                obj.receipt('prepared')
                for key,value in [('User','nobody'),('DropInPaths','/foreign/override.conf'),('TimeoutStartUSec','infinity')]:
                    obj.output=lambda *args,k=key,v=value:v if '-p' in args and args[args.index('-p')+1]==k else output(*args)
                    with self.assertRaises(RuntimeError):obj.install_boot_recovery()
                    self.assertFalse(durable.PENDING.exists())
                obj.output=output;obj.install_boot_recovery()
                self.assertEqual(durable.read_pending(),pending)
                self.assertIn(('systemctl','enable','hostsguardian-deployment-recovery.service'),commands)
                self.assertFalse(any('stop' in c for c in commands))
                with self.assertRaises(RuntimeError):obj.install_boot_recovery() # concurrent attempt
                obj.disarm_recovery();durable.UNIT_PATH.write_bytes(b'foreign unit')
                with self.assertRaises(RuntimeError):obj.install_boot_recovery()

    def test_acceptance_disarms_only_terminal_and_boot_consumer_execs_pinned_installer(self):
        with tempfile.TemporaryDirectory() as folder:
            obj,engine,helper,other,recovery,pending=self.setup_fixture(folder)
            with self.patches(obj,engine,helper,recovery):
                self.arm(obj,pending)
                with self.assertRaises(RuntimeError):obj.disarm_recovery()
                with patch.object(durable.os,'geteuid',return_value=0,create=True),patch.object(durable.os,'execv') as execute:
                    durable.main();execute.assert_called_once_with('/usr/bin/python3',durable.command(pending))
                obj.receipt('committed');obj.disarm_recovery()
                with patch.object(durable.os,'geteuid',return_value=0,create=True),patch.object(durable.os,'execv') as execute:
                    durable.main();execute.assert_not_called()
                self.assertEqual(json.loads((recovery/'latest.json').read_text())['phase'],'committed')

    def test_reboot_failure_attempt_budget_survives_objects(self):
        with tempfile.TemporaryDirectory() as folder:
            obj,engine,helper,other,recovery,pending=self.setup_fixture(folder)
            with self.patches(obj,engine,helper,recovery):
                self.arm(obj,pending);calls=[]
                for _ in range(4):
                    boot=self.fresh(obj)
                    def fail():calls.append(1);raise RuntimeError('fixture recovery failed')
                    boot.rollback=fail
                    with self.assertRaises(RuntimeError):boot.watchdog()
                self.assertEqual(len(calls),3);self.assertTrue(durable.PENDING.exists())
                state=json.loads((obj.backup/'transaction.json').read_text())
                self.assertEqual(state['watchdogStatus'],'EXHAUSTED_REQUIRES_HUMAN')

if __name__=='__main__':unittest.main()
