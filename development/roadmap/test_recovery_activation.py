import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import recovery_activation as activation


class ActivationTests(unittest.TestCase):
    def fixture(self, root):
        stage=root/'stage';stage.mkdir()
        (stage/'session.json').write_bytes(b'fixture session');(stage/'p0_policy_restore.py').write_bytes(b'fixture code')
        service=root/'fixture.service';timer=root/'fixture.timer'
        service.write_bytes(b'old service\r\n');timer.write_bytes(b'old timer\n')
        old_script=root/'previous.py';old_session=root/'previous.json'
        old_script.write_bytes(b'previous fixture');old_session.write_bytes(b'previous session')
        manifest=dict(attempt='a'*64,user='fixture',unit='fixture',intervalSeconds=90,
                      files={name:activation.digest(stage/name) for name in ('session.json','p0_policy_restore.py')},
                      previousFiles={path.name:activation.digest(path) for path in (service,timer)},
                      previousProperties={service.name:{'ExecStart':'{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B /old.py ; ignore_errors=no ; pid=1 ; }','User':'fixture','ProtectSystem':'strict'},timer.name:{'TimersMonotonic':'{ base=OnUnitInactiveUSec ; value=1min 30s ; next_elapse=190s ; }'}},
                      previousPayloadHashes={str(path):activation.digest(path) for path in (old_script,old_session)},
                      previousCheckCommand=['/usr/bin/python3','-I','-B',str(old_script),'--session',str(old_session),'--sha256',activation.digest(old_session),'--approved-recovery','--check-only'])
        (stage/'recovery-manifest.json').write_text(json.dumps(manifest))
        commands=[]
        def run(*args):
            commands.append(args)
            if args[0]=='runuser':return 'RECOVERY_PRECHECK_PASS'
            if 'is-active' in args:return 'active'
            if 'is-enabled' in args:return 'enabled'
            if 'NeedDaemonReload' in args:return 'no'
            if 'Result' in args:return 'success'
            if 'ExecMainStatus' in args:return '0'
            if 'NextElapseUSecMonotonic' in args:return '190s'
            if 'ProtectSystem' in args:return 'strict'
            if 'ExecStart' in args:return manifest['previousProperties'][service.name]['ExecStart']
            if 'TimersMonotonic' in args:return manifest['previousProperties'][timer.name]['TimersMonotonic']
            if 'User' in args:return 'fixture'
            return ''
        obj=activation.Activation(stage,manifest,run);obj.service=service;obj.timer=timer;obj.target=root/'new'
        return obj,commands

    def test_exact_single_pair_handover_no_engine_or_network_commands(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(activation,'protected'),patch.object(activation,'group_id',return_value=0),patch.object(activation.os,'chown',create=True),patch.object(Path,'read_text',return_value='100 0'):
            obj,commands=self.fixture(Path(folder));before=(obj.service.read_bytes(),obj.timer.read_bytes())
            obj.apply()
            self.assertEqual(sum(c==('systemctl','daemon-reload') for c in commands),1)
            guard=next(i for i,c in enumerate(commands) if c[0]=='systemd-run')
            stop=next(i for i,c in enumerate(commands) if c==('systemctl','stop','fixture.timer'))
            self.assertLess(guard,stop);self.assertIn('--rollback',commands[guard])
            self.assertIn('--property=Restart=on-failure',commands[guard])
            service=obj.service.read_text();data=obj.service.read_bytes().decode()
            self.assertIn('User=fixture',data);self.assertIn('ProtectSystem=strict',data);self.assertIn('CapabilityBoundingSet=\n',data)
            self.assertFalse(any('hostsguardian-engine.service' in c or c[0] in ('ip','nft','setcap') for c in commands))
            obj.rollback();self.assertEqual((obj.service.read_bytes(),obj.timer.read_bytes()),before)

    def test_failed_readiness_rolls_back_exact_bytes_and_retains_session(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(activation,'protected'),patch.object(activation,'group_id',return_value=0),patch.object(activation.os,'chown',create=True):
            obj,_=self.fixture(Path(folder));before=(obj.service.read_bytes(),obj.timer.read_bytes());run=obj.run
            def failing(*args):
                if 'Result' in args:return 'failed'
                return run(*args)
            obj.run=failing
            with patch.object(Path,'read_text',return_value='100 0'):
                with self.assertRaises(RuntimeError):obj.apply()
            self.assertEqual((obj.service.read_bytes(),obj.timer.read_bytes()),before)
            self.assertTrue((obj.target/'session.json').exists())

    def test_unscheduled_guard_aborts_before_stopping_previous_recovery(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(activation,'protected'),patch.object(activation,'group_id',return_value=0),patch.object(activation.os,'chown',create=True):
            obj,commands=self.fixture(Path(folder));run=obj.run
            obj.run=lambda *args:'infinity' if 'NextElapseUSecMonotonic' in args else run(*args)
            with self.assertRaises(RuntimeError):obj.apply()
            self.assertFalse(any(c==('systemctl','stop','fixture.timer') for c in commands))

    def test_payload_change_or_open_previous_session_aborts_before_unit_changes(self):
        for failure in ('hash','session'):
            with tempfile.TemporaryDirectory() as folder,patch.object(activation,'protected'):
                obj,commands=self.fixture(Path(folder))
                if failure=='hash':(obj.stage/'session.json').write_bytes(b'changed')
                else:
                    run=obj.run;obj.run=lambda *args:'NOT_ORIGINAL' if args[0]=='runuser' else run(*args)
                with self.assertRaises(RuntimeError):obj.preflight()
                self.assertFalse(any(c[:2]==('systemctl','stop') for c in commands));self.assertFalse(obj.target.exists())

    def test_corrupt_rollback_backup_refused_before_stopping_timer(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(activation,'protected'):
            obj,commands=self.fixture(Path(folder));obj.target.mkdir()
            (obj.target/'previous.service').write_bytes(b'corrupt');(obj.target/'previous.timer').write_bytes(obj.timer.read_bytes())
            with self.assertRaises(RuntimeError):obj.rollback()
            self.assertEqual(commands,[])

    def test_atomic_publication_failure_keeps_original_and_removes_temporary(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'unit.service';path.write_bytes(b'original\r\n')
            with patch.object(activation.os,'replace',side_effect=OSError('fixture failure')):
                with self.assertRaises(OSError):activation.atomic_unit(path,b'candidate\n')
            self.assertEqual(path.read_bytes(),b'original\r\n')
            self.assertEqual(list(Path(folder).iterdir()),[path])

    def test_second_unit_publication_failure_rolls_back_first(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(activation,'protected'),patch.object(activation,'group_id',return_value=0),patch.object(activation.os,'chown',create=True):
            obj,_=self.fixture(Path(folder));before=(obj.service.read_bytes(),obj.timer.read_bytes())
            real=activation.atomic_unit;calls=0
            def publish(path,data):
                nonlocal calls
                calls+=1
                if calls==2:raise OSError('fixture second publication failure')
                real(path,data)
            with patch.object(activation,'atomic_unit',side_effect=publish),patch.object(Path,'read_text',return_value='100 0'):
                with self.assertRaises(OSError):obj.apply()
            self.assertEqual((obj.service.read_bytes(),obj.timer.read_bytes()),before)

    def test_session_publication_is_exclusive_and_hash_matches_exact_bytes(self):
        from prepare_recovery_session import write_session
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'session.json'
            pin=write_session(path,{'approvedOverrides':[['fixture','example.invalid']]})
            self.assertEqual(pin,activation.digest(path))
            original=path.read_bytes()
            with self.assertRaises(FileExistsError):write_session(path,{'other':'session'})
            self.assertEqual(path.read_bytes(),original)

    def test_loaded_configuration_ignores_runtime_fields_but_rejects_definition_changes(self):
        key='ExecStart';first='{ path=/python ; argv[]=/python /old.py ; ignore_errors=no ; pid=1 ; start_time=[yesterday] ; }'
        second=first.replace('pid=1','pid=2').replace('yesterday','today')
        self.assertEqual(activation.loaded_configuration(key,first),activation.loaded_configuration(key,second))
        self.assertNotEqual(activation.loaded_configuration(key,first),activation.loaded_configuration(key,first.replace('/old.py','/other.py')))
        timer='{ base=OnUnitInactiveUSec ; value=1min 30s ; next_elapse=190s ; }'
        self.assertEqual(activation.loaded_configuration('TimersMonotonic',timer),activation.loaded_configuration('TimersMonotonic',timer.replace('190s','280s')))
        self.assertNotEqual(activation.loaded_configuration('TimersMonotonic',timer),activation.loaded_configuration('TimersMonotonic',timer.replace('1min 30s','3min')))

    def test_monotonic_next_is_absolute_boot_time_not_duration(self):
        self.assertAlmostEqual(activation.parse_monotonic('11h 40min 27.457164s'),42027.457164)
        self.assertEqual(activation.parse_monotonic('90s'),90)
        for invalid in ('infinity','0','','tomorrow','90'):
            with self.assertRaises(RuntimeError):activation.parse_monotonic(invalid)

    def test_actual_vivo_timer_format_and_strict_negative_cases(self):
        actual=Path(__file__).with_name('timer-vivo.fixture.txt').read_text(encoding='utf-8-sig')
        parsed=activation.loaded_configuration('TimersMonotonic',actual)
        self.assertEqual(len(parsed),3)
        self.assertEqual(parsed,activation.loaded_configuration('TimersMonotonic',actual.replace('2h 6min','3h 7min')))
        for invalid in ('garbage '+actual,actual+' trailing',actual+actual,
                        '{ OnActiveUSec=infinity ; next_elapse=1s }',
                        '{ OnActiveUSec='+('9'*400)+'s ; next_elapse=1s }',
                        '{ UnknownUSec=90s ; next_elapse=1s }',
                        '{ OnActiveUSec=90s ; next_elapse=1s ; injected=yes }'):
            with self.assertRaises(RuntimeError):activation.loaded_configuration('TimersMonotonic',invalid)


if __name__=='__main__':unittest.main()
