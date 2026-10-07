"""Pure archived-byte/readiness fixtures; never instantiate production deployment."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from guarded_install import inspect_archive,wait_ready


class InstallerTests(unittest.TestCase):
    def archive(self,name='engine/file',kind=tarfile.REGTYPE,data=b'fixture'):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as tar:
            member=tarfile.TarInfo(name);member.type=kind;member.size=len(data) if kind==tarfile.REGTYPE else 0;member.mode=0o644;tar.addfile(member,io.BytesIO(data) if member.size else None)
        stream.seek(0);return tarfile.open(fileobj=stream)
    def test_archive_integrity_and_links_traversal_extra_missing_rejected(self):
        files={'engine/file':dict(size=7,sha256=hashlib.sha256(b'fixture').hexdigest(),mode='0644')}
        with self.archive() as tar:inspect_archive(tar,files)
        for name,kind in (('../outside',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('engine/file',tarfile.SYMTYPE),('extra',tarfile.REGTYPE)):
            with self.archive(name,kind) as tar:
                with self.assertRaises(RuntimeError):inspect_archive(tar,files)
        with self.archive(data=b'changed') as tar:
            with self.assertRaises(RuntimeError):inspect_archive(tar,files)
    def test_candidate_and_rollback_poll_all_conditions_retain_missing_diagnostics(self):
        keys=('service','ipv4Udp','ipv4Tcp','ipv6Udp','ipv6Tcp','ownership','https','preservation','helper')
        for phase in ('candidate','rollback'):
            with tempfile.TemporaryDirectory() as folder:
                ticks=[0];attempt=[0]
                def probe(remaining):attempt[0]+=1;return {k:attempt[0]>1 or k!='ipv6Tcp' for k in keys}
                def pause(value):ticks[0]+=value
                wait_ready(probe,Path(folder),phase,clock=lambda:ticks[0],pause=pause)
                lines=[json.loads(line) for line in (Path(folder)/(phase+'-readiness.jsonl')).read_text().splitlines()]
                self.assertEqual(lines[0]['missing'],['ipv6Tcp']);self.assertEqual(lines[-1]['missing'],[])
    def test_timeout_does_not_weaken_dns_or_helper_gate(self):
        with tempfile.TemporaryDirectory() as folder:
            ticks=[0]
            def pause(value):ticks[0]+=value
            with self.assertRaises(RuntimeError):wait_ready(lambda _: {},Path(folder),'candidate',timeout=.5,clock=lambda:ticks[0],pause=pause)
            final=json.loads((Path(folder)/'candidate-readiness-final.json').read_text())
            self.assertIn('ipv4Udp',final['missing']);self.assertIn('ipv6Tcp',final['missing']);self.assertIn('helper',final['missing'])

# Collector fixtures exercise the exact deployed failure with no real systemctl,
# sudo, production files, credentials, or service operations.
from contextlib import ExitStack
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch
import subprocess
import guarded_install as installer


class CollectorTests(unittest.TestCase):
    def collect(self, candidate=True, separate=False, bad_owner=False,
                failed_probe=None, service_error=False, helper_caps='2000',
                stale=False, service_uid=1000, engine_caps='400'):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            stage=Path(folder)
            baseline=dict(engineUid=1000,oldExecutable='/fixture/old',dnsIpv4='127.0.0.1',dnsIpv6='::1',
                          readinessDomain='fixture.invalid',certificatePath='/fixture/cert',credentialPath='/fixture/token',
                          managementUrl='https://fixture.invalid/status',policyRevision=23,monitorStatusPath='/fixture/status')
            deployment=installer.Deployment(stage,dict(sourceIdentity='a'*64,files={'helper/dns_readiness.py':{'sha256':'fixture'}}),baseline)
            pid=42
            row=lambda proto,owner:f'{proto} LISTEN 0 16 *:53 *:* users:(("Engine",pid={owner},fd=7))'
            properties={'MainPID':'42','ActiveState':'active','SubState':'running'}
            def prop(name,timeout=3):
                self.assertGreaterEqual(timeout,installer.MIN_PROBE_BUDGET)
                if service_error:raise subprocess.TimeoutExpired(['systemctl','show','MainPID'],timeout)
                return properties[name]
            deployment.prop=prop
            def output(*args,timeout=3):
                self.assertGreaterEqual(timeout,installer.MIN_PROBE_BUDGET)
                if args[0]=='ss':
                    return '\n'.join(row(proto,420 if bad_owner else pid) for proto in ('udp','tcp')) if args[2]=='-6' or separate else ''
                return '99'
            deployment.output=output;deployment.preserved=lambda:True;deployment.old_engine_unchanged=lambda:True
            original_read=Path.read_text;original_stat=Path.stat
            def read(path,*args,**kwargs):
                name=str(path).replace('\\','/')
                if name=='/fixture/token':return 'fixture-secret-not-logged'
                if name=='/fixture/status':
                    now=datetime.now(timezone.utc).isoformat() if not stale else '2000-01-01T00:00:00+00:00'
                    return json.dumps(dict(processId=42,emittedAtUtc=now,validator=dict(state='READY',activeValidationEnabled=False,checkedAtUtc=now)))
                if name.startswith('/proc/') and name.endswith('/status'):
                    cap=helper_caps if '/99/' in name else engine_caps
                    return '\n'.join(f'{key}: {cap}' for key in ('CapPrm','CapEff','CapAmb','CapBnd'))+'\nNoNewPrivs: 1'
                return original_read(path,*args,**kwargs)
            def file_stat(path,*args,**kwargs):
                if str(path).replace('\\','/')=='/proc/42':return SimpleNamespace(st_uid=service_uid)
                return original_stat(path,*args,**kwargs)
            calls=[]
            def probe(address,transport,domain,timeout):
                self.assertGreaterEqual(timeout,installer.MIN_PROBE_BUDGET)
                calls.append((address,transport))
                if (address,transport)==failed_probe:raise TimeoutError('fixture refused DNS')
                return {'ready':True,'family':4 if address=='127.0.0.1' else 6,'transport':transport}
            stack.enter_context(patch.object(Path,'read_text',read));stack.enter_context(patch.object(Path,'stat',file_stat))
            stack.enter_context(patch.object(installer.os,'readlink',return_value=str(deployment.release/'engine/HostsGuardian.DnsEngine') if candidate else '/fixture/old'))
            stack.enter_context(patch.object(installer,'protected'));stack.enter_context(patch.object(installer,'sha',return_value='fixture'))
            stack.enter_context(patch.object(installer.importlib.util,'spec_from_file_location',return_value=SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _:None))))
            stack.enter_context(patch.object(installer.importlib.util,'module_from_spec',return_value=SimpleNamespace(probe=probe)))
            stack.enter_context(patch.object(installer.ssl,'create_default_context'))
            status=dict(implementation='HostsGuardian.DnsEngine',managementListening=True,policyLoaded=True,policyRevision=23,emergencySafeMode=False,udpListening=True,tcpListening=True,ipv6UdpState='Listening',ipv6TcpState='Listening')
            response=io.StringIO(json.dumps(status))
            stack.enter_context(patch.object(installer.urllib.request,'build_opener',return_value=SimpleNamespace(open=lambda *a,**k:response)))
            state=deployment.collect(30,candidate)
            self.assertNotIn('fixture-secret-not-logged',json.dumps(state))
            return state,calls

    def test_candidate_and_rollback_dual_mode_run_all_four_probes(self):
        for candidate in (True,False):
            state,calls=self.collect(candidate)
            self.assertEqual(len(calls),4)
            self.assertEqual(state['socketRowsByFamily']['-4'],[])
            for key in ('service','ipv4Udp','ipv4Tcp','ipv6Udp','ipv6Tcp','ownership','https','preservation','helper'):
                self.assertTrue(state[key],key)

    def test_separate_family_sockets_are_also_accepted(self):
        state,calls=self.collect(separate=True)
        self.assertTrue(state['ownership']);self.assertEqual(len(calls),4)

    def test_one_missing_transport_is_never_hidden_by_other_success(self):
        for address,prefix in (('127.0.0.1','ipv4'),('::1','ipv6')):
            for transport in ('udp','tcp'):
                state,calls=self.collect(failed_probe=(address,transport))
                key=prefix+transport.title();self.assertFalse(state[key]);self.assertEqual(len(calls),4)
                self.assertEqual(state[key+'Error']['message'],'fixture refused DNS')
                self.assertTrue(state['ownership']);self.assertTrue(state['https'])

    def test_wrong_pid_is_rejected_even_with_four_successful_responses(self):
        state,calls=self.collect(bad_owner=True)
        self.assertFalse(state['ownership']);self.assertEqual(len(calls),4)

    def test_service_timeout_does_not_suppress_protocol_or_management_evidence(self):
        state,calls=self.collect(service_error=True)
        self.assertFalse(state['service']);self.assertFalse(state['ownership']);self.assertEqual(len(calls),4)
        self.assertTrue(state['ipv4Udp']);self.assertTrue(state['https']);self.assertTrue(state['preservation'])
        self.assertEqual(state['serviceError']['type'],'TimeoutExpired')
        self.assertIn('command',state['serviceError']);self.assertIn('traceback',state['serviceError'])

    def test_raw_capability_not_allowed_on_engine_and_missing_on_helper_fails(self):
        state,_=self.collect(helper_caps='400');self.assertFalse(state['helper'])
        state,_=self.collect(service_uid=0);self.assertFalse(state['service'])
        state,_=self.collect(engine_caps='2400');self.assertFalse(state['service'])

    def test_stale_helper_health_is_not_ready(self):
        state,_=self.collect(stale=True);self.assertFalse(state['helper'])

    def test_socket_parser_only_uses_local_port_exact_owner_both_transports(self):
        rows=installer.dns_socket_rows('udp UNCONN 0 0 *:5353 *:53 users:(("x",pid=42,fd=1))\nudp UNCONN 0 0 *:53 *:* users:(("x",pid=420,fd=1))')
        self.assertEqual(len(rows),1);self.assertFalse(installer.dns_socket_ownership(rows,42))
        self.assertFalse(installer.dns_socket_ownership(['udp UNCONN 0 0 *:53 *:*'],42))

    def test_fresh_deployment_namespace_does_not_reuse_failed_artifacts(self):
        original=installer.Deployment(Path('/fixture'),dict(sourceIdentity='a'*64),{})
        retry=installer.Deployment(Path('/fixture'),dict(sourceIdentity='a'*64,deploymentId='b'*64),{})
        self.assertNotEqual(original.release,retry.release);self.assertNotEqual(original.backup,retry.backup)
        with self.assertRaises(RuntimeError):installer.Deployment(Path('/fixture'),dict(sourceIdentity='a'*64,deploymentId='../bad'),{})

    def test_deadline_keeps_last_complete_evidence_and_does_not_start_tiny_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            ticks=[0];budgets=[]
            def probe(remaining):
                budgets.append(remaining)
                if len(budgets)==1:return {key:key!='ipv4Udp' for key in ('service','ipv4Udp','ipv4Tcp','ipv6Udp','ipv6Tcp','ownership','https','preservation','helper')}
                ticks[0]+=.4;return {'budgetExhausted':True}
            with self.assertRaisesRegex(RuntimeError,'ipv4Udp'):
                installer.wait_ready(probe,Path(folder),'candidate',timeout=.75,clock=lambda:ticks[0],pause=lambda seconds:ticks.__setitem__(0,ticks[0]+seconds))
            final=json.loads((Path(folder)/'candidate-readiness-final.json').read_text())
            self.assertEqual(final['missing'],['ipv4Udp']);self.assertIn('terminalIncompleteAttempt',final)
            self.assertTrue(all(value>=installer.MIN_PROBE_BUDGET for value in budgets))

    def test_execstart_runtime_restart_does_not_change_configuration(self):
        first='{ path=/fixture/Engine ; argv[]=/fixture/Engine ; ignore_errors=no ; pid=42 ; start_time=old ; }'
        second=first.replace('pid=42','pid=99').replace('start_time=old','start_time=new')
        self.assertEqual(installer.exec_start_configuration(first),installer.exec_start_configuration(second))
        self.assertNotEqual(installer.exec_start_configuration(first),installer.exec_start_configuration(second.replace('argv[]=/fixture/Engine','argv[]=/fixture/Engine --unsafe')))
        with self.assertRaises(RuntimeError):installer.exec_start_configuration('unknown format')

class FailureEvidenceTests(unittest.TestCase):
    def test_original_and_rollback_exceptions_are_retained_without_overwriting_prior_attempt(self):
        import sys
        for newly_created in (True, False):
            with self.subTest(newly_created=newly_created), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                stage=Path(folder);backup=stage/'backup';backup.mkdir()
                evidence=backup/'deployment-failure.json';evidence.write_text('prior forensic bytes',encoding='utf-8')
                manifest=dict(sourceIdentity='a'*64,archive=dict(name='fixture.tar',sha256='fixture'),files={})
                baseline=dict(allowedInterface='fixture0',engineUser='fixture',engineGroup='fixture')
                (stage/'payload-manifest.json').write_text(json.dumps(manifest),encoding='utf-8')
                (stage/'baseline.json').write_text(json.dumps(baseline),encoding='utf-8')
                with tarfile.open(stage/'fixture.tar','w'):pass
                class Operation:
                    def __init__(self,*args):
                        self.backup=backup;self.backup_created=newly_created
                        self.changed=newly_created;self.created_units=[];self.installed_monitor=False
                    def apply(self):raise RuntimeError('candidate readiness timeout: ipv4Udp')
                    def rollback(self):raise RuntimeError('rollback readiness timeout: ipv6Tcp')
                stack.enter_context(patch.object(installer,'Deployment',Operation))
                stack.enter_context(patch.object(installer,'protected'))
                stack.enter_context(patch.object(installer,'sha',return_value='fixture'))
                stack.enter_context(patch.object(installer.os,'geteuid',return_value=0,create=True))
                stack.enter_context(patch.object(sys,'argv',['fixture','--stage',str(stage),'--expected-manifest-sha256','fixture','--expected-baseline-sha256','fixture','--apply','--approve-pending-daemon-reload']))
                with self.assertRaises(RuntimeError) as caught:installer.main()
                if newly_created:
                    result=json.loads(evidence.read_text())
                    self.assertIn('candidate readiness timeout',result['deployment']['message'])
                    self.assertIn('rollback readiness timeout',result['rollback']['message'])
                    self.assertIn('traceback',result['rollback'])
                    self.assertIn('ipv6Tcp',str(caught.exception))
                else:self.assertEqual(evidence.read_text(),'prior forensic bytes')
