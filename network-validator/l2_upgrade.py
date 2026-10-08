"""Reviewed coordinated Engine/helper upgrade. No policy, socket, Monitor or ARP mutation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import ssl
import stat
import sys
import tarfile
import time
import urllib.request
from datetime import datetime, timezone

if __name__ == '__main__':
    dependency=Path(__file__).absolute().with_name('guarded_install.py')
    for item in (dependency,*dependency.parents):
        info=item.lstat()
        if info.st_uid!=0 or stat.S_ISLNK(info.st_mode) or info.st_mode&0o022:raise RuntimeError('Unprotected installer dependency')
    sys.path.insert(0,str(dependency.parent))
from guarded_install import Deployment, UNIT, HELPER, SOCKET, SOCKET_PATH, check, protected, sha, inspect_archive, wait_ready, error_details, exec_start_configuration

ENGINE_OVERRIDE=Path('/etc/systemd/system/hostsguardian-engine.service.d/zz-p0-engine-only.conf')
HELPER_UNIT=Path('/etc/systemd/system/hostsguardian-network-validator.service')


class L2Upgrade(Deployment):
    def __init__(self,stage,manifest,baseline):
        super().__init__(stage,manifest,baseline)
        self.touched=False

    def replacements(self):
        return {ENGINE_OVERRIDE:('engine-override.original',self.engine_content),HELPER_UNIT:('helper-unit.original',self.helper_content)}

    def original(self,path):
        name=self.replacements()[path][0];saved=self.backup/name
        protected(saved);check(sha(saved)==self.baseline['unitFiles'][str(path)],'Rollback snapshot integrity failed')
        return saved.read_bytes()

    def engine_content(self):
        original=self.original(ENGINE_OVERRIDE).decode('utf-8')
        check(sum(line.startswith('ExecStart=') and line!='ExecStart=' for line in original.splitlines())==1 and
              original.splitlines().count('ExecStart=')==1 and sum(line.startswith('WorkingDirectory=') for line in original.splitlines())==1 and
              [line for line in original.splitlines() if line.startswith('[')]==['[Service]'],'Unsupported Engine override')
        check('HOSTSGUARDIAN_PASSIVE_DNS_L2' not in original,'Unexpected pre-existing L2 override')
        result=re.sub(r'^ExecStart=.+$',lambda _: 'ExecStart='+str(self.release/'engine/HostsGuardian.DnsEngine'),original,flags=re.M)
        result=re.sub(r'^WorkingDirectory=.*$',lambda _: 'WorkingDirectory='+str(self.release/'engine'),result,flags=re.M)
        return (result.rstrip('\n')+'\nEnvironment=HOSTSGUARDIAN_PASSIVE_DNS_L2=1\n').encode('utf-8')

    def helper_content(self):
        original=self.original(HELPER_UNIT).decode('utf-8')
        lines=[line[10:] for line in original.splitlines() if line.startswith('ExecStart=')]
        check(len(lines)==1,'Unsupported helper execution layout')
        args=shlex.split(lines[0])
        check(len(args)==12 and args[:3]==['/usr/bin/python3','-I','-B'] and args[3]==self.baseline['helperScript'] and
              args[4::2]==['--socket','--interface','--engine-uid','--engine-executable'] and args[5]==SOCKET_PATH.as_posix() and
              args[7]==self.baseline['allowedInterface'] and args[9]==str(self.baseline['engineUid']) and
              args[11]==self.baseline['helperProtectedExecutable'],'Unreviewed helper arguments')
        args[3]=str(self.release/'helper/validator.py');args[11]=str(self.release/'engine/HostsGuardian.DnsEngine');args.append('--passive-dns')
        return re.sub(r'^ExecStart=.*$',lambda _: 'ExecStart='+shlex.join(args),original,flags=re.M).encode('utf-8')

    def preserved(self):
        b=self.baseline
        for name,digest in b['unitFiles'].items():
            path=Path(name)
            if self.touched and path in self.replacements():
                if path.read_bytes()!=self.replacements()[path][1]():return False
            elif sha(path)!=digest:return False
        return (sha(b['policyPath'])==b['policySha256'] and all(sha(p)==h for p,h in b['securityFiles'].items()) and
                all(sha(p)==h for p,h in b['helperFiles'].items()) and all(sha(p)==h for p,h in b['monitorFiles'].items()))

    def invariants(self,timeout=3):
        b=self.baseline
        for unit,properties in b['securityProperties'].items():
            for key,value in properties.items():
                actual=self.output('systemctl','show',unit,'-p',key,'--value',timeout=timeout)
                if unit==UNIT and key=='Environment' and self.touched:
                    expected=dict(item.split('=',1) for item in shlex.split(value));expected['HOSTSGUARDIAN_PASSIVE_DNS_L2']='1'
                    if dict(item.split('=',1) for item in shlex.split(actual))!=expected:return False
                elif actual!=value:return False
        info=SOCKET_PATH.lstat()
        return (stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and info.st_gid==b['engineGid'] and stat.S_IMODE(info.st_mode)==0o660 and
                self.output('systemctl','is-enabled',SOCKET,timeout=timeout)=='enabled' and
                self.output('systemctl','show',SOCKET,'-p','ActiveState','--value',timeout=timeout)=='active' and
                self.output('systemctl','show',UNIT,'-p','DropInPaths','--value',timeout=timeout).split()==b['dropInPaths'] and
                self.output('systemctl','show',HELPER,'-p','DropInPaths','--value',timeout=timeout).split()==b['helperDropInPaths'] and
                self.output('dpkg-query','-W','-f=${Version}','hostsguardian-monitor',timeout=timeout)==b['monitorVersion'])

    def collect(self,remaining,candidate=True):
        deadline=time.monotonic()+remaining
        state=super().collect(remaining,candidate)
        def budget():
            left=deadline-time.monotonic()
            if left<.25:raise TimeoutError('Coordinated readiness budget exhausted')
            return min(2,left)
        try:
            b=self.baseline;pid=int(self.output('systemctl','show',HELPER,'-p','MainPID','--value',timeout=budget()))
            caps=dict(line.split(':',1) for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line)
            snapshot=json.loads(Path(b['monitorStatusPath']).read_text());health=snapshot['validator'];now=datetime.now(timezone.utc)
            fresh=all(0<=(now-datetime.fromisoformat(value.replace('Z','+00:00'))).total_seconds()<10 for value in (snapshot['emittedAtUtc'],health['checkedAtUtc']))
            state['helper']=pid>0 and snapshot['processId']==state.get('pid') and fresh and health['state']=='READY' and health['activeValidationEnabled'] is False and health.get('mode')=='Passive' and all(int(caps[key].strip(),16)==0x2000 for key in ('CapEff','CapPrm','CapAmb','CapBnd')) and caps['NoNewPrivs'].strip()=='1'
            if candidate:state['helper']=state['helper'] and health.get('passiveDnsL2State')=='READY' and health.get('approvedTargetCount')==0
            state['helperPid']=pid;state['validator']=health
            context=ssl.create_default_context(cafile=b['certificatePath'])
            request=urllib.request.Request(b['managementUrl'].removesuffix('/dns/status')+'/v2/policy',headers={'Authorization':'Bearer '+Path(b['credentialPath']).read_text().strip()})
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self,*args,**kwargs):return None
            opener=urllib.request.build_opener(NoRedirect,urllib.request.HTTPSHandler(context=context))
            with opener.open(request,timeout=budget()) as response:p=json.load(response)
            state['policyReadback']=p['revision']==b['policyRevision'] and hashlib.sha256(json.dumps(p['policy'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==b['canonicalPolicySha256'] and sorted(d['deviceId'] for d in p['policy']['devices'])==b['registrationIds']
            state['preservation']=state['preservation'] and state['policyReadback'] and self.old_engine_unchanged()
            expected_helper=str(self.release/'helper/validator.py') if candidate else b['helperScript']
            expected_engine=str(self.release/'engine/HostsGuardian.DnsEngine') if candidate else b['helperProtectedExecutable']
            loaded=exec_start_configuration(self.output('systemctl','show',HELPER,'-p','ExecStart','--value',timeout=budget()))[1]
            expected_args=['/usr/bin/python3','-I','-B',expected_helper,'--socket',SOCKET_PATH.as_posix(),
                           '--interface',b['allowedInterface'],'--engine-uid',str(b['engineUid']),
                           '--engine-executable',expected_engine]+(['--passive-dns'] if candidate else [])
            state['helper']=state['helper'] and shlex.split(loaded)==expected_args
        except Exception as error:
            state['preservation']=False;state['helper']=False;state['coordinatedError']=error_details(error)
        return state

    def preflight(self):
        b=self.baseline;protected(self.stage,True);protected(SOCKET_PATH.parent,True)
        check(not self.release.exists() and not self.backup.exists(),'Attempt exists; preserve evidence')
        for path in b['unitFiles']:protected(Path(path))
        for path in b['helperFiles']:protected(Path(path))
        for path in self.replacements():
            check(str(path) in b['unitFiles'] and stat.S_IMODE(path.stat().st_mode)==0o644,'Unsupported target baseline/mode')
        check(self.preserved() and self.old_engine_unchanged() and self.invariants(),'Baseline preservation or hardening changed')
        check(exec_start_configuration(self.prop('ExecStart'))==exec_start_configuration(b['execStart']) and self.prop('WorkingDirectory')==b['workingDirectory'],'Loaded Engine selection changed')
        check(exec_start_configuration(self.output('systemctl','show',HELPER,'-p','ExecStart','--value'))==exec_start_configuration(b['helperExecStart']),'Loaded helper selection changed')
        check('HOSTSGUARDIAN_ACTIVE_VALIDATION=0' in shlex.split(self.prop('Environment')) and 'HOSTSGUARDIAN_PASSIVE_DNS_L2' not in self.prop('Environment'),'Explicit passive baseline required')
        for unit in (UNIT,HELPER,SOCKET):check(self.output('systemctl','show',unit,'-p','NeedDaemonReload','--value')=='no','Unexpected target stale unit; refuse reload')
        self.backup.mkdir(mode=0o700,parents=True);self.backup_created=True;protected(self.backup,True)
        (self.backup/'baseline.json').write_bytes((self.stage/'baseline.json').read_bytes());(self.backup/'baseline.json').chmod(0o600)
        for path,(name,_) in self.replacements().items():
            with (self.backup/name).open('xb') as stream:stream.write(path.read_bytes())
            (self.backup/name).chmod(0o600);check(sha(self.backup/name)==b['unitFiles'][str(path)],'Byte-exact backup failed')
        self.engine_content();self.helper_content()
        wait_ready(lambda left:self.collect(left,False),self.backup,'baseline')

    def prepare(self):
        self.release.mkdir(mode=0o755,parents=True);protected(self.release,True)
        with tarfile.open(self.stage/self.manifest['archive']['name']) as archive:
            inspect_archive(archive,self.manifest['files']);archive.extractall(self.release,filter='data')
        for path in self.release.rglob('*'):
            if path.is_dir():path.chmod(0o755)
        for name,item in self.manifest['files'].items():protected(self.release/name);check(sha(self.release/name)==item['sha256'],'Extracted payload mismatch')
        check(self.preserved() and self.old_engine_unchanged(),'Baseline changed before activation')

    def apply(self):
        self.preflight();self.prepare();self.changed=True
        self.run('systemctl','stop',UNIT);self.run('systemctl','stop',HELPER)
        self.touched=True
        for path,(_,content) in self.replacements().items():path.write_bytes(content());path.chmod(0o644)
        self.run('systemctl','daemon-reload');self.run('systemctl','start',HELPER);self.run('systemctl','start',UNIT)
        wait_ready(lambda left:self.collect(left,True),self.backup,'candidate')
        check(self.preserved() and self.invariants(),'Final preservation/hardening failed')
        (self.backup/'result.json').write_text(json.dumps(dict(status='ENGINE_HELPER_L2_DEPLOYED_ACTIVE_OFF',sourceCommit=self.manifest['sourceCommit'],policyPreserved=True,monitorChanged=False,socketChanged=False,activeValidation=False))+'\n')

    def rollback(self):
        check(self.old_engine_unchanged(),'Old Engine changed; refuse unsafe rollback')
        for path in self.replacements():self.original(path)  # Verify both before stopping anything.
        self.run('systemctl','stop',UNIT);self.run('systemctl','stop',HELPER)
        for path in self.replacements():path.write_bytes(self.original(path));path.chmod(0o644)
        self.touched=False
        self.run('systemctl','daemon-reload');self.run('systemctl','start',HELPER);self.run('systemctl','start',UNIT)
        folder=self.backup
        if (folder/'rollback-readiness.jsonl').exists():folder=self.backup/('rollback-retry-'+str(time.time_ns()));folder.mkdir(mode=0o700)
        wait_ready(lambda left:self.collect(left,False),folder,'rollback')
        check(self.preserved() and self.invariants(),'Rollback preservation/hardening failed')
        (self.backup/'rollback-result.json').write_text(json.dumps(dict(status='ROLLBACK_VERIFIED',policyPreserved=True,activeValidation=False))+'\n')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,required=True);parser.add_argument('--manifest-sha256',required=True);parser.add_argument('--baseline-sha256',required=True)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--rollback',action='store_true');args=parser.parse_args()
    check(args.apply!=args.rollback and os.geteuid()==0,'Choose one reviewed privileged action')
    protected(Path(__file__).absolute());protected(args.stage,True)
    for name,digest in [('l2-manifest.json',args.manifest_sha256),('baseline.json',args.baseline_sha256)]:protected(args.stage/name);check(sha(args.stage/name)==digest,'Pinned configuration mismatch')
    m=json.loads((args.stage/'l2-manifest.json').read_text());b=json.loads((args.stage/'baseline.json').read_text())
    check(re.fullmatch('[a-f0-9]{40}',m['sourceCommit']) and re.fullmatch('[A-Za-z0-9_.:-]{1,15}',b['allowedInterface']),'Invalid source/interface')
    for name,digest in m['toolHashes'].items():check(name in ('l2_upgrade.py','guarded_install.py','dns_readiness.py'),'Unexpected tool');protected(args.stage/name);check(sha(args.stage/name)==digest,'Tool mismatch')
    check(set(m['toolHashes'])=={'l2_upgrade.py','guarded_install.py','dns_readiness.py'},'Incomplete tool pins')
    check({'engine/HostsGuardian.DnsEngine','helper/validator.py','helper/dns_readiness.py'}<=set(m['files']) and all(name.startswith('engine/') or name in ('helper/validator.py','helper/dns_readiness.py') for name in m['files']),'Payload scope violation')
    archive=args.stage/m['archive']['name'];check(archive.parent==args.stage,'Archive path escape');protected(archive);check(sha(archive)==m['archive']['sha256'],'Archive mismatch')
    with tarfile.open(archive) as tar:inspect_archive(tar,m['files'])
    operation=L2Upgrade(args.stage,m,b)
    if args.rollback:
        protected(operation.backup/'baseline.json');check(sha(operation.backup/'baseline.json')==args.baseline_sha256,'Saved baseline mismatch')
        for path,(_,content) in operation.replacements().items():
            protected(path);check(path.read_bytes() in (operation.original(path),content()),'Target no longer owned by attempt')
        operation.rollback();return
    try:operation.apply()
    except BaseException as error:
        evidence=dict(deployment=error_details(error))
        if operation.changed:
            try:operation.rollback()
            except BaseException as rollback_error:evidence['rollback']=error_details(rollback_error)
        if operation.backup_created:(operation.backup/'failure.json').write_text(json.dumps(evidence,indent=2)+'\n')
        if 'rollback' in evidence:raise RuntimeError('DEPLOYMENT FAILED; ROLLBACK UNVERIFIED; retained failure.json') from error
        raise


if __name__=='__main__':main()
