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
import tempfile
import urllib.request
from datetime import datetime, timezone

if __name__ == '__main__':
    dependency=Path(__file__).absolute().with_name('guarded_install.py')
    for item in (dependency,*dependency.parents):
        info=item.lstat()
        if info.st_uid!=0 or stat.S_ISLNK(info.st_mode) or info.st_mode&0o022:raise RuntimeError('Unprotected installer dependency')
    sys.path.insert(0,str(dependency.parent))
from guarded_install import Deployment, UNIT, HELPER, SOCKET, SOCKET_PATH, check, protected, sha, inspect_archive, wait_ready, error_details, exec_start_configuration
import durable_recovery as durable

ENGINE_OVERRIDE=Path('/etc/systemd/system/hostsguardian-engine.service.d/zz-p0-engine-only.conf')
HELPER_UNIT=Path('/etc/systemd/system/hostsguardian-network-validator.service')

def atomic_write(path,data,mode=0o644):
    fd,name=tempfile.mkstemp(prefix='.hg-upgrade-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode) if hasattr(os,'fchmod') else os.chmod(name,mode)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
        if os.name=='posix':
            directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)


class L2Upgrade(Deployment):
    def __init__(self,stage,manifest,baseline):
        super().__init__(stage,manifest,baseline)
        self.touched=False

    def replacements(self):
        return {ENGINE_OVERRIDE:('engine-override.original',self.engine_content),HELPER_UNIT:('helper-unit.original',self.helper_content)}

    def receipt(self,phase):
        previous=self.backup/'transaction.json'
        attempts=json.loads(previous.read_text()).get('watchdogAttempts',0) if previous.exists() else 0
        targets={}
        for path,(_,content) in self.replacements().items():
            info=path.lstat() if path.exists() else None
            targets[str(path)]={'original':hashlib.sha256(self.original(path)).hexdigest(),
                'candidate':hashlib.sha256(content()).hexdigest(),'inode':None if info is None else [info.st_dev,info.st_ino]}
        atomic_write(previous,json.dumps(dict(identity=self.manifest['sourceIdentity'],phase=phase,targets=targets,watchdogAttempts=attempts)).encode(),0o600)

    def watchdog(self):
        path=self.backup/'transaction.json';protected(path)
        state=json.loads(path.read_text())
        check(state.get('identity')==self.manifest['sourceIdentity'],'Watchdog identity mismatch')
        if state.get('phase') in ('prepared','committed','rolledBack'):
            if durable.PENDING.exists():
                current=durable.read_pending()
                if current['identity']==self.manifest['sourceIdentity']:self.disarm_recovery()
            return
        self.assert_recovery_owner()
        check(state.get('phase')=='mutating','Unknown watchdog transaction phase')
        attempts=state.get('watchdogAttempts',0)
        check(type(attempts) is int and 0<=attempts<=3,'Invalid watchdog attempt count')
        if attempts==3:
            state['watchdogStatus']='EXHAUSTED_REQUIRES_HUMAN'
            atomic_write(path,json.dumps(state).encode(),0o600)
            raise RuntimeError('Watchdog exhausted; no further service mutation')
        state['watchdogAttempts']=attempts+1
        state['watchdogStatus']='FINAL_ATTEMPT_REQUIRES_HUMAN_UNLESS_VERIFIED' if attempts+1==3 else 'RUNNING'
        atomic_write(path,json.dumps(state).encode(),0o600)
        try:self.rollback()
        except BaseException as error:
            state['watchdogStatus']='EXHAUSTED_REQUIRES_HUMAN' if attempts+1==3 else 'FAILED_RETRY_PENDING'
            state['watchdogFailure']=error_details(error)
            atomic_write(path,json.dumps(state).encode(),0o600)
            raise

    def validate_restore_targets(self):
        receipt_path=self.backup/'transaction.json';receipt=None
        if receipt_path.exists():
            protected(receipt_path);receipt=json.loads(receipt_path.read_text())
            check(receipt['identity']==self.manifest['sourceIdentity'] and set(receipt['targets'])=={str(p) for p in self.replacements()},'Untrusted recovery receipt')
        for name,digest in self.baseline['unitFiles'].items():
            if Path(name) not in self.replacements():protected(Path(name));check(sha(name)==digest,'Unrelated unit changed; refuse rollback')
        for path,(_,content) in self.replacements().items():
            old=self.original(path);candidate=content();protected(path.parent,True)
            if path.exists() or path.is_symlink():
                protected(path);data=path.read_bytes()
                if data in (old,candidate):continue
            else:data=None
            check(receipt is not None and receipt['phase']=='mutating','No interrupted attempt ownership')
            target=receipt['targets'][str(path)]
            check(target['original']==hashlib.sha256(old).hexdigest() and target['candidate']==hashlib.sha256(candidate).hexdigest(),'Receipt pins changed')
            if data is not None:
                info=path.lstat()
                check(target['inode']==[info.st_dev,info.st_ino] and
                      (old.startswith(data) or candidate.startswith(data)),'Unknown conflicting selector; refuse overwrite')

    def arm_watchdog(self):
        self.install_boot_recovery()
        unit='hg-l2-rollback-'+self.manifest['sourceIdentity'][:16]
        self.run('systemd-run','--unit='+unit,'--on-active=1000s','--timer-property=AccuracySec=1s',
            '--property=Type=exec','--property=RuntimeMaxSec=600s','--property=TimeoutStopSec=15s',
            '--property=Restart=on-failure','--property=RestartSec=5s',
            '--property=StartLimitIntervalSec=1800s','--property=StartLimitBurst=3',
            '--','/usr/bin/python3','-I','-B',str(self.stage/'l2_upgrade.py'),'--stage',str(self.stage),
            '--manifest-sha256',sha(self.stage/'l2-manifest.json'),'--baseline-sha256',sha(self.stage/'baseline.json'),'--watchdog')
        check(self.output('systemctl','is-active',unit+'.timer')=='active','Independent rollback watchdog not active')
        raw=self.output('systemctl','show',unit+'.timer','-p','NextElapseUSecMonotonic','--value')
        units={'us':1e-6,'ms':.001,'s':1,'min':60,'h':3600,'d':86400}
        tokens=[re.fullmatch(r'(\d+(?:\.\d+)?)(us|ms|s|min|h|d)',p) for p in raw.split()]
        check(tokens and all(tokens),'Rollback watchdog not scheduled')
        next_time=sum(float(p[1])*units[p[2]] for p in tokens)
        uptime=float(Path('/proc/uptime').read_text().split()[0])
        check(0<next_time-uptime<=1002,'Rollback watchdog deadline invalid')

    def install_boot_recovery(self):
        check(not durable.PENDING.exists() and not durable.PENDING.is_symlink(),'Pending recovery owns deployment; refuse another attempt')
        durable.ROOT.mkdir(mode=0o700,exist_ok=True);protected(durable.ROOT,True)
        for path,data in [(durable.ROOT/'consumer.py',(self.stage/'durable_recovery.py').read_bytes()),(durable.UNIT_PATH,durable.UNIT_BYTES)]:
            protected(path.parent,True)
            if path.exists() or path.is_symlink():
                protected(path);check(path.read_bytes()==data,'Existing boot consumer differs; review required')
            else:atomic_write(path,data,0o600 if path.name=='consumer.py' else 0o644)
        self.run('systemctl','daemon-reload')
        self.run('systemctl','enable','hostsguardian-deployment-recovery.service')
        check(self.output('systemctl','is-enabled','hostsguardian-deployment-recovery.service')=='enabled','Boot recovery consumer not enabled')
        if os.name=='posix':
            for directory in (durable.ROOT.parent,durable.UNIT_PATH.parent,durable.UNIT_PATH.parent/'multi-user.target.wants'):
                protected(directory,True)
                fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(fd)
                finally:os.close(fd)
        check(exec_start_configuration(self.output('systemctl','show','hostsguardian-deployment-recovery.service','-p','ExecStart','--value'))==
              ('/usr/bin/python3','/usr/bin/python3 -I -B /var/lib/hostsguardian-deployment/recovery/consumer.py','no'),'Unexpected loaded boot consumer')
        expected={'DropInPaths':'','User':'root','Type':'oneshot','TimeoutStartUSec':'10min 50s',
                  'Restart':'on-failure','NoNewPrivileges':'yes','CapabilityBoundingSet':'cap_dac_read_search','AmbientCapabilities':'cap_dac_read_search',
                  'ProtectSystem':'strict','ProtectHome':'read-only','PrivateTmp':'yes','NeedDaemonReload':'no',
                  'FragmentPath':str(durable.UNIT_PATH)}
        for key,value in expected.items():
            check(self.output('systemctl','show','hostsguardian-deployment-recovery.service','-p',key,'--value')==value,
                  'Unexpected loaded boot consumer property: '+key)
        pointer=dict(identity=self.manifest['sourceIdentity'],stage=str(self.stage),manifestSha256=sha(self.stage/'l2-manifest.json'),
                     baselineSha256=sha(self.stage/'baseline.json'),installerSha256=sha(self.stage/'l2_upgrade.py'))
        atomic_write(durable.PENDING,json.dumps(pointer).encode(),0o600)
        self.assert_recovery_owner()

    def assert_recovery_owner(self):
        state=durable.read_pending()
        check(state['identity']==self.manifest['sourceIdentity'] and state['stage']==str(self.stage),'Another recovery owns transaction')

    def disarm_recovery(self):
        self.assert_recovery_owner()
        terminal=json.loads((self.backup/'transaction.json').read_text())
        check(terminal['phase'] in ('prepared','committed','rolledBack'),'Cannot disarm unverified transaction')
        atomic_write(durable.ROOT/'latest.json',json.dumps(dict(identity=self.manifest['sourceIdentity'],phase=terminal['phase'])).encode(),0o600)
        durable.PENDING.unlink()
        if os.name=='posix':
            fd=os.open(durable.ROOT,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)

    def original(self,path):
        name=self.replacements()[path][0];saved=self.backup/name
        protected(saved);check(sha(saved)==self.baseline['unitFiles'][str(path)],'Rollback snapshot integrity failed')
        return saved.read_bytes()

    def engine_content(self):
        original=self.original(ENGINE_OVERRIDE).decode('utf-8')
        check(sum(line.startswith('ExecStart=') and line!='ExecStart=' for line in original.splitlines())==1 and
              original.splitlines().count('ExecStart=')==1 and sum(line.startswith('WorkingDirectory=') for line in original.splitlines())==1 and
              [line for line in original.splitlines() if line.startswith('[')]==['[Service]'],'Unsupported Engine override')
        passive=[line for line in original.splitlines() if 'HOSTSGUARDIAN_PASSIVE_DNS_L2' in line]
        check(passive in ([],['Environment=HOSTSGUARDIAN_PASSIVE_DNS_L2=1']),'Unexpected passive override layout')
        result=re.sub(r'^ExecStart=.+$',lambda _: 'ExecStart='+str(self.release/'engine/HostsGuardian.DnsEngine'),original,flags=re.M)
        result=re.sub(r'^WorkingDirectory=.*$',lambda _: 'WorkingDirectory='+str(self.release/'engine'),result,flags=re.M)
        return (result.rstrip('\n')+('\n' if passive else '\nEnvironment=HOSTSGUARDIAN_PASSIVE_DNS_L2=1\n')).encode('utf-8')

    def helper_content(self):
        original=self.original(HELPER_UNIT).decode('utf-8')
        lines=[line[10:] for line in original.splitlines() if line.startswith('ExecStart=')]
        check(len(lines)==1,'Unsupported helper execution layout')
        args=shlex.split(lines[0])
        if len(args)==13 and args[-1]=='--passive-dns':args=args[:-1]
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
                           '--engine-executable',expected_engine]+(['--passive-dns'] if candidate or '--passive-dns' in b['helperExecStart'] else [])
            state['helper']=state['helper'] and shlex.split(loaded)==expected_args
        except Exception as error:
            state['preservation']=False;state['helper']=False;state['coordinatedError']=error_details(error)
        return state

    def preflight(self):
        b=self.baseline;protected(self.stage,True);protected(SOCKET_PATH.parent,True)
        check(not durable.PENDING.exists() and not durable.PENDING.is_symlink(),'Pending recovery blocks new deployment')
        check(not self.release.exists() and not self.backup.exists(),'Attempt exists; preserve evidence')
        for path in b['unitFiles']:protected(Path(path))
        for path in b['helperFiles']:protected(Path(path))
        for path in self.replacements():
            check(str(path) in b['unitFiles'] and stat.S_IMODE(path.stat().st_mode)==0o644,'Unsupported target baseline/mode')
        check(self.preserved() and self.old_engine_unchanged() and self.invariants(),'Baseline preservation or hardening changed')
        check(exec_start_configuration(self.prop('ExecStart'))==exec_start_configuration(b['execStart']) and self.prop('WorkingDirectory')==b['workingDirectory'],'Loaded Engine selection changed')
        check(exec_start_configuration(self.output('systemctl','show',HELPER,'-p','ExecStart','--value'))==exec_start_configuration(b['helperExecStart']),'Loaded helper selection changed')
        environment=dict(item.split('=',1) for item in shlex.split(self.prop('Environment')))
        check(environment.get('HOSTSGUARDIAN_ACTIVE_VALIDATION')=='0' and
              environment.get('HOSTSGUARDIAN_PASSIVE_DNS_L2') in (None,'1'),'Explicit active-OFF/passive baseline required')
        for unit in (UNIT,HELPER,SOCKET):check(self.output('systemctl','show',unit,'-p','NeedDaemonReload','--value')=='no','Unexpected target stale unit; refuse reload')
        self.backup.mkdir(mode=0o700,parents=True);self.backup_created=True;protected(self.backup,True)
        if os.name=='posix':
            fd=os.open(self.backup.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        atomic_write(self.backup/'baseline.json',(self.stage/'baseline.json').read_bytes(),0o600)
        for path,(name,_) in self.replacements().items():
            with (self.backup/name).open('xb') as stream:
                stream.write(path.read_bytes());stream.flush();os.fsync(stream.fileno())
            (self.backup/name).chmod(0o600);check(sha(self.backup/name)==b['unitFiles'][str(path)],'Byte-exact backup failed')
        self.engine_content();self.helper_content()
        wait_ready(lambda left:self.collect(left,False),self.backup,'baseline')

    def prepare(self):
        protected(self.release.parent,True)  # Existing release hierarchy is a deployment precondition.
        self.release.mkdir(mode=0o755);protected(self.release,True)
        with tarfile.open(self.stage/self.manifest['archive']['name']) as archive:
            inspect_archive(archive,self.manifest['files']);archive.extractall(self.release,filter='data')
        for path in self.release.rglob('*'):
            if path.is_dir():path.chmod(0o755)
        for name,item in self.manifest['files'].items():protected(self.release/name);check(sha(self.release/name)==item['sha256'],'Extracted payload mismatch')
        if os.name=='posix':
            for name in self.manifest['files']:
                with (self.release/name).open('rb') as stream:os.fsync(stream.fileno())
            directories=sorted((p for p in self.release.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True)
            for directory in [*directories,self.release,self.release.parent]:
                fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(fd)
                finally:os.close(fd)
        check(self.preserved() and self.old_engine_unchanged(),'Baseline changed before activation')

    def apply(self):
        self.preflight();self.prepare();self.receipt('prepared');self.arm_watchdog();self.changed=True;self.receipt('mutating')
        self.run('systemctl','stop',UNIT);self.run('systemctl','stop',HELPER)
        self.touched=True
        for path,(_,content) in self.replacements().items():atomic_write(path,content());self.receipt('mutating')
        self.run('systemctl','daemon-reload');self.run('systemctl','start',HELPER);self.run('systemctl','start',UNIT)
        wait_ready(lambda left:self.collect(left,True),self.backup,'candidate')
        check(self.preserved() and self.invariants(),'Final preservation/hardening failed')
        self.receipt('committed')
        self.disarm_recovery()
        (self.backup/'result.json').write_text(json.dumps(dict(status='ENGINE_HELPER_L2_DEPLOYED_ACTIVE_OFF',sourceCommit=self.manifest['sourceCommit'],policyPreserved=True,monitorChanged=False,socketChanged=False,activeValidation=False))+'\n')

    def rollback(self):
        if durable.PENDING.exists():self.assert_recovery_owner()
        elif (durable.ROOT/'latest.json').exists():
            protected(durable.ROOT/'latest.json')
            check(json.loads((durable.ROOT/'latest.json').read_text())['identity']==self.manifest['sourceIdentity'],'Newer completed transaction; refuse stale rollback')
        check(self.old_engine_unchanged(),'Old Engine changed; refuse unsafe rollback')
        self.validate_restore_targets()
        for path in self.replacements():self.original(path)  # Verify both before stopping anything.
        self.run('systemctl','stop',UNIT);self.run('systemctl','stop',HELPER)
        for path in self.replacements():atomic_write(path,self.original(path))
        self.touched=False
        self.run('systemctl','daemon-reload');self.run('systemctl','start',HELPER);self.run('systemctl','start',UNIT)
        folder=self.backup
        if (folder/'rollback-readiness.jsonl').exists():folder=self.backup/('rollback-retry-'+str(time.time_ns()));folder.mkdir(mode=0o700)
        wait_ready(lambda left:self.collect(left,False),folder,'rollback')
        check(self.preserved() and self.invariants(),'Rollback preservation/hardening failed')
        self.receipt('rolledBack')
        if durable.PENDING.exists():self.disarm_recovery()
        (self.backup/'rollback-result.json').write_text(json.dumps(dict(status='ROLLBACK_VERIFIED',policyPreserved=True,activeValidation=False))+'\n')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,required=True);parser.add_argument('--manifest-sha256',required=True);parser.add_argument('--baseline-sha256',required=True)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--rollback',action='store_true');parser.add_argument('--watchdog',action='store_true');args=parser.parse_args()
    check(sum((args.apply,args.rollback,args.watchdog))==1 and os.geteuid()==0,'Choose one reviewed privileged action')
    import fcntl
    fd=os.open('/run/hostsguardian-l2-upgrade.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'a') as lock:
        info=os.fstat(lock.fileno())
        check(info.st_uid==0 and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not info.st_mode&0o077,'Untrusted deployment lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        execute(args)

def execute(args):
    protected(Path(__file__).absolute());protected(args.stage,True)
    for name,digest in [('l2-manifest.json',args.manifest_sha256),('baseline.json',args.baseline_sha256)]:protected(args.stage/name);check(sha(args.stage/name)==digest,'Pinned configuration mismatch')
    m=json.loads((args.stage/'l2-manifest.json').read_text());b=json.loads((args.stage/'baseline.json').read_text())
    check(re.fullmatch('[a-f0-9]{40}',m['sourceCommit']) and re.fullmatch('[A-Za-z0-9_.:-]{1,15}',b['allowedInterface']),'Invalid source/interface')
    for name,digest in m['toolHashes'].items():check(name in ('l2_upgrade.py','guarded_install.py','dns_readiness.py','durable_recovery.py'),'Unexpected tool');protected(args.stage/name);check(sha(args.stage/name)==digest,'Tool mismatch')
    check(set(m['toolHashes'])=={'l2_upgrade.py','guarded_install.py','dns_readiness.py','durable_recovery.py'},'Incomplete tool pins')
    check({'engine/HostsGuardian.DnsEngine','helper/validator.py','helper/dns_readiness.py'}<=set(m['files']) and all(name.startswith('engine/') or name in ('helper/validator.py','helper/dns_readiness.py') for name in m['files']),'Payload scope violation')
    archive=args.stage/m['archive']['name'];check(archive.parent==args.stage,'Archive path escape');protected(archive);check(sha(archive)==m['archive']['sha256'],'Archive mismatch')
    with tarfile.open(archive) as tar:inspect_archive(tar,m['files'])
    operation=L2Upgrade(args.stage,m,b)
    if args.rollback or args.watchdog:
        protected(operation.backup/'baseline.json');check(sha(operation.backup/'baseline.json')==args.baseline_sha256,'Saved baseline mismatch')
        if args.watchdog:operation.watchdog()
        else:operation.rollback()
        return
    try:operation.apply()
    except BaseException as error:
        evidence=dict(deployment=error_details(error))
        accepted=(operation.backup/'transaction.json').exists() and json.loads((operation.backup/'transaction.json').read_text()).get('phase')=='committed'
        if operation.changed and not accepted:
            try:operation.rollback()
            except BaseException as rollback_error:evidence['rollback']=error_details(rollback_error)
        if operation.backup_created:(operation.backup/'failure.json').write_text(json.dumps(evidence,indent=2)+'\n')
        if 'rollback' in evidence:raise RuntimeError('DEPLOYMENT FAILED; ROLLBACK UNVERIFIED; retained failure.json') from error
        raise


if __name__=='__main__':main()
