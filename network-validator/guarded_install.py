"""Future reviewed root deployment only. Import/tests never perform production operations.

No package dependency installation, ARP enablement, policy restoration, user/group creation,
network/firewall changes or file capability grants. Default invocation refuses mutation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import ssl
import stat
import subprocess
import tarfile
import time
import urllib.request
import traceback

UNIT='hostsguardian-engine.service'
HELPER='hostsguardian-network-validator.service'
SOCKET='hostsguardian-network-validator.socket'
SOCKET_PATH=Path('/run/hostsguardian-validator/validator.sock')
DROPIN=Path('/etc/systemd/system/hostsguardian-engine.service.d/99-network-validator.conf')


def check(value,message):
    if not value:raise RuntimeError(message)


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protected(path,directory=False):
    path=Path(path)
    check(path.is_absolute() and str(path)==os.path.normpath(path),'Noncanonical path')
    for item in (path,*path.parents):
        info=item.lstat()
        check(info.st_uid==0 and not stat.S_ISLNK(info.st_mode) and not info.st_mode&0o022,'Root protection missing: '+str(item))
        check(stat.S_ISDIR(info.st_mode) if item!=path or directory else stat.S_ISREG(info.st_mode),'Unexpected file type')


def inspect_archive(archive,files):
    """Validate all bytes/types before extracting into a newly created root-only directory."""
    seen=set()
    for member in archive.getmembers():
        name=PurePosixPath(member.name)
        check(member.isfile() and not name.is_absolute() and '..' not in name.parts and str(name)==member.name and member.name not in seen,'Unsafe/duplicate archive member')
        check(member.name in files,'Unexpected archive file')
        item=files[member.name];check(member.size==item['size'] and member.mode==int(item['mode'],8) and member.uid==member.gid==0,'Archive size/mode/owner mismatch')
        stream=archive.extractfile(member);check(hashlib.sha256(stream.read()).hexdigest()==item['sha256'],'Archive hash mismatch');seen.add(member.name)
    check(seen==set(files),'Incomplete archive')


MIN_PROBE_BUDGET = .25


def error_details(error):
    # No frame locals/HTTP headers/credentials. Commands here are only systemctl/ss.
    result = dict(type=type(error).__name__, message=str(error),
                  traceback="".join(traceback.format_exception(type(error), error, error.__traceback__)))
    if isinstance(error, subprocess.TimeoutExpired):
        result.update(command=list(error.cmd), timeoutSeconds=error.timeout)
    return result


def dns_socket_rows(text):
    """Select local DNS sockets only, never a peer port or a similarly named PID."""
    return [line for line in text.splitlines()
            if len(line.split()) >= 6 and line.split()[0] in ('udp', 'tcp')
            and line.split()[4].rsplit(':', 1)[-1] == '53']


def dns_socket_ownership(rows, pid):
    return pid > 0 and all(
        any(line.split()[0] == transport for line in rows)
        for transport in ('udp', 'tcp')) and all(
        re.findall(r'pid=(\d+),', line) and
        set(re.findall(r'pid=(\d+),', line)) == {str(pid)} for line in rows)


def exec_start_configuration(value):
    # PID/start/stop/result fields are runtime evidence, not executable configuration.
    match=re.search(r'path=([^;]+);\s*argv\[\]=([^;]+);\s*ignore_errors=([^;]+);',value)
    check(match is not None, 'Unrecognized loaded ExecStart format')
    return tuple(part.strip() for part in match.groups())


def wait_ready(probe,folder,phase,timeout=90,clock=time.monotonic,pause=time.sleep):
    check(timeout >= MIN_PROBE_BUDGET, 'Readiness timeout too short')
    deadline=clock()+timeout;attempt=0;entry=None;last_complete=None
    required=('service','ipv4Udp','ipv4Tcp','ipv6Udp','ipv6Tcp','ownership','https','preservation','helper')
    with (folder/(phase+'-readiness.jsonl')).open('x') as log:
        while deadline-clock() >= MIN_PROBE_BUDGET:
            attempt+=1
            remaining=deadline-clock()
            try:state=probe(remaining)
            except Exception as error:state={'probeError':error_details(error)}
            missing=[key for key in required if not state.get(key)]
            entry=dict(attempt=attempt,utc=datetime.now(timezone.utc).isoformat(),phase=phase,
                       remainingBudgetSeconds=remaining,missing=missing,state=state)
            log.write(json.dumps(entry)+'\n');log.flush();os.fsync(log.fileno())
            if not state.get('budgetExhausted'):last_complete=entry
            if not missing:
                (folder/(phase+'-readiness-final.json')).write_text(json.dumps(entry,indent=2)+'\n')
                return state
            pause(min(.25,max(0,deadline-clock())))
        # Do not launch a near-zero timeout sweep which overwrites useful diagnostics.
        check(entry is not None, 'No readiness attempt completed')
        if last_complete is not None and last_complete is not entry:
            terminal=entry;entry=dict(last_complete);entry['terminalIncompleteAttempt']=terminal
        entry['deadlineExhausted']=True
        (folder/(phase+'-readiness-final.json')).write_text(json.dumps(entry,indent=2)+'\n')
        raise RuntimeError(phase+' readiness timeout: '+', '.join(entry['missing']))


class Deployment:
    def __init__(self,stage,manifest,baseline):
        self.stage=stage;self.manifest=manifest;self.baseline=baseline
        deployment_id=manifest.get('deploymentId',manifest['sourceIdentity'])
        check(re.fullmatch('[0-9a-f]{64}', deployment_id), 'Invalid deployment identity')
        self.release=Path('/opt/hostsguardian/releases')/deployment_id[:16]
        self.backup=Path('/var/lib/hostsguardian-deployment/rollback')/(deployment_id[:16]+'-pre')
        self.created_units=[];self.changed=False;self.installed_monitor=False;self.backup_created=False

    @staticmethod
    def output(*args,timeout=3):return subprocess.check_output(args,text=True,timeout=timeout).strip()
    @staticmethod
    def run(*args):subprocess.run(args,check=True,timeout=60)
    def prop(self,name,timeout=3):return self.output('systemctl','show',UNIT,'-p',name,'--value',timeout=timeout)

    def preserved(self):
        b=self.baseline
        return sha(b['policyPath'])==b['policySha256'] and all(sha(name)==digest for name,digest in b['securityFiles'].items()) and all(sha(name)==digest for name,digest in b['unitFiles'].items())

    def old_engine_unchanged(self):
        root=Path(self.baseline['workingDirectory'])
        return not any(p.is_symlink() for p in root.rglob('*')) and {p.relative_to(root).as_posix():sha(p) for p in root.rglob('*') if p.is_file()}==self.baseline['engineFiles']

    def preflight(self):
        b=self.baseline
        protected(Path('/etc/systemd/system'),True)
        if DROPIN.parent.exists():protected(DROPIN.parent,True)
        for path in b['unitFiles']:protected(Path(path))
        check(self.preserved(),'Policy/security/existing unit bytes changed since review')
        check(self.prop('ActiveState')=='active' and self.prop('SubState')=='running','Baseline service unavailable')
        check(exec_start_configuration(self.prop('ExecStart'))==exec_start_configuration(b['execStart']) and self.prop('WorkingDirectory')==b['workingDirectory'],'Loaded execution configuration changed')
        check(self.prop('Environment')==b['environment'],'Loaded configuration changed')
        check(self.prop('User')==b['engineUser'] and self.prop('Group')==b['engineGroup'],'Service identity changed')
        check(self.output('dpkg-query','-W','-f=${Version}','hostsguardian-monitor')==b['monitorVersion'],'Installed Monitor changed')
        protected(self.stage/b['rollbackMonitor'])
        check(sha(self.stage/b['rollbackMonitor'])==b['rollbackMonitorSha256'],'Rollback Monitor mismatch')
        for package in ('python3-cairo','python3-gi-cairo'):
            check(self.output('dpkg-query','-W','-f=${Status}',package)=='install ok installed','Explicit prerequisite not installed: '+package)
        check(not self.release.exists() and not self.backup.exists() and not DROPIN.exists(),'Candidate/backup/drop-in already exists; inspect before retry')
        for name in (HELPER,SOCKET):
            check(not Path('/etc/systemd/system',name).exists() and not Path('/usr/lib/systemd/system',name).exists() and self.output('systemctl','show',name,'-p','LoadState','--value')=='not-found','Unexpected existing helper unit')
        check(not SOCKET_PATH.exists() and not SOCKET_PATH.is_symlink(),'Existing socket requires review, never blindly unlink')
        if SOCKET_PATH.parent.exists():protected(SOCKET_PATH.parent,True)
        # Preserve old publication for rollback; never edit/move it.
        check(self.old_engine_unchanged(),'Old Engine publication changed')
        check(self.output('id','-u',b['engineUser'])==str(b['engineUid']),'Service UID changed')
        check(self.output('getent','group',b['engineGroup']).split(':')[2]==str(b['engineGid']),'Service GID changed')

    def collect(self,remaining,candidate=True):
        b=self.baseline;deadline=time.monotonic()+remaining
        state=dict(service=False,ipv4Udp=False,ipv4Tcp=False,ipv6Udp=False,ipv6Tcp=False,
                   ownership=False,https=False,preservation=False,helper=not candidate)
        def budget():
            left=deadline-time.monotonic()
            if left < MIN_PROBE_BUDGET:
                state['budgetExhausted']=True
                raise TimeoutError('Readiness phase budget exhausted; operation not started')
            return min(2, left)
        pid=0
        try:
            pid=int(self.prop('MainPID',budget()));state['pid']=pid
            state['service']=pid>0 and self.prop('ActiveState',budget())=='active' and self.prop('SubState',budget())=='running'
            if pid:
                state['processUid']=Path('/proc',str(pid)).stat().st_uid
                expected=str(self.release/'engine/HostsGuardian.DnsEngine') if candidate else b['oldExecutable']
                state['processExecutable']=os.readlink('/proc/'+str(pid)+'/exe')
                caps={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line}
                state['service']=state['service'] and state['processUid']==b['engineUid'] and state['processExecutable']==expected and all(int(caps[key],16)==0x400 for key in ('CapPrm','CapEff','CapAmb','CapBnd')) and caps['NoNewPrivs']=='1'
                state['engineCapabilities']={key:caps[key] for key in ('CapPrm','CapEff','CapAmb','NoNewPrivs')}
        except Exception as error:state['serviceError']=error_details(error)
        try:
            rows=[];state['socketRowsByFamily']={}
            for family in ('-4','-6'):
                found=dns_socket_rows(self.output('ss','-H',family,'-luntp',timeout=budget()))
                rows+=found;state['socketRowsByFamily'][family]=found
            state['socketRows']=rows;state['ownership']=dns_socket_ownership(rows,pid)
        except Exception as error:state['ownershipError']=error_details(error)
        try:
            probe_path=(self.release/'helper/dns_readiness.py') if candidate else self.stage/'dns_readiness.py'
            protected(probe_path)
            check(sha(probe_path)==self.manifest['files']['helper/dns_readiness.py']['sha256'],'Readiness helper integrity mismatch')
            spec=importlib.util.spec_from_file_location('reviewed_dns_readiness',probe_path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            # AF_INET6 dual-mode sockets can serve IPv4 without any ss -4 row.
            # Never gate protocol probes on the family reported by ss.
            for address,prefix in ((b['dnsIpv4'],'ipv4'),(b['dnsIpv6'],'ipv6')):
                for transport in ('udp','tcp'):
                    key=prefix+transport.title()
                    try:
                        state[key+'Evidence']=module.probe(address,transport,b['readinessDomain'],timeout=budget())
                        state[key]=True
                    except Exception as error:state[key+'Error']=error_details(error)
        except Exception as error:state['dnsProbeSetupError']=error_details(error)
        try:
            context=ssl.create_default_context(cafile=b['certificatePath'])
            request=urllib.request.Request(b['managementUrl']);request.add_header('Authorization','Bearer '+Path(b['credentialPath']).read_text().strip())
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self,*args,**kwargs):return None
            opener=urllib.request.build_opener(NoRedirect,urllib.request.HTTPSHandler(context=context))
            with opener.open(request,timeout=budget()) as response:status=json.load(response)
            state['https']=status.get('implementation')=='HostsGuardian.DnsEngine' and status.get('managementListening') and status.get('policyLoaded') and status.get('policyRevision')==b['policyRevision'] and not status.get('emergencySafeMode') and status.get('udpListening') and status.get('tcpListening') and status.get('ipv6UdpState')=='Listening' and status.get('ipv6TcpState')=='Listening'
            state['management']={key:status.get(key) for key in ('policyRevision','emergencySafeMode','ipv6UdpState','ipv6TcpState')}
        except Exception as error:state['managementError']=error_details(error)
        try:state['preservation']=self.preserved() and (candidate or self.old_engine_unchanged())
        except Exception as error:state['preservationError']=error_details(error)
        if candidate:
            try:
                snapshot=json.loads(Path(b['monitorStatusPath']).read_text());health=snapshot.get('validator',{})
                fresh=(datetime.now(timezone.utc)-datetime.fromisoformat(snapshot['emittedAtUtc'].replace('Z','+00:00'))).total_seconds()
                checked=(datetime.now(timezone.utc)-datetime.fromisoformat(health['checkedAtUtc'].replace('Z','+00:00'))).total_seconds()
                helper_pid=int(self.output('systemctl','show',HELPER,'-p','MainPID','--value',timeout=budget()))
                helper_caps={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc',str(helper_pid),'status').read_text().splitlines() if ':' in line}
                state['helper']=helper_pid>0 and snapshot['processId']==pid and 0<=fresh<10 and 0<=checked<10 and health['state']=='READY' and health['activeValidationEnabled'] is False and all(int(helper_caps[key],16)==0x2000 for key in ('CapPrm','CapEff','CapAmb','CapBnd')) and helper_caps['NoNewPrivs']=='1'
                state['helperPid']=helper_pid;state['validator']=health
            except Exception as error:state['helperError']=error_details(error)
        if deadline-time.monotonic() < MIN_PROBE_BUDGET:state['budgetExhausted']=True
        return state

    def apply(self):
        self.preflight();b=self.baseline
        self.backup.mkdir(mode=0o700,parents=True);self.backup_created=True;protected(self.backup,True)
        (self.backup/'baseline.json').write_text(json.dumps(b,indent=2)+'\n');os.chmod(self.backup/'baseline.json',0o600)
        shutil.copyfile(self.stage/b['rollbackMonitor'],self.backup/b['rollbackMonitor']);os.chmod(self.backup/b['rollbackMonitor'],0o600)
        check(sha(self.backup/b['rollbackMonitor'])==b['rollbackMonitorSha256'],'Rollback package snapshot mismatch')
        shutil.copytree(b['workingDirectory'],self.backup/'engine',symlinks=False)
        check(self.old_engine_unchanged() and {p.relative_to(self.backup/'engine').as_posix():sha(p) for p in (self.backup/'engine').rglob('*') if p.is_file()}==b['engineFiles'],'Engine changed during rollback snapshot')
        self.release.mkdir(mode=0o755,parents=True);protected(self.release,True)
        with tarfile.open(self.stage/self.manifest['archive']['name']) as archive:
            inspect_archive(archive,self.manifest['files']);archive.extractall(self.release,filter='data')
        # tar extraction is root, exact manifest types/modes; no links or directory entries.
        for folder in self.release.rglob('*'):
            if folder.is_dir():folder.chmod(0o755)
        replacements={'@ENGINE_USER@':b['engineUser'],'@ENGINE_GROUP@':b['engineGroup'],'@ENGINE_UID@':str(b['engineUid']),
            '@ALLOWED_INTERFACE@':b['allowedInterface'],'@ROOT_PROTECTED_HELPER@':str(self.release/'helper/validator.py'),
            '@ROOT_PROTECTED_ENGINE_EXECUTABLE@':str(self.release/'engine/HostsGuardian.DnsEngine')}
        for name in (HELPER,SOCKET):
            content=(self.release/'units'/(name+'.in')).read_text()
            for key,value in replacements.items():content=content.replace(key,value)
            check('@' not in content,'Unresolved unit template')
            target=Path('/etc/systemd/system',name);self.created_units.append(target);target.write_text(content);target.chmod(0o644)
        DROPIN.parent.mkdir(exist_ok=True)
        self.changed=True
        DROPIN.write_text('[Service]\nExecStart=\nExecStart='+str(self.release/'engine/HostsGuardian.DnsEngine')+'\nWorkingDirectory='+str(self.release/'engine')+'\nEnvironment=HOSTSGUARDIAN_VALIDATOR_SOCKET='+str(SOCKET_PATH)+'\nEnvironment=HOSTSGUARDIAN_ACTIVE_VALIDATION=0\n')
        DROPIN.chmod(0o644)
        self.run('systemd-analyze','verify',str(self.created_units[0]),str(self.created_units[1]))
        self.run('systemctl','stop',UNIT)
        check(self.preserved(),'Preservation changed before restart; policy is never restored automatically')
        self.installed_monitor=True;self.run('dpkg','--install',str(self.release/('hostsguardian-monitor_'+self.manifest['monitorVersion']+'_all.deb')))
        self.run('systemctl','daemon-reload');self.run('systemctl','start',SOCKET);self.run('systemctl','start',UNIT)
        wait_ready(lambda remaining:self.collect(remaining,True),self.backup,'candidate')
        (self.backup/'result.json').write_text(json.dumps(dict(status='DEPLOYED_IPC_VERIFIED_ACTIVE_ARP_DISABLED',sourceIdentity=self.manifest['sourceIdentity'],policyPreserved=True,activeValidationEnabled=False,unitConfigurationChanged=True,networkConfigurationChanged=False,daemonReloadPerformed=True),indent=2)+'\n')

    def rollback(self):
        # Only revert files created by this attempt. Prior Engine/policy/security remain untouched.
        self.run('systemctl','stop',UNIT)
        for name in (HELPER,SOCKET):
            loaded=self.output('systemctl','show',name,'-p','LoadState','--value')
            if loaded!='not-found':self.run('systemctl','stop',name)
        if self.changed and DROPIN.exists():DROPIN.unlink()
        for path in self.created_units:
            if path.exists():path.unlink()
        if self.installed_monitor:self.run('dpkg','--install',str(self.backup/self.baseline['rollbackMonitor']))
        check(self.old_engine_unchanged(),'Old Engine bytes changed; refuse to execute altered rollback, manual review required')
        self.run('systemctl','daemon-reload');self.run('systemctl','start',UNIT)
        wait_ready(lambda remaining:self.collect(remaining,False),self.backup,'rollback')
        (self.backup/'rollback-result.json').write_text(json.dumps(dict(status='ROLLED_BACK',policyPreserved=self.preserved(),inactiveCandidateRetained=str(self.release)),indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,required=True);parser.add_argument('--expected-manifest-sha256',required=True);parser.add_argument('--expected-baseline-sha256',required=True)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--approve-pending-daemon-reload',action='store_true');args=parser.parse_args()
    check(args.apply and args.approve_pending_daemon_reload,'No mutations authorized by default; both reviewed flags required')
    check(os.geteuid()==0,'Future privileged human execution only')
    protected(Path(__file__).absolute());protected(args.stage,True)
    for name in ('payload-manifest.json','baseline.json'):protected(args.stage/name)
    check(sha(args.stage/'payload-manifest.json')==args.expected_manifest_sha256,'Pinned manifest mismatch')
    check(sha(args.stage/'baseline.json')==args.expected_baseline_sha256,'Pinned preservation baseline mismatch')
    manifest=json.loads((args.stage/'payload-manifest.json').read_text());baseline=json.loads((args.stage/'baseline.json').read_text())
    check(re.fullmatch('[0-9a-f]{64}',manifest['sourceIdentity']),'Invalid candidate identity')
    check(re.fullmatch('[A-Za-z0-9_.:-]{1,15}',baseline['allowedInterface']),'Invalid reviewed interface')
    for key in ('engineUser','engineGroup'):check(re.fullmatch('[a-z_][a-z0-9_-]{0,31}',baseline[key]),'Invalid service identity')
    archive=args.stage/manifest['archive']['name'];protected(archive)
    check(sha(archive)==manifest['archive']['sha256'],'Payload archive mismatch')
    with tarfile.open(archive) as tar:inspect_archive(tar,manifest['files'])
    operation=Deployment(args.stage,manifest,baseline)
    try:operation.apply()
    except BaseException as error:
        if operation.backup_created:
            (operation.backup/'deployment-failure.json').write_text(json.dumps(dict(deployment=error_details(error)),indent=2)+'\n')
        if operation.changed or operation.created_units or operation.installed_monitor:
            try:operation.rollback()
            except BaseException as rollback_error:
                (operation.backup/'deployment-failure.json').write_text(json.dumps(dict(deployment=error_details(error),rollback=error_details(rollback_error)),indent=2)+'\n')
                raise RuntimeError('Deployment failed: '+str(error)+'; ROLLBACK FAILED: '+str(rollback_error)) from rollback_error
        raise


if __name__=='__main__':main()
