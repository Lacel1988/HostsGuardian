"""Human-gated Engine-only upgrade. Existing helper/socket/Monitor are never mutated."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import ssl
import urllib.request
if __name__=='__main__':
    # -I excludes the script directory. Add only this root-protected tool directory.
    tool=Path(__file__).absolute().with_name('guarded_install.py')
    for item in (tool,*tool.parents):
        info=item.lstat()
        if info.st_uid!=0 or stat.S_ISLNK(info.st_mode) or info.st_mode&0o022:
            raise RuntimeError('Untrusted installer dependency hierarchy')
    sys.path.insert(0,str(tool.parent))
from guarded_install import Deployment, UNIT, HELPER, SOCKET, protected, sha, check, inspect_archive, wait_ready, error_details, exec_start_configuration

UPGRADE_DROPIN=Path('/etc/systemd/system/hostsguardian-engine.service.d/zz-p0-engine-only.conf')


class EngineUpgrade(Deployment):
    def __init__(self,stage,manifest,baseline):
        super().__init__(stage,manifest,baseline)
        self.touched=False

    def stable_components(self,budget=None):
        b=self.baseline
        def output(*args):return self.output(*args,timeout=budget() if budget else 3)
        return (self.preserved() and self.old_engine_unchanged()
                and all(sha(path)==value for path,value in b['helperFiles'].items())
                and output('systemctl','is-enabled',SOCKET)=='enabled'
                and output('systemctl','show',SOCKET,'-p','ActiveState','--value')=='active'
                and output('systemctl','show',HELPER,'-p','MainPID','--value')==str(b['helperPid'])
                and output('dpkg-query','-W','-f=${Version}','hostsguardian-monitor')==b['monitorVersion'])

    def collect(self,remaining,candidate=True):
        # Reuse corrected functional probes: ss family reporting is ownership only.
        deadline=time.monotonic()+remaining
        state=super().collect(remaining,candidate)
        def budget():
            left=deadline-time.monotonic()
            if left<.25:
                state['budgetExhausted']=True
                raise TimeoutError('Engine-only preservation deadline exhausted')
            return min(2,left)
        if not candidate:
            # The baseline already has the helper: rollback must verify it too.
            try:
                import datetime
                snapshot=json.loads(Path(self.baseline['monitorStatusPath']).read_text())
                health=snapshot['validator'];now=datetime.datetime.now(datetime.timezone.utc)
                fresh=all(0 <= (now-datetime.datetime.fromisoformat(x.replace('Z','+00:00'))).total_seconds()<10
                          for x in (snapshot['emittedAtUtc'],health['checkedAtUtc']))
                caps=Path('/proc',str(self.baseline['helperPid']),'status').read_text()
                values={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in caps.splitlines() if ':' in line}
                state['helper']=fresh and snapshot['processId']==state.get('pid') and health['state']=='READY' and health['activeValidationEnabled'] is False and all(int(values[k],16)==0x2000 for k in ('CapPrm','CapEff','CapAmb','CapBnd')) and values['NoNewPrivs']=='1'
            except Exception as error:state['helper']=False;state['helperError']=error_details(error)
        try:
            context=ssl.create_default_context(cafile=self.baseline['certificatePath'])
            request=urllib.request.Request(self.baseline['managementUrl'].removesuffix('/dns/status')+'/v2/policy')
            request.add_header('Authorization','Bearer '+Path(self.baseline['credentialPath']).read_text().strip())
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self,*a,**k):return None
            opener=urllib.request.build_opener(NoRedirect,urllib.request.HTTPSHandler(context=context))
            with opener.open(request,timeout=budget()) as response:readback=json.load(response)
            policy_digest=hashlib.sha256(json.dumps(readback['policy'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
            state['policyReadback']=readback['revision']==self.baseline['policyRevision'] and policy_digest==self.baseline['canonicalPolicySha256'] and sorted(d['deviceId'] for d in readback['policy']['devices'])==self.baseline['registrationIds']
            state['preservation']=state['preservation'] and state['policyReadback']
            state['preservation']=state['preservation'] and self.stable_components(budget)
            if candidate:
                health=state.get('validator',{})
                state['helper']=state['helper'] and health.get('mode')=='Passive' and health.get('approvedTargetCount')==0 and health.get('modeReason')=='Disabled'
        except Exception as error:state['preservation']=False;state['preservationError']=error_details(error)
        return state

    def preflight(self):
        protected(self.stage,True);protected(UPGRADE_DROPIN.parent,True)
        check(not UPGRADE_DROPIN.exists() and not UPGRADE_DROPIN.is_symlink(),'Existing Engine-only override requires review')
        check(not self.release.exists() and not self.backup.exists(),'Attempt already exists; do not overwrite evidence')
        for path in [*self.baseline['unitFiles'],*self.baseline['helperFiles']]:protected(Path(path))
        protected(Path(self.baseline['workingDirectory']),True)
        for name in self.baseline['engineFiles']:protected(Path(self.baseline['workingDirectory'])/name)
        check(self.stable_components(),'Baseline policy/security/units/helper/socket/Monitor changed')
        check(self.prop('Environment')==self.baseline['environment'],'Loaded environment changed')
        check(exec_start_configuration(self.prop('ExecStart'))==exec_start_configuration(self.baseline['execStart']),'Loaded executable changed')
        check(self.prop('WorkingDirectory')==self.baseline['workingDirectory'],'Loaded working directory changed')
        check(self.prop('User')==self.baseline['engineUser'] and self.prop('Group')==self.baseline['engineGroup'],'Service identity changed')
        check('HOSTSGUARDIAN_ACTIVE_VALIDATION=0' in self.prop('Environment').split(),'Baseline must be explicitly OFF')
        self.backup.mkdir(mode=0o700,parents=True);self.backup_created=True;protected(self.backup,True)
        (self.backup/'baseline.json').write_bytes((self.stage/'baseline.json').read_bytes());(self.backup/'baseline.json').chmod(0o600)
        wait_ready(lambda remaining:self.collect(remaining,False),self.backup,'baseline')

    def prepare(self):
        self.release.mkdir(mode=0o755,parents=True);protected(self.release,True)
        with tarfile.open(self.stage/self.manifest['archive']['name']) as archive:
            inspect_archive(archive,self.manifest['files'])
            archive.extractall(self.release,filter='data')
        for folder in self.release.rglob('*'):
            if folder.is_dir():folder.chmod(0o755)
        for name,item in self.manifest['files'].items():
            protected(self.release/name);check(sha(self.release/name)==item['sha256'],'Extracted payload changed')
        check(self.stable_components(),'Preservation changed before Engine restart')

    def activate(self):
        self.run('systemctl','stop',UNIT)
        # Mark before writing so partial writes/reload/start are rollback-owned.
        self.touched=True
        UPGRADE_DROPIN.write_text('[Service]\nExecStart=\nExecStart='+str(self.release/'engine/HostsGuardian.DnsEngine')+'\nWorkingDirectory='+str(self.release/'engine')+'\nEnvironment=HOSTSGUARDIAN_ACTIVE_VALIDATION=0\nEnvironment=HOSTSGUARDIAN_ACTIVE_VALIDATION_DEVICE_IDS=\nEnvironment=HOSTSGUARDIAN_ACTIVE_VALIDATION_SECONDS=\n')
        UPGRADE_DROPIN.chmod(0o644)
        self.run('systemctl','daemon-reload');self.run('systemctl','start',UNIT)
        wait_ready(lambda remaining:self.collect(remaining,True),self.backup,'candidate')

    def apply(self):
        self.preflight();self.prepare()
        # stop itself can fail after stopping: rollback is required once activation starts.
        self.changed=True
        self.activate()
        check(self.stable_components(),'Final preservation failed')
        (self.backup/'result.json').write_text(json.dumps(dict(status='ENGINE_ONLY_DEPLOYED_ACTIVE_OFF',sourceCommit=self.manifest['sourceCommit'],helperRestarted=False,monitorChanged=False,policyPreserved=True))+'\n')

    def rollback(self):
        check(self.old_engine_unchanged(),'Original protected Engine altered; refuse rollback')
        self.run('systemctl','stop',UNIT)
        if self.touched and UPGRADE_DROPIN.exists():UPGRADE_DROPIN.unlink()
        self.run('systemctl','daemon-reload');self.run('systemctl','start',UNIT)
        wait_ready(lambda remaining:self.collect(remaining,False),self.backup,'rollback')
        check(self.stable_components(),'Rollback preservation failed')
        (self.backup/'rollback-result.json').write_text(json.dumps(dict(status='ROLLBACK_VERIFIED',activeValidationEnabled=False,policyPreserved=True))+'\n')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--manifest-sha256',required=True);parser.add_argument('--baseline-sha256',required=True)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--rollback',action='store_true')
    args=parser.parse_args()
    check(args.apply!=args.rollback,'Choose exactly one explicitly reviewed action')
    check(os.geteuid()==0,'Human privileged execution required')
    protected(Path(__file__).absolute());protected(args.stage,True)
    for name in ('engine-upgrade-manifest.json','baseline.json','guarded_install.py','dns_readiness.py'):protected(args.stage/name)
    check(sha(args.stage/'engine-upgrade-manifest.json')==args.manifest_sha256 and sha(args.stage/'baseline.json')==args.baseline_sha256,'Pinned manifest/baseline mismatch')
    manifest=json.loads((args.stage/'engine-upgrade-manifest.json').read_text());baseline=json.loads((args.stage/'baseline.json').read_text())
    for name,value in manifest['toolHashes'].items():check(sha(args.stage/name)==value,'Pinned tool mismatch')
    check(re.fullmatch('[0-9a-f]{40}',manifest['sourceCommit']) is not None,'Invalid source commit')
    allowed=set(manifest['files'])
    check('engine/HostsGuardian.DnsEngine' in allowed and 'helper/dns_readiness.py' in allowed and all(n.startswith('engine/') or n=='helper/dns_readiness.py' for n in allowed),'Engine-only payload required')
    archive=args.stage/manifest['archive']['name'];protected(archive)
    check(archive.parent==args.stage and sha(archive)==manifest['archive']['sha256'],'Payload hash/path mismatch')
    operation=EngineUpgrade(args.stage,manifest,baseline)
    if args.rollback:
        protected(operation.backup/'baseline.json');check(sha(operation.backup/'baseline.json')==args.baseline_sha256,'Saved baseline mismatch')
        if UPGRADE_DROPIN.exists():
            protected(UPGRADE_DROPIN);check(UPGRADE_DROPIN.read_text().splitlines()[2]=='ExecStart='+str(operation.release/'engine/HostsGuardian.DnsEngine'),'Override does not belong to attempt')
            operation.touched=True
        else:
            loaded=exec_start_configuration(operation.prop('ExecStart'))[0]
            check(loaded in (baseline['oldExecutable'],str(operation.release/'engine/HostsGuardian.DnsEngine')),'Unexpected loaded executable; manual review required')
        operation.rollback();return
    try:operation.apply()
    except BaseException as error:
        evidence=dict(deployment=error_details(error))
        if operation.changed:
            try:operation.rollback()
            except BaseException as rollback_error:evidence['rollback']=error_details(rollback_error)
        if operation.backup_created:(operation.backup/'failure.json').write_text(json.dumps(evidence,indent=2)+'\n')
        if 'rollback' in evidence:raise RuntimeError('DEPLOYMENT FAILED; ROLLBACK FAILED; preserved failure.json requires human action') from error
        raise


if __name__=='__main__':main()
