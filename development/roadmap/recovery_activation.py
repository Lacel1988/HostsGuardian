"""Reviewed single-unit recovery handover. Import/fixtures never touch production.

The owner must separately approve activation. No Engine restart or network change.
Only an explicit hash-pinned session may acquire policy-restoration authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import signal
import sys
import time
import tempfile
import math


def require(value, message):
    if not value: raise RuntimeError(message)


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protected(path):
    for item in (path, *path.parents):
        info=item.lstat()
        require(info.st_uid==0 and not stat.S_ISLNK(info.st_mode) and not info.st_mode&0o022, 'Unprotected recovery hierarchy')


def run(*args):
    return subprocess.check_output(args,text=True,timeout=15,env=dict(os.environ,LC_ALL='C')).strip()


def loaded_configuration(key, value):
    # PID/start timestamps/next firing change while an unchanged timer runs.
    if key=='ExecStart':
        match=re.search(r'path=([^;]+);\s*argv\[\]=([^;]+);\s*ignore_errors=([^;]+);',value)
        require(match is not None,'Unrecognized loaded recovery execution')
        return tuple(part.strip() for part in match.groups())
    if key=='TimersMonotonic':
        blocks=re.findall(r'\{[^{}]*\}',value)
        require(blocks and not re.sub(r'\{[^{}]*\}','',value).strip(),'Unrecognized loaded timer configuration')
        entries=[]
        for block in blocks:
            legacy=re.fullmatch(r'\{\s*base=(\w+)\s*;\s*value=([^;{}]+)\s*;\s*next_elapse=([^;{}]+)\s*;?\s*\}',block)
            native=re.fullmatch(r'\{\s*(\w+)=([^;{}]+)\s*;\s*next_elapse=([^;{}]+)\s*;?\s*\}',block)
            match=legacy or native
            require(match is not None,'Unrecognized loaded timer entry')
            base,duration,next_value=(x.strip() for x in match.groups())
            require(base in ('OnActiveUSec','OnBootUSec','OnStartupUSec','OnUnitActiveUSec','OnUnitInactiveUSec'),'Unsupported monotonic timer base')
            seconds=parse_monotonic(duration)
            require(seconds>0,'Invalid timer duration')
            # Runtime firing is not definition identity, but still must be a supported representation.
            require(next_value in ('0','infinity') or parse_monotonic(next_value)>=0,'Invalid next firing representation')
            require(all(previous!=base for previous,_ in entries),'Ambiguous duplicate timer base')
            entries.append((base,seconds))
        return tuple(sorted(entries))
    return value


def atomic_unit(path, data):
    """Same-directory atomic publication; failed writes leave previous bytes intact."""
    fd, temporary = tempfile.mkstemp(prefix='.hg-recovery-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        if os.name == 'posix':
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try: os.fsync(directory)
            finally: os.close(directory)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def group_id(user):
    import grp
    import pwd
    pwd.getpwnam(user)
    return grp.getgrnam(user).gr_gid


class Activation:
    def __init__(self, stage, manifest, execute=run):
        self.stage=Path(stage);self.m=manifest;self.run=execute
        require(re.fullmatch('[a-f0-9]{64}',manifest['attempt']), 'Invalid attempt')
        require(re.fullmatch('[a-z_][a-z0-9_-]{0,31}',manifest['user']), 'Invalid recovery user')
        require(re.fullmatch('[a-z0-9-]{1,80}',manifest['unit']), 'Invalid recovery unit')
        require(manifest['intervalSeconds']==90, 'Unreviewed recovery interval')
        self.unit=manifest['unit'];self.user=manifest['user']
        self.service=Path('/etc/systemd/system')/(self.unit+'.service')
        self.timer=Path('/etc/systemd/system')/(self.unit+'.timer')
        self.target=Path('/var/lib/hostsguardian-recovery')/manifest['attempt'][:16]
        self.changed=False

    def command(self):
        return ['/usr/bin/python3','-I','-B',str(self.target/'p0_policy_restore.py'),
                '--session',str(self.target/'session.json'),'--sha256',self.m['files']['session.json'], '--approved-recovery']

    def contents(self):
        command=shlex.join(self.command())
        service=('[Unit]\nDescription=HostsGuardian approved exact policy recovery\nAfter=network-online.target\nWants=network-online.target\n'
                 '[Service]\nType=oneshot\nUser='+self.user+'\nGroup='+self.user+'\nExecStart='+command+'\n'
                 'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=yes\n'
                 'CapabilityBoundingSet=\nAmbientCapabilities=\nUMask=0077\nRestart=on-failure\nRestartSec=5s\n'
                 'TimeoutStartSec=20s\n[Unit]\nStartLimitIntervalSec=0\n')
        timer=('[Unit]\nDescription=HostsGuardian single approved recovery watchdog\n[Timer]\n'
               'OnBootSec=30s\nOnActiveSec=90s\nOnUnitInactiveSec=90s\nAccuracySec=1s\nUnit='+self.unit+'.service\n'
               '[Install]\nWantedBy=timers.target\n')
        return service.encode(),timer.encode()

    def preflight(self):
        protected(self.stage)
        require(not self.target.exists(), 'Attempt exists; inspect or rollback, never overwrite')
        require(set(self.m['files'])=={'session.json','p0_policy_restore.py'}, 'Payload scope mismatch')
        for name,pin in self.m['files'].items():
            protected(self.stage/name);require(digest(self.stage/name)==pin, 'Payload integrity mismatch')
        for path in (self.service,self.timer):
            protected(path);require(digest(path)==self.m['previousFiles'][path.name], 'Previous recovery changed')
            unit=path.name
            require(self.run('systemctl','show',unit,'-p','NeedDaemonReload','--value')=='no', 'Loaded recovery stale')
            properties=self.m['previousProperties'][unit]
            require(set(properties)==({'ExecStart','User','ProtectSystem'} if path==self.service else {'TimersMonotonic'}), 'Incomplete loaded baseline')
            for key,value in properties.items():
                require(loaded_configuration(key,self.run('systemctl','show',unit,'-p',key,'--value'))==loaded_configuration(key,value),'Loaded recovery differs from review')
        require(self.run('systemctl','is-active',self.unit+'.timer')=='active', 'Previous recovery not active')
        require(self.run('systemctl','is-enabled',self.unit+'.timer')=='enabled', 'Previous boot recovery not enabled')
        # Previous exact session must already be restored; explicit reviewed argv only.
        previous=self.m['previousCheckCommand']
        require(isinstance(previous,list) and len(previous)==10 and previous[:3]==['/usr/bin/python3','-I','-B'] and
                previous[4]=='--session' and previous[6]=='--sha256' and previous[8:]==['--approved-recovery','--check-only'] and
                re.fullmatch('[a-f0-9]{64}',previous[7]), 'Invalid previous recovery check')
        for name in (previous[3],previous[5]):
            protected(Path(name));require(digest(name)==self.m['previousPayloadHashes'][name], 'Previous recovery payload changed')
        require('RECOVERY_PRECHECK_PASS' in self.run('runuser','-u',self.user,'--',*previous), 'Old session not closed')
        # New session preflight executes as the eventual unprivileged recovery user.
        command=['/usr/bin/python3','-I','-B',str(self.stage/'p0_policy_restore.py'),'--session',str(self.stage/'session.json'),
                 '--sha256',self.m['files']['session.json'],'--approved-recovery','--check-only']
        require('RECOVERY_PRECHECK_PASS' in self.run('runuser','-u',self.user,'--',*command), 'New session precheck failed')

    def rollback(self):
        protected(self.target)
        for path in (self.service,self.timer):
            saved=self.target/('previous.'+path.suffix[1:])
            protected(saved);require(digest(saved)==self.m['previousFiles'][path.name], 'Rollback backup changed')
            require(path.read_bytes() in (saved.read_bytes(),self.contents()[0 if path==self.service else 1]), 'Recovery unit not owned by attempt')
        self.run('systemctl','stop',self.unit+'.timer');self.run('systemctl','stop',self.unit+'.service')
        for path in (self.service,self.timer):
            atomic_unit(path,(self.target/('previous.'+path.suffix[1:])).read_bytes())
        self.run('systemctl','daemon-reload');self.run('systemctl','start',self.unit+'.timer')
        require(self.run('systemctl','is-active',self.unit+'.timer')=='active', 'Previous recovery rollback unavailable')
        require(self.run('systemctl','is-enabled',self.unit+'.timer')=='enabled', 'Previous boot state lost')

    def arm_handover_guard(self):
        # Independent root-owned systemd transaction guard, not a second policy recovery.
        guard='hg-recovery-handover-'+self.m['attempt'][:16]
        script=Path(__file__).absolute();protected(script)
        manifest=self.stage/'recovery-manifest.json';protected(manifest)
        self.run('systemd-run','--unit='+guard,'--on-active=120s','--timer-property=AccuracySec=1s',
                 '--property=Restart=on-failure','--property=RestartSec=5s','--property=StartLimitIntervalSec=0',
                 '--','/usr/bin/python3','-I','-B',str(script),'--stage',str(self.stage),
                 '--manifest-sha256',digest(manifest),'--approved-activation','--rollback')
        require(self.run('systemctl','is-active',guard+'.timer')=='active','Handover rollback guard unavailable')
        raw=self.run('systemctl','show',guard+'.timer','-p','NextElapseUSecMonotonic','--value')
        scheduled=parse_monotonic(raw)
        uptime=float(Path('/proc/uptime').read_text().split()[0])
        require(0<scheduled-uptime<=122,'Handover rollback guard not scheduled')
        return guard

    def apply(self):
        self.preflight()
        gid=group_id(self.user)
        self.target.parent.mkdir(mode=0o755,exist_ok=True);protected(self.target.parent)
        self.target.mkdir(mode=0o750);os.chown(self.target,0,gid)
        for name in self.m['files']:
            path=self.target/name
            with path.open('xb') as stream:stream.write((self.stage/name).read_bytes())
            os.chown(path,0,gid);path.chmod(0o440)
            require(digest(path)==self.m['files'][name], 'Installed recovery mismatch')
        for path in (self.service,self.timer):
            saved=self.target/('previous.'+path.suffix[1:]);saved.write_bytes(path.read_bytes());saved.chmod(0o600)
        (self.target/'activation.json').write_text(json.dumps(self.m));(self.target/'activation.json').chmod(0o600)
        require('RECOVERY_PRECHECK_PASS' in self.run('runuser','-u',self.user,'--',*self.command(),'--check-only'), 'Installed unprivileged check failed')
        guard=self.arm_handover_guard()
        try:
            self.changed=True
            self.run('systemctl','stop',self.unit+'.timer');self.run('systemctl','stop',self.unit+'.service')
            for path,data in zip((self.service,self.timer),self.contents()):atomic_unit(path,data)
            self.run('systemd-analyze','verify',str(self.service),str(self.timer))
            self.run('systemctl','daemon-reload');self.run('systemctl','start',self.unit+'.service')
            require(self.run('systemctl','show',self.unit+'.service','-p','Result','--value')=='success' and
                    self.run('systemctl','show',self.unit+'.service','-p','ExecMainStatus','--value')=='0','Recovery execution failed')
            self.run('systemctl','start',self.unit+'.timer')
            require(self.run('systemctl','is-active',self.unit+'.timer')=='active' and
                    self.run('systemctl','is-enabled',self.unit+'.timer')=='enabled', 'Recovery timer not armed')
            # systemctl formats absolute boot-monotonic time; compare against uptime.
            raw=self.run('systemctl','show',self.unit+'.timer','-p','NextElapseUSecMonotonic','--value')
            seconds=parse_monotonic(raw)
            uptime=float(Path('/proc/uptime').read_text().split()[0])
            require(0<seconds-uptime<=92, 'No bounded next recovery firing')
            require('RECOVERY_PRECHECK_PASS' in self.run('runuser','-u',self.user,'--',*self.command(),'--check-only'), 'Policy changed during handover')
            self.run('systemctl','stop',guard+'.timer');self.run('systemctl','stop',guard+'.service')
        except BaseException:
            self.rollback();raise


def parse_monotonic(raw):
    require(raw not in ('','0','infinity'), 'Recovery not scheduled')
    units={'us':1e-6,'ms':.001,'s':1,'min':60,'h':3600,'d':86400}
    total=0.0
    for token in raw.split():
        match=re.fullmatch(r'(\d+(?:\.\d+)?)(us|ms|s|min|h|d)',token)
        require(match is not None,'Unknown monotonic time format')
        total+=float(match[1])*units[match[2]]
        require(math.isfinite(total),'Nonfinite monotonic time')
    return total


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--manifest-sha256',required=True);parser.add_argument('--approved-activation',action='store_true')
    parser.add_argument('--rollback',action='store_true');args=parser.parse_args()
    require(os.geteuid()==0 and args.approved_activation,'Explicit privileged activation approval required')
    protected(Path(__file__).absolute());protected(args.stage)
    path=args.stage/'recovery-manifest.json';protected(path)
    require(digest(path)==args.manifest_sha256,'Manifest pin mismatch')
    # Serialize handovers; no parallel timer/session installation.
    import fcntl
    for number in (signal.SIGTERM,signal.SIGINT):signal.signal(number,lambda *_:(_ for _ in ()).throw(SystemExit(1)))
    fd=os.open('/run/hostsguardian-recovery-activation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'a') as lock:
        info=os.fstat(lock.fileno())
        require(info.st_uid==0 and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not info.st_mode&0o077,'Untrusted handover lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        operation=Activation(args.stage,json.loads(path.read_text()))
        if args.rollback:operation.rollback()
        else:operation.apply()


if __name__=='__main__':
    try:main()
    except Exception as error:
        print('RECOVERY_ACTIVATION_UNCONFIRMED: '+type(error).__name__)
        raise SystemExit(1)
