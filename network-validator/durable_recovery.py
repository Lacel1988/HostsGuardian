"""Root-owned boot dispatcher for a pinned pending upgrade; never runs on import."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ROOT=Path('/var/lib/hostsguardian-deployment/recovery')
STAGING=Path('/var/lib/hostsguardian-deployment/staging')
PENDING=ROOT/'pending.json'
UNIT_PATH=Path('/etc/systemd/system/hostsguardian-deployment-recovery.service')
UNIT_BYTES=b'''# HostsGuardian guarded recovery v1
[Unit]
Description=HostsGuardian pending release recovery
Wants=network-online.target
After=network-online.target hostsguardian-engine.service hostsguardian-network-validator.service
StartLimitIntervalSec=1800s
StartLimitBurst=3
ConditionPathExists=/var/lib/hostsguardian-deployment/recovery/pending.json
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 -I -B /var/lib/hostsguardian-deployment/recovery/consumer.py
TimeoutStartSec=650s
Restart=on-failure
RestartSec=10s
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_DAC_READ_SEARCH
ProtectSystem=strict
ReadWritePaths=/etc/systemd/system /var/lib/hostsguardian-deployment /run
ProtectHome=read-only
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
[Install]
WantedBy=multi-user.target
'''

def protected(path):
    for item in (path,*path.parents):
        info=item.lstat()
        if info.st_uid!=0 or stat.S_ISLNK(info.st_mode) or info.st_mode&0o022:
            raise RuntimeError('Unprotected recovery path')

def read_pending():
    protected(PENDING)
    if PENDING.stat().st_size>4096:raise RuntimeError('Oversized recovery state')
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d:raise RuntimeError('Duplicate recovery field')
            d[k]=v
        return d
    state=json.loads(PENDING.read_text(),object_pairs_hook=unique)
    if set(state)!={'identity','stage','manifestSha256','baselineSha256','installerSha256'}:
        raise RuntimeError('Invalid recovery state')
    for key in ('identity','manifestSha256','baselineSha256','installerSha256'):
        if not isinstance(state[key],str) or not re.fullmatch('[a-f0-9]{64}',state[key]):raise RuntimeError('Invalid recovery pin')
    stage=STAGING/('reliability-'+state['identity'][:16])
    if state['stage']!=str(stage):raise RuntimeError('Recovery stage escape')
    for name,key in [('l2_upgrade.py','installerSha256'),('l2-manifest.json','manifestSha256'),('baseline.json','baselineSha256')]:
        path=stage/name;protected(path)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=state[key]:raise RuntimeError('Recovery pin mismatch')
    manifest=json.loads((stage/'l2-manifest.json').read_text())
    if manifest.get('sourceIdentity')!=state['identity']:raise RuntimeError('Recovery identity mismatch')
    return state

def command(state):
    return ['/usr/bin/python3','-I','-B',str(Path(state['stage'])/'l2_upgrade.py'),
            '--stage',state['stage'],'--manifest-sha256',state['manifestSha256'],
            '--baseline-sha256',state['baselineSha256'],'--watchdog']

def main():
    if os.geteuid()!=0:raise RuntimeError('Recovery requires reviewed root unit')
    if not PENDING.exists():return
    # exec retains the service timeout boundary and avoids a second parent/child lifetime.
    args=command(read_pending());os.execv(args[0],args)

if __name__=='__main__':main()
