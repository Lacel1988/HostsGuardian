"""Generate pinned transfer bootstrap; generation never deploys or invokes systemd."""
from pathlib import Path, PurePosixPath
import json

def render(pins,names):
    # Transfer location is an explicit packaging input, independent of an operator account.
    transfer=PurePosixPath(pins.get('transferDirectory','/var/tmp/hostsguardian-transfer'))
    archive=PurePosixPath(pins['archive'])
    if not transfer.is_absolute() or '..' in transfer.parts or len(archive.parts)!=1 or archive.name!=pins['archive']:
        raise ValueError('Absolute transfer directory and archive basename required')
    constants=dict(TRANSFER_DIRECTORY=str(transfer),ARCHIVE_NAME=pins['archive'],ARCHIVE_PIN=pins['archiveSha256'],ATTEMPT=pins['attempt'],
        NAMES=sorted(names),MANIFEST_PIN=pins['manifestSha256'],BASELINE_PIN=pins['baselineSha256'])
    code='''
import hashlib,io,os,stat,subprocess,tarfile
from pathlib import Path,PurePosixPath
ARCHIVE=Path(TRANSFER_DIRECTORY)/ARCHIVE_NAME
STAGE=Path('/var/lib/hostsguardian-deployment/staging')/('reliability-'+ATTEMPT)
def require(ok,message):
 if not ok:raise RuntimeError(message)
def protected(path):
 for item in (path,*path.parents):
  info=item.lstat();require(info.st_uid==0 and not stat.S_ISLNK(info.st_mode) and not info.st_mode&0o022,'Unprotected staging')
def main():
 require(os.geteuid()==0,'Separate deployment authorization required')
 protected(STAGE.parent);require(not STAGE.exists() and not STAGE.is_symlink(),'Attempt exists')
 data=ARCHIVE.read_bytes();require(hashlib.sha256(data).hexdigest()==ARCHIVE_PIN,'Transfer hash mismatch')
 with tarfile.open(fileobj=io.BytesIO(data)) as archive:
  members=archive.getmembers();require(len(members)==len(NAMES) and {m.name for m in members}==set(NAMES),'Inventory mismatch')
  for m in members:
   name=PurePosixPath(m.name)
   require(m.isfile() and not name.is_absolute() and '..' not in name.parts and str(name)==m.name and m.uid==m.gid==0 and m.mode==0o600,'Unsafe member')
  STAGE.mkdir(mode=0o700)
  for m in members:
   path=STAGE/m.name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   with path.open('xb') as stream:stream.write(archive.extractfile(m).read());stream.flush();os.fsync(stream.fileno())
   path.chmod(0o600)
 protected(STAGE)
 # Persist directory entries as well as file contents before arming durable recovery.
 for directory in [*sorted((p for p in STAGE.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True),STAGE,STAGE.parent]:
  if os.name=='posix':
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
   try:os.fsync(fd)
   finally:os.close(fd)
 # PID1 owns worker and separately scheduled rollback timer. Parent loss cannot kill either
 # through a subprocess timeout. Worker has a bounded runtime; rollback is a different unit.
 subprocess.run(['systemd-run','--unit=hg-l2-install-'+ATTEMPT,'--wait','--collect',
  '--property=Type=exec','--property=RuntimeMaxSec=900s','--property=TimeoutStopSec=15s',
  '--property=KillMode=control-group','--','/usr/bin/python3','-I','-B',str(STAGE/'l2_upgrade.py'),
  '--stage',str(STAGE),'--manifest-sha256',MANIFEST_PIN,'--baseline-sha256',BASELINE_PIN,'--apply'],check=True)
 print('ENGINE_HELPER_RELIABILITY_DEPLOYED_ACTIVE_OFF')
if __name__=='__main__':main()
'''
    return '\n'.join(k+'='+repr(v) for k,v in constants.items())+'\n'+code
