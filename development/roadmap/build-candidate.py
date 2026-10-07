"""Unprivileged reproducible development artifacts; never installs or touches a running service."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile

root = Path(__file__).resolve().parents[2]
if sys.platform != 'linux' or root.parent != Path.home() / 'hostsguardian-dev' or not root.name.startswith('roadmap-'):
    raise SystemExit('Only an isolated Linux development candidate is supported')
def git(*args):
    return subprocess.check_output(['git',*args],cwd=root,text=True).strip()
if git('status','--porcelain') or git('branch','--show-current') != 'dev/roadmap-integration':
    raise SystemExit('A clean owned candidate is required')
commit = git('rev-parse','HEAD')
output = root.parent / (root.name+'-artifacts')
output.mkdir(mode=0o700)
engine = output/'engine'
subprocess.run(['dotnet','publish','HostsGuardian.DnsEngine','-c','Release','-r','linux-x64','--self-contained','true','-o',str(engine)],cwd=root,check=True)
sys.path.insert(0,str(root/'linux-monitor'))
from build_monitor_package import build_monitor_package
version='0.4.0+roadmap.'+commit[:12]
package,deb=build_monitor_package(root/'linux-monitor',output,version)
archive=output/'engine-linux-x64.tar.gz'
with tarfile.open(archive,'w:gz') as target:
    target.add(engine,arcname='engine')
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
manifest={'schemaVersion':1,'commit':commit,'branch':git('branch','--show-current'),'sourceTree':git('rev-parse','HEAD^{tree}'),
    'monitorPackageVersion':version,'engineAssemblyVersion':'0.4.0.0; commit manifest identifies this development candidate',
    'artifacts':{p.name:{'sha256':sha(p),'size':p.stat().st_size} for p in (archive,deb)},
    'engineFiles':{p.relative_to(engine).as_posix():{'sha256':sha(p),'size':p.stat().st_size,'mode':oct(p.stat().st_mode & 0o777)} for p in engine.rglob('*') if p.is_file()},
    'monitorFiles':{p.relative_to(package).as_posix():{'sha256':sha(p),'size':p.stat().st_size} for p in package.rglob('*') if p.is_file()},
    'runtimeChanges':False,'privilegedCommands':False,'productionPolicyMigration':False}
(output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
print(json.dumps({'artifacts':str(output),'manifestSha256':sha(output/'manifest.json'),'commit':commit}))
