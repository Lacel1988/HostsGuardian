"""Unprivileged Linux artifact build only; never installs or invokes systemd."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import sys


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source-manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();root=Path(__file__).resolve().parents[1]
    if os.name!='posix' or os.geteuid()==0:raise SystemExit('Only an unprivileged Linux build is allowed')
    manifest=json.loads(args.source_manifest.read_text());identity=manifest['sourceIdentity']
    if len(identity)!=64 or any(c not in '0123456789abcdef' for c in identity):raise ValueError('Invalid source identity')
    for name,item in manifest['files'].items():
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts or sha(root/relative)!=item['sha256']:raise ValueError('Source manifest mismatch: '+name)
    out=args.output.resolve();out.mkdir(mode=0o700,parents=False,exist_ok=False)
    engine=out/'engine'
    subprocess.run(['dotnet','publish',str(root/'HostsGuardian.DnsEngine'),'-c','Release','-r','linux-x64','--self-contained','true','-o',str(engine)],check=True)
    sys.path.insert(0,str(root/'linux-monitor'))
    from build_monitor_package import build_monitor_package
    version='0.4.0+topology.'+identity[:12]
    package,deb=build_monitor_package(root/'linux-monitor',out,version)
    payload=out/'payload';payload.mkdir();shutil.copytree(engine,payload/'engine')
    helper=payload/'helper';helper.mkdir();shutil.copyfile(root/'network-validator/validator.py',helper/'validator.py')
    shutil.copyfile(root/'development/roadmap/dns_readiness.py',helper/'dns_readiness.py')
    units=payload/'units';units.mkdir()
    for source in (root/'network-validator/packaging').glob('*.in'):shutil.copyfile(source,units/source.name)
    shutil.copyfile(deb,payload/deb.name)
    files={p.relative_to(payload).as_posix():dict(sha256=sha(p),size=p.stat().st_size,mode='0755' if p.name=='HostsGuardian.DnsEngine' else '0644') for p in sorted(payload.rglob('*')) if p.is_file()}
    archive=out/'linux-payload.tar.gz'
    with tarfile.open(archive,'w:gz') as tar:
        for name,item in files.items():
            info=tar.gettarinfo(str(payload/name),name);info.uid=info.gid=0;info.uname=info.gname='root';info.mode=int(item['mode'],8)
            with (payload/name).open('rb') as stream:tar.addfile(info,stream)
    result=dict(schemaVersion=2,sourceIdentity=identity,baseHead=manifest['baseHead'],sourceManifestSha256=sha(args.source_manifest),monitorVersion=version,
                archive=dict(name=archive.name,sha256=sha(archive),size=archive.stat().st_size),files=files,activeValidationDefault=False,
                prerequisites=['Linux SO_PEERPIDFD (>=6.5)','systemd system bus/socket activation','python3-cairo','python3-gi-cairo'],productionChanged=False)
    (out/'payload-manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(output=str(out),manifestSha256=sha(out/'payload-manifest.json'),sourceIdentity=identity)))


if __name__=='__main__':main()
