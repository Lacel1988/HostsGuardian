"""Monitor-only package construction and direct, non-GUI launcher smoke checks.

Never installs packages, starts/restarts units, changes capabilities or accesses
production policy/security. Full builds call the same packaging functions.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess


def validate_linux_script(data):
    if not data.startswith(b'#!') or b'\n' not in data or b'\r' in data:
        raise ValueError('Linux executable script requires a shebang and LF-only bytes')
    if not data.split(b'\n', 1)[0][2:].startswith(b'/'):
        raise ValueError('Linux shebang interpreter must be absolute')


def copy_package_file(source, target, executable=False):
    data = source.read_bytes()
    if executable:
        validate_linux_script(data)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(0o755 if executable else 0o644)


def validate_staging(package):
    launcher = package/'usr/bin/hostsguardian-monitor'
    validate_linux_script(launcher.read_bytes())
    if stat.S_IMODE(launcher.stat().st_mode) != 0o755:
        raise ValueError('Monitor launcher must be executable mode0755')
    for path in package.rglob('*'):
        if path.is_file() and path.stat().st_mode & 0o111:
            data = path.read_bytes()
            if data.startswith((b'#!', b'\xef\xbb\xbf#!')):
                validate_linux_script(data)


def smoke_launcher(launcher, timeout=15):
    # Deliberately execute the file itself. "python launcher" would hide CRLF shebang bugs.
    result = subprocess.run([str(launcher.resolve()), '--smoke-check'],
                            text=True, capture_output=True, timeout=timeout, check=True)
    value = json.loads(result.stdout)
    expected_library = launcher.resolve().parents[1]/'lib/hostsguardian-monitor'
    if not (value.get('status') == 'MONITOR_LAUNCH_SMOKE_PASS' and value.get('uid', 0) != 0
            and value.get('launcher') == str(launcher.resolve())
            and value.get('library') == str(expected_library)
            and value.get('applicationStarted') is False and value.get('serviceActions') is False
            and value.get('cairo') is True and value.get('topology') is True):
        raise ValueError('Monitor direct-launch smoke did not establish safe readiness')
    return value


def build_monitor_package(root, output, version):
    if os.name != 'posix' or os.geteuid() == 0:
        raise RuntimeError('Only an unprivileged Linux package build is permitted')
    if not version or any(c not in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+~:-' for c in version):
        raise ValueError('Invalid package version')
    validate_linux_script((root/'debian/rules').read_bytes())
    package = output/'monitor-package'
    (package/'DEBIAN').mkdir(parents=True, exist_ok=False)
    for line in (root/'debian/install').read_text().splitlines():
        if not line.strip():
            continue
        source, destination = line.split()
        for name in (source, destination):
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe package layout path')
        copy_package_file(root/source, package/destination/Path(source).name,
                          executable=destination == 'usr/bin')
    control = ('Package: hostsguardian-monitor\nVersion: '+version+'\nArchitecture: all\n'
               'Maintainer: HostsGuardian maintainers\n'
               'Depends: python3, python3-gi, python3-cairo, python3-gi-cairo, gir1.2-gtk-4.0, polkitd | policykit-1\n'
               'Description: HostsGuardian local operations and read-only diagnostics\n'
               ' LF launcher with safe direct execution smoke verification.\n')
    (package/'DEBIAN/control').write_text(control, encoding='utf-8')
    validate_staging(package)
    smoke_launcher(package/'usr/bin/hostsguardian-monitor')
    deb = output/('hostsguardian-monitor_'+version+'_all.deb')
    subprocess.run(['dpkg-deb','--build','--root-owner-group',str(package),str(deb)], check=True)
    # Smoke the actual container extraction, not only pre-build source/staging.
    extracted = output/'extracted-package'
    subprocess.run(['dpkg-deb','--extract',str(deb),str(extracted)], check=True)
    validate_staging(extracted)
    evidence = smoke_launcher(extracted/'usr/bin/hostsguardian-monitor')
    (output/'monitor-launch-smoke.json').write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    return package, deb


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    parser.add_argument('--version')
    parser.add_argument('--verify-staging', type=Path)
    args = parser.parse_args()
    if args.verify_staging:
        validate_staging(args.verify_staging)
    else:
        if not args.output or not args.version:
            parser.error('--output and --version are required')
        args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        package, deb = build_monitor_package(Path(__file__).resolve().parent, args.output, args.version)
        print(json.dumps(dict(package=str(deb), version=args.version, launchSmoke='PASS', productionChanged=False)))