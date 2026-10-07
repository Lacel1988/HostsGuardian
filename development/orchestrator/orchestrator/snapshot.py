"""Fixed read-only repository probe, transferable as source over a single SSH call."""
PROBES = {
    'git': ('rev-parse', '--is-inside-work-tree'),
    'root': ('rev-parse', '--show-toplevel'),
    'origin': ('remote', 'get-url', 'origin'),
    'branch': ('branch', '--show-current'),
    'head': ('rev-parse', 'HEAD'),
    'status': ('status', '--porcelain=v1', '--untracked-files=all'),
}


def script():
    # No path, project identity or command supplied by configuration is executed.
    return ("import subprocess,json,sys\n"
            f"probes={PROBES!r}\n"
            "values={}\n"
            "for name,args in probes.items():\n"
            " p=subprocess.run(['git','--no-optional-locks',*args],capture_output=True,text=True,encoding='utf-8',errors='replace')\n"
            " if p.returncode:\n"
            "  sys.stderr.write(p.stderr);sys.exit(p.returncode)\n"
            " values[name]=p.stdout.strip()\n"
            "print(json.dumps(values))\n")
