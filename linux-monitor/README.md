# HostsGuardian Linux Monitor

HostsGuardian Monitor is the single local Linux application for Engine operations,
health and diagnostics. The Linux DNS Engine is a separate systemd background service.
Closing or crashing Monitor never stops Engine. Reopening reconnects to its current PID;
Engine restarts clear the old instance's graph samples and rate baseline.

Overview shows observed service state, PID, uptime, Engine assembly version, DNS listeners,
API listener health, passive upstream evidence and policy/persistence health. It never
infers end-to-end DNS success from a listening socket. API health is Engine-reported,
not an active reachability probe. No traffic means upstream observation is Unknown.

Start, Stop and Restart require confirmation and the existing interactive systemd
D-Bus/polkit authorization. Only hostsguardian-engine.service is allowed, with replace
job mode. An accepted request is not success: Monitor polls actual service/PID evidence.
Authorization failures remain visible. No password or bearer credential is read by GUI.
The sample polkit rule and Engine drop-in remain examples and are not installed by this
package. No new privilege grant, service enablement or configuration change is required.

Diagnostics preserves V1 four-card native GTK graphs, DNS results and pressure/health.
History is bounded to 600 samples and ten elapsed minutes in memory. Samples follow the
real two-second publisher timestamps, duplicate publications do not invent samples,
missing/stale evidence creates gaps, and policy blocks remain successful filtering.
See [the metric contract](../docs/linux-diagnostics-console-v1.md).

Events / Incidents uses optional operationalEvents from the Engine-owned local snapshot:
occurrence time, Warning/Critical/Recovery, component, incident and recovery relationship.
The Engine retains at most 64 events under normal defaults; Monitor does not persist them.
Older Diagnostics V1 Engines remain compatible: current component incident snapshots
and recent bounded logs are available; structured history is explicitly unavailable.
The candidate Engine adds this local feed without changing DNS or policy execution.
Details contains read-only listener, resolver, counters, capacities and runtime evidence.

Status must be no older than ten seconds, match systemd MainPID and have trusted ownership,
regular-file type, safe permissions and no symlinks. The full file is bounded to 128 KiB.
Untrusted or stale evidence does not appear as current health. Monitor has no policy editor,
management credential access, certificate enrollment or networking controls. WPF Windows
Control Center owns policy decisions. Device/source diagnostics consume bounded Engine aggregates and identity evidence; Monitor adds no independent identity store or raw-query history.

The v0.4.0 package retains the historical 0.3.0+unified1 executable, application
ID and desktop/autostart paths. Exactly one normal launcher and one normal autostart path
remain. User-owned entries are never removed by scripts. The existing autostart conffile
uses normal dpkg preservation semantics; a locally modified file requires human review
of the package prompt. No maintainer scripts or Engine unit modifications are included.

Run python3 -m unittest discover -v from this directory. GTK fixture tests require
PyGObject GTK4 and a graphical session; headless environments explicitly skip them.
Fixtures never operate the real service. Real polkit/action acceptance is a later human
checkpoint; production service transitions are not used for development screenshots.

## v0.4.0 device diagnostics, topology and packaging

Device lists and selected details separate identity, presence, DNS activity, coverage
and provenance. The evidence-driven Topology page preserves Unknown access technology
and uncertain relationships instead of inventing infrastructure. Registered identity
comes from the Engine-committed WPF policy; Monitor cannot rename or register devices.

The launcher and Debian rules require LF bytes. Package builds reject CRLF executable
scripts and directly execute the actual extracted launcher with `--smoke-check` as an
ordinary Linux user. This imports GTK, Cairo and Topology without constructing a window
or controlling services. `python launcher` is not an acceptable shebang smoke test.
Build with `python3 -B build_monitor_package.py --output /absolute/fresh/output --version 0.4.0`
in an isolated ordinary-user Linux fixture. This builds only; it never installs.
