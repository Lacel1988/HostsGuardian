# One product, separate responsibilities

> **v0.3.0 status update:** accepted Unified Monitor source/package is 0.3.0+unified1; real installed GUI Stop/Start/Restart and Windows WPF runtime acceptance subsequently passed within documented coverage. Earlier pending/source-milestone statements below are historical. Automatic candidate WPF operational-event polling is not in the retained Windows variant. See [the checkpoint record](checkpoint-v0.3.0.md).

HostsGuardian consists of Windows Control Center, Linux DNS Engine, Linux Monitor,
and shared Core/contracts. Linux Monitor is the single local operational/diagnostic GUI.
Monitor is not Engine: systemd owns the background Engine, and closing Monitor never
stops DNS. WPF remains the policy Control Center; Linux Monitor displays policy operational
health without editing filtering policy, devices, schedules or groups.

The UI uses Overview, Diagnostics, Events / Incidents and expandable Details with a shared
dark/green visual identity. Fixed-unit controls retain confirmation and interactive system
authorization, followed by actual state readback. Engine analysis produces health and
structured incidents; the Monitor presents that evidence rather than deriving a second
health model. Raw telemetry stays Linux-side; actionable state changes may reach WPF.

The candidate Engine local publisher adds optional operationalEvents using the existing
OperationalEventBatch contract, bounded ring and status file protections. It publishes
sequence, occurrence, severity, incident and recovery metadata, no domains or clients.
The existing management feed and auth boundary are unchanged. Older Engines remain usable
with explicit unavailable structured history and current component snapshots. Full incident
history requires deploying the candidate Engine separately at the prepared checkpoint.

Both launcher and autostart retain hostsguardian-monitor.desktop and application identity
org.hostsguardian.Monitor. No Engine startup/enablement changes follow from GUI startup.
The package installs no polkit rule, unit or drop-in and has no maintainer scripts. Old UI
names and the mixed JSON/control expander are retired; no obsolete duplicate launcher was
present to delete. No privileged action or deployment is part of this source milestone.

Verification covers real GTK layouts and confirmation/readback against an isolated service
client, plus production read-only snapshots. Successful Start/Stop/Restart through the real
polkit agent remains a later human maintenance test. Natural production traffic acceptance,
real incident delivery and Windows WPF runtime acceptance remain separate pending gates.
