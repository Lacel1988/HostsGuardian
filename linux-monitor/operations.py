"""Presentation of Engine-owned evidence; no service, policy or credential access."""
from datetime import datetime, timezone
from monitor_core import upstream_state, control_request

COMPONENTS = ('Listeners', 'Management', 'Upstream', 'Processing', 'Capacity', 'Persistence')
STATES = ('Healthy', 'Degraded', 'Critical')


def engine_state(unit):
    state = {'active': 'Running', 'inactive': 'Stopped', 'failed': 'Failed',
             'activating': 'Starting', 'deactivating': 'Stopping'}.get(unit.get('ActiveState'), 'Unknown')
    if state == 'Running' and (unit.get('SubState') != 'running' or type(unit.get('MainPID')) is not int or unit['MainPID'] <= 0):
        return 'Unknown'
    return state


def confirmation_text(verb):
    control_request(verb)
    return (f'{verb.capitalize()} HostsGuardian Engine?',
            'Stopping or restarting can interrupt DNS service. System authorization is required. The result will be checked against actual service state.')


def duration(seconds):
    seconds = max(0, int(seconds))
    return f'{seconds // 3600} h {(seconds % 3600) // 60} min {seconds % 60} s'


def overview(unit, snapshot, diagnostic=None):
    state = engine_state(unit)
    result = dict(engine=state, identity=f"PID {unit.get('MainPID', 0) or '—'}", dns='Unknown',
                  api='Unknown', upstream='Unknown', policy='Unknown', health='Unknown',
                  evidence='Missing, stale or untrusted Engine status')
    if state != 'Running' or snapshot is None:
        return result
    status = snapshot['status']
    components = {c['component']: c['state'] for c in diagnostic['components']} if diagnostic else {}
    result['dns'] = f"IPv4 UDP {status['udpState']} · TCP {status['tcpState']}\nIPv6 UDP {status.get('ipv6UdpState', 'Unknown')} · TCP {status.get('ipv6TcpState', 'Unknown')}"
    result['api'] = f"{status['managementState']} · {components.get('Management', 'health unmeasured')}"
    # Listener evidence is not an HTTPS reachability probe or a successful DNS query.
    result['upstream'] = upstream_state(status)
    result['policy'] = ('Loaded' if status['policyLoaded'] else 'Not loaded') + ' · ' + (
        'Persistence fault' if status.get('persistenceFault') else 'No reported persistence fault')
    result['evidence'] = 'Local Engine evidence · HTTPS reachability is not actively probed'
    if diagnostic:
        resource = diagnostic['resources']
        result['identity'] += f" · Uptime {duration(resource['uptimeSeconds'])} · Engine {resource.get('revision', 'unknown')}"
        result['health'] = diagnostic['health']
        result['dns'] += ' · ' + components.get('Listeners', 'Unknown')
        counts = diagnostic['counters']
        result['evidence'] = (f"{counts['received']:,} queries since start · {counts['allowed']:,} forwarded · "
                              f"{counts['policyBlocked']:,} policy blocked · {counts['failed']:,} failed. "
                              'Listener health does not prove end-to-end DNS. API state is Engine-reported.')
    coverage=status.get('coverage', {})
    coverage_state=coverage.get('state', 'UNKNOWN') if isinstance(coverage,dict) else 'UNKNOWN'
    if coverage_state not in ('COMPLETE','PARTIAL','UNKNOWN'):coverage_state='UNKNOWN'
    result['evidence'] += '\nDNS coverage: '+coverage_state+'. Router advertisements and client resolver selection are separate from Engine health.'
    return result


def validate_events(batch, instance):
    if not isinstance(batch, dict) or batch.get('schemaVersion') != 1 or batch.get('instanceId') != instance:
        raise ValueError('Wrong operational event instance')
    if type(batch.get('latestSequence')) is not int or batch['latestSequence'] < 0 or type(batch.get('cursorGap')) is not bool:
        raise ValueError('Invalid event cursor')
    events = batch.get('events')
    if not isinstance(events, list) or len(events) > 64:
        raise ValueError('Invalid event bounds')
    previous = 0
    for e in events:
        if not isinstance(e, dict):
            raise ValueError('Invalid event')
        for name, limit in (('instanceId', 100), ('incidentId', 140), ('component', 40), ('type', 20),
                            ('severity', 20), ('state', 20), ('summaryId', 100), ('occurredAtUtc', 50)):
            if not isinstance(e.get(name), str) or len(e[name]) > limit:
                raise ValueError('Invalid event field')
        if e['instanceId'] != instance or e['component'] not in COMPONENTS or e['type'] != e['component'].upper() + ('_RECOVERED' if e['severity'] == 'Recovery' else '_CRITICAL' if e['severity'] == 'Critical' else '_DEGRADED') or e['state'] not in STATES:
            raise ValueError('Invalid operational event')
        if e['severity'] not in ('Warning', 'Critical', 'Recovery'):
            raise ValueError('Invalid event severity')
        sequence = e.get('sequence')
        if type(sequence) is not int or not previous < sequence <= batch['latestSequence']:
            raise ValueError('Invalid event ordering')
        previous = sequence
        datetime.fromisoformat(e['occurredAtUtc'].replace('Z', '+00:00'))
        recovery = e.get('recoveryOf')
        if recovery is not None and (not isinstance(recovery, str) or len(recovery) > 140):
            raise ValueError('Invalid recovery reference')
    return events


def incident_rows(snapshot, diagnostic):
    if not snapshot or not diagnostic:
        return 'No fresh incident evidence', []
    batch = snapshot.get('operationalEvents')
    if batch is None:
        rows = [(c['state'], f"{c['component']} · {c['state']}",
                 f"Since {c.get('sinceUtc') or 'unknown'} · Incident {c.get('incidentId') or 'unknown'}")
                for c in diagnostic['components'] if c['state'] != 'Healthy']
        return 'Current component state only · structured event history unavailable on this Engine', rows
    try:
        events = validate_events(batch, diagnostic['instanceId'])
    except (ValueError, KeyError, TypeError):
        return 'Structured event history invalid or unavailable', []
    states = {c['component']: c['state'] for c in diagnostic['components']}
    rows = [(e['severity'], f"{e['component']} · {e['severity']}",
             f"{e['occurredAtUtc']} · {e['state']} at occurrence · now {states.get(e['component'], 'Unknown')} · Incident {e['incidentId']}" +
             (f" · Recovery of {e['recoveryOf']}" if e.get('recoveryOf') else '')) for e in reversed(events)]
    return ('Recent Engine incidents · up to 64, memory only' + (' · Earlier events no longer retained' if batch['cursorGap'] else ''), rows)


def details_text(unit, snapshot, diagnostic):
    lines = [f"Service: hostsguardian-engine.service · {engine_state(unit)} / {unit.get('SubState', 'unknown')}",
             f"Systemd PID: {unit.get('MainPID', 0)}"]
    if not snapshot:
        return '\n'.join(lines + ['Fresh Engine evidence unavailable.'])
    status = snapshot['status']
    lines.append(f"Policy schema: {status.get('policySchemaVersion', 'unknown')} · Groups: {status.get('deviceGroupCount', 'unknown')} · Catalog: {status.get('serviceCatalogCount', 'unknown')} · Profiles: {status.get('profileCount', 'unknown')} · Schedules: {status.get('scheduleCount', 'unknown')}")
    lines.append('Policy precedence: Device override > Active Profile/Schedule > Device Group > Global; same-layer Block wins.')
    lines.append('Retention: raw DNS observations 15 min / 64 entries; product activity 24 h / 256 memory buckets; durable policy audit 1000 entries. Restart clears ephemeral activity. No policy/security bodies are published here.')
    lines += [f"Published: {snapshot['emittedAtUtc']} (freshness bound 10 s) · Engine start: {snapshot.get('startedAtUtc', 'unknown')}",
              f"DNS: UDP {status.get('dnsPort', '?')} / TCP {status.get('tcpTargetPort', '?')}",
              f"Management: HTTPS port {status.get('apiPort', '?')} · {status['managementState']}",
              f"Policy restore: {status.get('policyRestoreState', 'unknown')} · revision {status.get('policyRevision', '?')}",
              f"Filtering: {'Safe Mode bypass' if status.get('emergencySafeMode') else 'active' if status.get('filteringEnabled') else 'disabled'}",
              f"Rules committed / active: {status.get('committedRuleCount', '?')} / {status.get('activeRuleCount', '?')}",
              f"Device overrides committed / active: {status.get('committedDeviceOverrideCount', '?')} / {status.get('activeDeviceOverrideCount', '?')}",
              f"Upstream outcome: {status.get('lastUpstreamOutcome', 'NotObserved')} · success {status.get('lastUpstreamSuccessUtc') or 'not observed'} · failure {status.get('lastUpstreamFailureUtc') or 'not observed'}"]
    if not diagnostic:
        return '\n'.join(lines + ['Diagnostics unavailable; counters and resources are not inferred.'])
    r = diagnostic['resources']; p = diagnostic['pressure']; c = diagnostic['counters']
    lines += ['', 'RUNTIME', f"Instance {diagnostic['instanceId']} · PID {r['processId']} · Engine assembly {r.get('revision', 'unknown')}",
              f"Uptime {duration(r['uptimeSeconds'])} · CPU {r['cpuPercent'] if r['cpuPercent'] is not None else 'unavailable'}% · RAM {r['workingSetBytes'] if r['workingSetBytes'] is not None else 'unavailable'} bytes",
              '', 'EXECUTION / CAPACITY', f"Requests current / peak: {p['currentRequests']} / {p['peakRequests']}",
              f"UDP {p['udpCurrent']} / {p['udpCapacity']} · TCP requests {p['tcpCurrentRequests']} · connections {p['tcpConnections']} / {p['tcpConnectionCapacity']}",
              '', 'TRANSPORT / OUTCOMES']
    lines += [f"{name}: {value:,}" for name, value in c.items()]
    for name in ('upstreamLatency', 'processingLatency'):
        lat = diagnostic[name]
        lines += ['', name, f"Samples {lat['samples']} · recent {lat['recentMs']} ms · P50 {lat['p50Ms']} ms · P95 {lat['p95Ms']} ms · skipped {lat.get('skipped', 0)}"]
    lines += ['', 'RESOLVERS']
    for resolver in diagnostic['resolvers']:
        lines.append(' · '.join(f'{key}: {value}' for key, value in resolver.items() if key != 'latency'))
    lines += ['', 'HEALTH COMPONENTS']
    lines += [f"{v['component']}: {v['state']} · since {v.get('sinceUtc') or '—'} · incident {v.get('incidentId') or '—'}" for v in diagnostic['components']]
    return '\n'.join(lines)
