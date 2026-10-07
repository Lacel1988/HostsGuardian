"""Read-only Engine attribution. No device identity database, policy actions or raw domain history."""
from datetime import datetime, timezone
import math
import uuid
import ipaddress

FIELDS = ('received', 'allowed', 'policyBlocked', 'failed', 'servfail', 'rejected', 'capacityDropped', 'cancelled', 'tcpConnectionsRejected')


def stamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def validate_devices(diagnostic):
    value = diagnostic.get('devices')
    if value is None:
        return None
    if not isinstance(value, dict) or value.get('schemaVersion') != 1 or value.get('instanceId') != diagnostic['instanceId'] or value.get('windowSeconds') != 600 or value.get('maximumSources') != 64:
        raise ValueError('Unsupported device evidence')
    if abs((stamp(value['snapshotUtc']) - stamp(diagnostic['snapshotUtc'])).total_seconds()) > 2:
        raise ValueError('Mixed device snapshot')
    if type(value.get('evictedSources')) is not int or value['evictedSources'] < 0:
        raise ValueError('Invalid eviction count')
    rows = value.get('devices')
    if not isinstance(rows, list) or len(rows) > 64:
        raise ValueError('Unbounded device evidence')
    seen = set()
    for row in rows:
        tracking = row['trackingId']
        if not isinstance(tracking, str) or len(tracking) != 32 or any(c not in '0123456789abcdef' for c in tracking) or tracking in seen:
            raise ValueError('Invalid tracking epoch')
        seen.add(tracking)
        if row.get('deviceId') is not None:
            uuid.UUID(row['deviceId'])
        for key, limit in (('name',128), ('lastObservedAddress',45), ('identityState',40)):
            if not isinstance(row.get(key),str) or len(row[key]) > limit or any(ord(c)<32 for c in row[key]):
                raise ValueError('Invalid identity label')
        if row.get('nameEvidence') not in ('OBSERVED','INFERRED','USER-CONFIRMED','UNKNOWN'):
            raise ValueError('Unknown identity provenance')
        if not isinstance(row.get('deviceType',''),str) or len(row.get('deviceType',''))>128 or any(ord(c)<32 for c in row.get('deviceType','')):
            raise ValueError('Invalid user type metadata')
        evidence = row.get('networkEvidence')
        if evidence is not None:
            if not isinstance(evidence,dict) or any(not isinstance(evidence.get(k),str) or len(evidence[k])>limit or any(ord(c)<32 for c in evidence[k]) for k,limit in (('address',45),('mac',32),('hostname',128),('provenance',160))):
                raise ValueError('Invalid network identity evidence')
            stamp(evidence['observedAtUtc'])
        first, last = stamp(row['firstSeenUtc']), stamp(row['lastSeenUtc'])
        if first > last or (last - stamp(value['snapshotUtc'])).total_seconds() > 2:
            raise ValueError('Invalid identity timestamps')
        if row.get('lastDnsActivityUtc') is not None and stamp(row['lastDnsActivityUtc']) > last:
            raise ValueError('Invalid DNS timestamp')
        for count in [row.get('cumulativeReceived'), *[row['window'].get(f) for f in FIELDS]]:
            if type(count) is not int or not 0 <= count <= 9223372036854775807:
                raise ValueError('Invalid device counter')
    lan = value.get('lanDevices', [])
    if not isinstance(lan, list) or len(lan) > 64:
        raise ValueError('Unbounded LAN observations')
    ids = set()
    if type(value.get('omittedLanDevices',0)) is not int or value.get('omittedLanDevices',0)<0:
        raise ValueError('Invalid omitted LAN count')
    status=value.get('discoveryStatus','Passive evidence; visibility incomplete.')
    if not isinstance(status,str) or len(status)>1024 or any(ord(c)<32 for c in status):
        raise ValueError('Invalid discovery scope')
    for device in lan:
        identifier = uuid.UUID(device['observationDeviceId']).hex
        if identifier in ids or device['presence'] != 'OBSERVED' or device['coverage'] not in ('UNKNOWN', 'PARTIAL') or device['dnsActivity'] not in ('OBSERVED', 'NOT OBSERVED') or device['resolverPath'] != 'UNKNOWN':
            raise ValueError('Invalid LAN assessment')
        ids.add(identifier)
        if type(device.get('evidenceOmitted',0)) is not int or device.get('evidenceOmitted',0)<0:
            raise ValueError('Invalid evidence omission count')
        first, last = stamp(device['firstObservedUtc']), stamp(device['lastObservedUtc'])
        if first > last or (last-stamp(value['snapshotUtc'])).total_seconds() > 30:
            raise ValueError('Invalid LAN observation time')
        for field in ('stability', 'explanation'):
            if not isinstance(device[field],str) or len(device[field])>256 or any(ord(c)<32 for c in device[field]):
                raise ValueError('Invalid LAN explanation')
        retained=device.get('lastReliableClassification')
        if retained is not None:
            from device_types import find
            last=retained.get('classification') if isinstance(retained,dict) else None
            if not isinstance(last,dict) or find(last.get('deviceType')) is None or last.get('deviceType')=='Unknown' or last.get('confidence') not in ('Medium','High') or last.get('evidence')!=[]:raise ValueError('Invalid retained classification')
            stamp(last['assessedAtUtc']);stamp(retained['retainUntilUtc'])
            if last.get('evidenceFreshUntilUtc'):stamp(last['evidenceFreshUntilUtc'])
            provenance=retained.get('provenance')
            if not isinstance(provenance,list) or len(provenance)>4 or any(not isinstance(p,str) or len(p)>256 or any(ord(c)<32 for c in p) for p in provenance):raise ValueError('Invalid classification provenance')
            if not isinstance(last.get('reason'),str) or len(last['reason'])>256 or any(ord(c)<32 for c in last['reason']):raise ValueError('Invalid retained reason')
        classification=device.get('classification')
        if classification is not None:
            from device_types import find
            if not isinstance(classification,dict) or find(classification.get('deviceType')) is None or classification.get('confidence') not in ('Unknown','Low','Medium','High') or classification.get('source')!='INFERRED':raise ValueError('Invalid classification')
            stamp(classification['assessedAtUtc'])
            if not isinstance(classification.get('reason'),str) or len(classification['reason'])>256 or any(ord(c)<32 for c in classification['reason']):raise ValueError('Invalid classification reason')
            fingerprints=classification.get('evidence')
            if not isinstance(fingerprints,list) or len(fingerprints)>32:raise ValueError('Invalid fingerprint evidence')
            for item in fingerprints:
                if not isinstance(item,dict):raise ValueError('Invalid fingerprint evidence')
                for field in ('address','provider','kind','value'):
                    if not isinstance(item.get(field),str) or len(item[field])>256 or any(ord(c)<32 for c in item[field]):raise ValueError('Invalid fingerprint string')
                stamp(item['observedAtUtc'])
        identity=device.get('identity')
        if identity is not None:
            if not isinstance(identity,dict) or identity.get('state') not in ('Registered','Provisional','Ambiguous') or identity.get('confidence') not in ('USER-CONFIRMED','UNKNOWN'):
                raise ValueError('Invalid control-plane identity')
            if identity.get('deviceId') is not None: uuid.UUID(identity['deviceId'])
            if (identity.get('state')=='Registered') != (identity.get('deviceId') is not None) or (identity.get('state')=='Registered') != (identity.get('confidence')=='USER-CONFIRMED'):
                raise ValueError('Incoherent identity association')
            for field,limit in (('friendlyName',128),('observedHostname',128),('provenance',256),('deviceType',128)):
                if not isinstance(identity.get(field,''),str) or len(identity.get(field,''))>limit or any(ord(c)<32 for c in identity.get(field,'')):
                    raise ValueError('Invalid control-plane label')
            groups=identity.get('groups',[])
            if not isinstance(groups,list) or len(groups)>128 or any(not isinstance(g,str) or len(g)>128 or any(ord(c)<32 for c in g) for g in groups):
                raise ValueError('Invalid group labels')
        evidence = device['evidence']
        if not isinstance(evidence,list) or not 1 <= len(evidence) <= 8:
            raise ValueError('Invalid LAN provenance')
        for item in evidence:
            ipaddress.ip_address(item['address'])
            stamp(item['observedAtUtc'])
            for field, limit in (('mac',32),('hostname',128),('provenance',160),('interface',64),('neighborState',64)):
                if not isinstance(item.get(field,''),str) or len(item.get(field,''))>limit or any(ord(c)<32 for c in item.get(field,'')):
                    raise ValueError('Invalid LAN evidence')
    return value


def correlate_lan(rows, observations, omitted=0):
    """Presentation of Engine-owned observations; no independent Monitor identity registry."""
    counts = {}
    for device in observations:
        for address in {e['address'] for e in device['evidence']}:
            counts[address] = counts.get(address,0)+1
    remaining = list(rows); result = []
    for device in observations:
        addresses = {e['address'] for e in device['evidence'] if counts[e['address']] == 1} if not omitted and not device.get('evidenceOmitted',0) else set()
        matching = [r for r in remaining if r['lastObservedAddress'] in addresses]
        for row in matching:
            remaining.remove(row)
        evidence = device['evidence']; primary = evidence[0]
        row = dict(matching[0]) if matching else dict(deviceId=None,identityState='Unknown',name='Unknown device',nameEvidence='UNKNOWN',lastDnsActivityUtc=None,cumulativeReceived=0,rate=None,share=None,highContribution=False)
        row.update(trackingId=uuid.UUID(device['observationDeviceId']).hex, firstSeenUtc=device['firstObservedUtc'],lastSeenUtc=device['lastObservedUtc'],lastObservedAddress=' · '.join(dict.fromkeys(e['address'] for e in evidence)),networkEvidence=primary,lanObservation=device)
        row['window']={f:sum(r['window'][f] for r in matching) for f in FIELDS}
        row['cumulativeReceived']=sum(r['cumulativeReceived'] for r in matching)
        identities={r.get('deviceId') for r in matching}
        row['dnsAttribution'] = dict(attributed=sum(r['window']['received'] for r in matching if r.get('deviceId')), unresolved=sum(r['window']['received'] for r in matching if not r.get('deviceId')), deviceIds=sorted(i for i in identities if i))
        if len(identities)>1:
            row.update(deviceId=None,identityState='Unknown',name='Unknown device',nameEvidence='UNKNOWN',dnsIdentityConflict=True)
        times=[r['lastDnsActivityUtc'] for r in matching if r.get('lastDnsActivityUtc')]
        row['lastDnsActivityUtc']=max(times,key=stamp) if times else None
        if matching and all(r['rate'] is not None for r in matching):row['rate']=sum(r['rate'] for r in matching)
        else:row['rate']=None
        if matching and all(r['share'] is not None for r in matching):row['share']=min(100,sum(r['share'] for r in matching))
        else:row['share']=None
        row['highContribution']=row['rate'] is not None and row['rate']>=10 and row['share'] is not None and row['share']>=50
        if row['nameEvidence']=='UNKNOWN' and primary['hostname']:
            row.update(name=primary['hostname'],nameEvidence='OBSERVED')
        identity=device.get('identity')
        if identity:
            # Consume the shared Engine projection of user-authored metadata, not a Monitor registry.
            # This display association never grants execution binding or changes policy.
            if identity['state']=='Registered':
                row['dnsAttribution']['state'] = 'MIXED' if row.get('dnsIdentityConflict') else 'OBSERVED' if matching else 'NOT OBSERVED'
                row.update(deviceId=identity['deviceId'],name=identity['friendlyName'],nameEvidence='USER-CONFIRMED',identityState='Registered',deviceType=identity.get('deviceType',''))
            elif identity['state']=='Ambiguous' or (row.get('deviceId') and identity.get('deviceId') and row['deviceId']!=identity['deviceId']):
                row.update(deviceId=None,name='Unknown device',nameEvidence='UNKNOWN',identityState='Ambiguous',dnsIdentityConflict=True,deviceType='')
        # Policy identity remains the validated Engine contract; never copy the provisional observation ID into it.
        result.append(row)
    return result+remaining


class DeviceAwareDiagnostics:
    def __init__(self):
        self.previous = None
        self.rows = []
        self.message = 'Device attribution unavailable'

    def accept(self, diagnostic):
        try:
            value = validate_devices(diagnostic) if diagnostic else None
            if value is None:
                self.previous = None; self.rows = []; self.message = 'Device attribution unavailable from this Engine'; return
            previous = self.previous
            if previous and previous['snapshotUtc'] == diagnostic['snapshotUtc']:
                return
            elapsed = (stamp(diagnostic['snapshotUtc']) - stamp(previous['snapshotUtc'])).total_seconds() if previous and previous['instanceId'] == diagnostic['instanceId'] else 0
            usable = 0 < elapsed <= 10
            old = {r['trackingId']: r for r in previous['devices']['devices']} if usable else {}
            global_delta = diagnostic['counters']['received'] - previous['counters']['received'] if usable else None
            rows = []
            for item in value['devices']:
                row = dict(item)
                prior = old.get(item['trackingId'])
                delta = item['cumulativeReceived'] - prior['cumulativeReceived'] if prior else None
                if usable and prior is None and stamp(item['firstSeenUtc']) >= stamp(previous['snapshotUtc']):
                    delta = item['cumulativeReceived']
                row['rate'] = delta / elapsed if usable and delta is not None and delta >= 0 else None
                row['share'] = delta * 100 / global_delta if usable and global_delta is not None and global_delta > 0 and delta is not None and 0 <= delta <= global_delta else None
                row['highContribution'] = row['rate'] is not None and row['rate'] >= 10 and row['share'] is not None and row['share'] >= 50
                rows.append(row)
            rows = correlate_lan(rows, value.get('lanDevices', []), value.get('omittedLanDevices',0))
            self.rows = sorted(rows, key=lambda r: (r['rate'] if r['rate'] is not None else -1, r['window']['received']), reverse=True)
            self.previous = diagnostic
            self.message = f"{len(value.get('lanDevices', []))} LAN observations + {len(value['devices'])} DNS sources; correlated rows {len(rows)}. Retained 10-minute aggregates; evicted DNS sources {value['evictedSources']}; LAN rows omitted by payload limit {value.get('omittedLanDevices',0)}. Missing DNS does not prove bypass. Session observation IDs are not permanent identities."
            self.message += ' '+value.get('discoveryStatus','Passive evidence; visibility incomplete.')
        except (ValueError, KeyError, TypeError, OverflowError, AttributeError):
            self.previous = None; self.rows = []; self.message = 'Device attribution invalid or incoherent; aggregate diagnostics remain separate'

    def text(self):
        lines = [self.message, 'Device management remains in WPF. Registered names are not automatic hostname discovery.']
        if not self.rows:
            return '\n'.join(lines + ['No attributable device evidence.'])
        for row in self.rows:
            name = row['name']
            evidence = row.get('networkEvidence')
            if evidence:
                lines.append('Network evidence: ' + evidence['provenance'] + ' · MAC ' + (evidence['mac'] or 'UNKNOWN') + ' · hostname ' + (evidence['hostname'] or 'UNKNOWN'))
            if row['nameEvidence'] == 'UNKNOWN':
                name += ' · ' + (row['lastObservedAddress'] or 'address unavailable')
            rate = 'unavailable' if row['rate'] is None else f"{row['rate']:.1f} q/s"
            share = 'unavailable' if row['share'] is None else f"{row['share']:.1f}%"
            counts = row['window']
            lines += ['', f"{name} [{row['nameEvidence']}] · identity {row['identityState']}",
                f"DNS rate {rate} · contribution {share} of aggregate sample interval",
                f"10-min received {counts['received']} · allowed {counts['allowed']} · blocked {counts['policyBlocked']} · failed {counts['failed']} / SERVFAIL {counts['servfail']} · dropped/rejected {counts['rejected']} (capacity {counts['capacityDropped']})",
                f"First observed {row['firstSeenUtc']} · last seen {row['lastSeenUtc']} · Last DNS {row['lastDnsActivityUtc'] or 'not observed'} · last observed address {row['lastObservedAddress'] or 'unavailable'} · DeviceId {row.get('deviceId') or 'UNKNOWN'}"]
            if counts['tcpConnectionsRejected']:
                lines.append(f"Rejected TCP connections {counts['tcpConnectionsRejected']} (connections, not DNS queries)")
            if counts['failed']:
                lines.append('OBSERVED failures in retained window; temporal incident association is not proof of cause.')
            if row['highContribution']:
                lines.append('INFERRED high relative DNS contribution (>=10 q/s and >=50%); informational, not a health fault.')
        return '\n'.join(lines)
