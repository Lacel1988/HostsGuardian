"""Shared catalog presentation only. No probes, registry or execution classification."""
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

CATALOG=json.loads(Path(__file__).with_name('device-types.json').read_text(encoding='utf-8'))
if CATALOG['schemaVersion']!=1:raise ValueError('Unsupported type catalog')
TYPES=CATALOG['types']

def find(value):
    return next((t for t in TYPES if (value or '').casefold() in [t['id'].casefold(),*[a.casefold() for a in t['aliases']]]),None)

def assess(confirmed,hostnames):
    unknown=find('Unknown')
    if confirmed and confirmed.strip():
        value=find(confirmed)
        return dict(type=value or unknown,source='USER-CONFIRMED' if value else 'UNKNOWN',confidence='User' if value else 'Unknown',
                    provenance='Explicit user-owned type metadata; not physical identity evidence.' if value else 'Unrecognized user metadata retained; no automatic replacement.')
    names={n.casefold() for n in hostnames if n and n.strip()}
    if len(names)!=1:return dict(type=unknown,source='UNKNOWN',confidence='Unknown',provenance='Insufficient or conflicting observed hostname evidence; MAC/vendor alone is not a type.')
    tokens=set(re.split('[^a-z0-9]+',next(iter(names))))
    hints=[t for t in TYPES if any(h in tokens for h in t['hostnameHints'])]
    return dict(type=hints[0] if len(hints)==1 else unknown,source='INFERRED' if len(hints)==1 else 'UNKNOWN',confidence='Low' if len(hints)==1 else 'Unknown',
                provenance='Observed hostname category hint; name is not proof of device type.' if len(hints)==1 else 'No unique supported hostname category hint; MAC/vendor alone is not a type.')

def for_row(row):
    lan=row.get('lanObservation') or {};identity=lan.get('identity') or {}
    evidence=lan.get('evidence') or [row.get('networkEvidence') or {}]
    confirmed=identity.get('deviceType') if identity.get('state')=='Registered' else row.get('deviceType','')
    classification=lan.get('classification')
    retained=lan.get('lastReliableClassification')
    if not confirmed and retained:
        try:
            last=retained['classification'];now=datetime.now(timezone.utc)
            until=datetime.fromisoformat(retained['retainUntilUtc'].replace('Z','+00:00'))
            classified=datetime.fromisoformat(last['assessedAtUtc'].replace('Z','+00:00'))
            fresh=datetime.fromisoformat((last.get('evidenceFreshUntilUtc') or last['assessedAtUtc']).replace('Z','+00:00'))
            if not last.get('evidenceFreshUntilUtc'):fresh+=timedelta(minutes=5)
            if until>now and classified<=now+timedelta(seconds=5) and find(last['deviceType']) and last['deviceType']!='Unknown' and last['confidence'] in ('Medium','High'):
                conflict=(classification or {}).get('conflictingEvidence') is True
                current=(classification or {}).get('deviceType')==last['deviceType'] and (classification or {}).get('confidence') in ('Medium','High')
                state='CONFLICT' if conflict else 'STALE' if fresh<now or not current else 'CURRENT'
                return dict(type=find(last['deviceType']),source='INFERRED',confidence=last['confidence'],provenance=last['reason']+'; '+'; '.join(retained['provenance']),freshness=state,lastClassified=classified.isoformat())
        except (KeyError,ValueError,TypeError):pass
    if not confirmed and classification is not None:
        try:
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(classification['assessedAtUtc'].replace('Z','+00:00'))).total_seconds()
            value=find(classification['deviceType']) or find('Unknown')
            if age < -5 or age > 300:return dict(type=find('Unknown'),source='UNKNOWN',confidence='Unknown',provenance='Classification expired; refresh observations.')
            return dict(type=value,source='UNKNOWN' if value['id']=='Unknown' else 'INFERRED',confidence=classification['confidence'],provenance=classification['reason'])
        except (KeyError,ValueError,TypeError):return dict(type=find('Unknown'),source='UNKNOWN',confidence='Unknown',provenance='Invalid classification evidence.')
    return assess(identity.get('deviceType') if identity.get('state')=='Registered' else row.get('deviceType',''),[e.get('hostname','') for e in evidence])

def label(value):
    suffix=' · '+{'CURRENT':'evidence fresh','STALE':'evidence stale','CONFLICT':'current evidence conflicts; last reliable inference'}.get(value.get('freshness'),'')+' · last classified '+value['lastClassified'] if value.get('lastClassified') else ''
    return value['type']['label']+(' · user confirmed' if value['source']=='USER-CONFIRMED' else ' · inferred, '+value['confidence'].lower()+' confidence' if value['source']=='INFERRED' else ' · insufficient evidence')+suffix
