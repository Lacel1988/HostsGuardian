"""Explicitly approved independent recovery only; no Block action or DNS probes."""
import argparse
import hashlib
import json
import ipaddress
import re
from pathlib import Path
import ssl
import urllib.request


class Conflict(RuntimeError):pass


def validate_scope(session):
    """The hash-pinned session grants authority; no device/domain is built in."""
    rows=session.get('approvedOverrides')
    if not isinstance(rows,list) or not 1<=len(rows)<=64:
        raise Conflict('Explicit bounded recovery scope required')
    devices=session['original']['policy']['devices']
    ids=[x['deviceId'] for x in devices]
    if len(ids)!=len(set(ids)):raise Conflict('Ambiguous registration')
    approved=set()
    for row in rows:
        if not isinstance(row,list) or len(row)!=2 or not all(isinstance(x,str) for x in row):
            raise Conflict('Malformed recovery scope')
        device,domain=row
        if device not in ids or not device or not valid_domain(domain):
            raise Conflict('Unknown recovery target or noncanonical domain')
        if tuple(row) in approved:raise Conflict('Duplicate recovery scope')
        approved.add(tuple(row))
    if len({device for device,domain in approved})!=1:
        raise Conflict('One explicitly approved device per session required')
    before=keyed(session['original']['policy']['overrides'])
    if any(r.get('state') not in ('Inherit','Allow','Block') for k,r in before.items() if k in approved):
        raise Conflict('Unsupported original override state')
    states=session.get('originalOverrideStates')
    expected=[dict(deviceId=d,domain=n,original=before.get((d,n))) for d,n in sorted(approved)]
    if states is not None and states!=expected:raise Conflict('Original state ledger mismatch')
    return approved


def valid_domain(domain):
    if len(domain)>253 or domain!=domain.lower() or '.' not in domain:return False
    labels=domain.split('.')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in labels):return False
    try:ipaddress.ip_address(domain);return False
    except ValueError:return True


def make_session(original,api_config,device_id,domains):
    """No network writes. null ledger entry means ABSENT, never Inherit."""
    session=dict(original=original,api=api_config,
                 approvedOverrides=[[device_id,d] for d in domains])
    approved=validate_scope(session)
    before=keyed(original['policy']['overrides'])
    session['originalOverrideStates']=[dict(deviceId=d,domain=n,original=before.get((d,n)))
                                      for d,n in sorted(approved)]
    return session


def keyed(rows):
    result={}
    for row in rows:
        key=(row['deviceId'],row['domain'])
        if key in result:raise Conflict('Duplicate policy reference')
        result[key]=row
    return result


def safe_to_restore(original,current,approved):
    # Only pre-approved device/domain override differences are test-owned.
    if {k:v for k,v in original.items() if k!='overrides'}!={k:v for k,v in current.items() if k!='overrides'}:
        raise Conflict('Non-test policy changed; do not overwrite unrelated decisions')
    before=keyed(original['overrides']);after=keyed(current['overrides'])
    for key in set(before)|set(after):
        if key not in approved and before.get(key)!=after.get(key):raise Conflict('Unapproved override changed')
        if key in approved and before.get(key)!=after.get(key):
            if after.get(key)!={'deviceId':key[0],'domain':key[1],'state':'Block'}:
                raise Conflict('Unexpected test override state')


class Api:
    def __init__(self,config):
        if not config['url'].startswith('https://'):raise Conflict('Authenticated HTTPS required')
        self.url=config['url'].rstrip('/')
        self.token=Path(config['credentialPath']).read_text().strip()
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*a,**k):return None
        self.opener=urllib.request.build_opener(NoRedirect,urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=config['certificatePath'])))
    def call(self,path,body=None):
        request=urllib.request.Request(self.url+path,data=None if body is None else json.dumps(body).encode(),headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
        with self.opener.open(request,timeout=3) as response:return json.load(response)


def restore(session,api):
    original=session['original']['policy'];approved=validate_scope(session)
    current=api.call('/v2/policy')
    safe_to_restore(original,current['policy'],approved)
    if current['policy']==original:return dict(restored=True,revision=current['revision'],alreadyOriginal=True)
    # Only remaining session-owned differences; already-restored rows stay untouched.
    before=keyed(original['overrides']);after=keyed(current['policy']['overrides'])
    for key in approved:
        if before.get(key)==after.get(key):continue
        if key in before:after[key]=before[key]
        else:after.pop(key,None)
    restored=dict(current['policy'],overrides=original['overrides'])
    if after!=before:raise Conflict('Restoration scope incomplete')
    ack=api.call('/v2/policy/replace',dict(expectedRevision=current['revision'],expectedInstanceId=current['instanceId'],policy=restored))
    readback=api.call('/v2/policy')
    if not ack.get('ok') or readback['revision']!=ack.get('revision') or readback['instanceId']!=current['instanceId'] or readback['policy']!=original:
        raise Conflict('Restoration readback unconfirmed')
    return dict(restored=True,revision=readback['revision'],alreadyOriginal=False)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--session',type=Path,required=True)
    parser.add_argument('--sha256',required=True);parser.add_argument('--approved-recovery',action='store_true')
    parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    if not args.approved_recovery:raise Conflict('Recovery approval required')
    data=args.session.read_bytes()
    if hashlib.sha256(data).hexdigest()!=args.sha256:raise Conflict('Pinned recovery session changed')
    session=json.loads(data);validate_scope(session);api=Api(session['api'])
    if args.check_only:
        current=api.call('/v2/policy')
        if current['policy']!=session['original']['policy']:raise Conflict('Pre-test original no longer current')
        print('RECOVERY_PRECHECK_PASS');return
    result=restore(session,api)
    # Success only after exact semantic readback, never after a POST alone.
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except Exception as error:
        # No bearer/config contents or arbitrary server responses in logs.
        print('RESTORE_UNCONFIRMED: '+type(error).__name__);raise SystemExit(1)
