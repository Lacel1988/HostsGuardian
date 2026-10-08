"""Explicitly approved independent recovery only; no Block action or DNS probes."""
import argparse
import hashlib
import json
from pathlib import Path
import ssl
import urllib.request


class Conflict(RuntimeError):pass


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
    original=session['original']['policy'];approved={tuple(x) for x in session['approvedOverrides']}
    if not approved or len(approved)>64:raise Conflict('Explicit recovery scope required')
    ids={x['deviceId'] for x in original['devices']}
    if any(device not in ids or domain!='youtube.com' for device,domain in approved):raise Conflict('Unknown recovery target/domain')
    current=api.call('/v2/policy')
    safe_to_restore(original,current['policy'],approved)
    if current['policy']==original:return dict(restored=True,revision=current['revision'],alreadyOriginal=True)
    ack=api.call('/v2/policy/replace',dict(expectedRevision=current['revision'],expectedInstanceId=current['instanceId'],policy=original))
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
    session=json.loads(data);api=Api(session['api'])
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
