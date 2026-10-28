"""Prepare an exclusive, private recovery session using authenticated GET only.

Run before a separately approved activation. Never arms a timer or changes policy.
Existing session is used only for its API credential/certificate file references.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from p0_policy_restore import Api, Conflict, make_session


def write_session(path, session):
    data=(json.dumps(session,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(data).hexdigest()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--api-session',type=Path,required=True)
    parser.add_argument('--device-id',required=True)
    parser.add_argument('--domain',action='append',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    config=json.loads(args.api_session.read_bytes())['api']
    api=Api(config)
    original=api.call('/v2/policy')
    session=make_session(original,config,args.device_id,args.domain)
    # Abort if policy/instance changed while preparing; activation must recheck too.
    if api.call('/v2/policy')!=original:raise Conflict('Policy changed during preparation')
    pin=write_session(args.output,session)
    print('SESSION_PREPARED_NOT_ARMED; SHA256='+pin)


if __name__=='__main__':
    try:main()
    except Exception as error:
        print('SESSION_PREPARATION_FAILED: '+type(error).__name__)
        raise SystemExit(1)
