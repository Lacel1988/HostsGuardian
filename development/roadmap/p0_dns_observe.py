"""Bounded authenticated read-only acceptance collector. No policy or DNS requests."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import time
from p0_policy_restore import Api,Conflict


def collect(api,seconds,output,clock=time.monotonic,pause=time.sleep):
    if not 5<=seconds<=300:raise Conflict('Bounded observation window required')
    start=datetime.datetime.now(datetime.timezone.utc);deadline=clock()+seconds;seen=set();attempt=0
    with output.open('x',encoding='utf-8') as stream:
        while clock()<deadline:
            attempt+=1;record=dict(attempt=attempt,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),responseEvidence='NOT_AVAILABLE_FROM_DECISION_API')
            try:
                for path,key in (('/v2/policy','policy'),('/v2/bindings','bindings'),('/v2/dns-observations','decisions')):
                    if clock()>=deadline:break
                    record[key]=api.call(path)
                if 'decisions' in record:
                    fresh=[]
                    for decision in record['decisions']['observations']:
                        stamp=datetime.datetime.fromisoformat(decision['request']['receivedAtUtc'].replace('Z','+00:00'))
                        key=json.dumps(decision,sort_keys=True)
                        if stamp>=start and key not in seen and len(seen)<10000:
                            seen.add(key);fresh.append(decision)
                    record['decisions']={'observations':fresh}
            except Exception as error:record['errorType']=type(error).__name__
            stream.write(json.dumps(record)+'\n');stream.flush()
            pause(min(2,max(0,deadline-clock())))
    return dict(attempts=attempt,uniqueClientDecisions=len(seen),dnsResponseAcceptance='PENDING')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--session',type=Path,required=True)
    parser.add_argument('--sha256',required=True);parser.add_argument('--seconds',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    data=args.session.read_bytes()
    if hashlib.sha256(data).hexdigest()!=args.sha256:raise Conflict('Session changed')
    config=json.loads(data);print(json.dumps(collect(Api(config['api']),args.seconds,args.output)))


if __name__=='__main__':main()
