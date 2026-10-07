"""Validate Engine-owned topology; no discovery, registration or topology inference here."""
import ipaddress
from datetime import datetime, timezone


def validate(snapshot, now=None):
    if snapshot is None:
        return None
    now = now or datetime.now(timezone.utc)
    if not isinstance(snapshot, dict) or snapshot.get('schemaVersion') != 1:
        raise ValueError('Unsupported topology')
    stamp = datetime.fromisoformat(snapshot['snapshotUtc'].replace('Z', '+00:00'))
    if not -2 <= (now-stamp).total_seconds() <= 10:
        raise ValueError('Topology expired')
    nodes, links, networks = snapshot['nodes'], snapshot['links'], snapshot['networks']
    if not isinstance(nodes,list) or not isinstance(links,list) or not isinstance(networks,list) or len(nodes)>128 or len(links)>256 or len(networks)>64:
        raise ValueError('Unbounded topology')
    def text(value, limit=256):
        if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 for c in value): raise ValueError('Invalid topology label')
    network_ids={n["id"] for n in networks if isinstance(n,dict) and isinstance(n.get("id"),str)}
    ids=set()
    for node in nodes:
        for field in ('id','kind','name','deviceType','presence','access','dnsActivity','coverage','binding','policyIdentity'):
            text(node[field])
        if not node['id'] or node['id'] in ids:raise ValueError('Duplicate node')
        ids.add(node['id'])
        if node.get('networkId') is not None and node['networkId'] not in network_ids:raise ValueError('Unknown network membership')
        if node['access'] not in ('Unknown','Ethernet','Wi-Fi') or node['coverage'] not in ('UNKNOWN','PARTIAL') or node['kind'] not in ('Engine','Registered','Provisional','Gateway','Infrastructure','Resolver'):
            raise ValueError('Unsupported topology semantics')
        if not isinstance(node['addresses'],list) or len(node['addresses'])>8 or not isinstance(node['macs'],list) or len(node['macs'])>8 or not isinstance(node['evidence'],list) or len(node['evidence'])>8:
            raise ValueError('Unbounded node evidence')
        for address in node['addresses']:text(address,64);ipaddress.ip_address(address)
        for mac in node['macs']:text(mac,32)
        if node['deviceId'] is not None:
            import uuid
            uuid.UUID(node['deviceId'])
        for evidence in node['evidence']:
            for field in ('provider','confidence','explanation'):text(evidence[field])
            if evidence['confidence'] not in ('UNKNOWN','OBSERVED','INFERRED','PROVEN','USER-CONFIRMED'):raise ValueError('Invalid evidence confidence')
    seen=set()
    for link in links:
        for field in ('id','from','to','relationship','confidence','explanation'):text(link[field])
        if link['id'] in seen or link['from'] not in ids or link['to'] not in ids or link['confidence'] not in ('UNKNOWN','OBSERVED','INFERRED','PROVEN'):
            raise ValueError('Invalid topology link')
        seen.add(link['id'])
    for network in networks:
        for field in ('id','name','membershipConfidence'):text(network[field])
    for field in ('omittedNodes','omittedLinks'):
        if type(snapshot[field]) is not int or snapshot[field]<0:raise ValueError('Invalid omitted count')
    return snapshot


def positions(nodes):
    ordered=sorted(nodes,key=lambda n:({'Gateway':0,'Engine':1,'Infrastructure':2}.get(n['kind'],3),n.get('networkId') or '',n['id']))
    return {node['id']:(30+(i%4)*240,30+(i//4)*175) for i,node in enumerate(ordered)}
