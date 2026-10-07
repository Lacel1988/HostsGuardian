import copy
import unittest
from datetime import datetime,timezone,timedelta
from topology import validate,positions


def fixture():
    now=datetime.now(timezone.utc).isoformat()
    def node(id,kind='Provisional'):
        return dict(id=id,kind=kind,name='Unknown fixture',deviceId=None,deviceType='',presence='Cached; online unknown',access='Unknown',addresses=['192.0.2.20'],macs=[],dnsActivity='NOT OBSERVED',coverage='UNKNOWN',binding='Unknown / unvalidated',policyIdentity='Global fallback / identity unvalidated',evidence=[])
    return dict(schemaVersion=1,snapshotUtc=now,nodes=[node('engine','Engine'),node('fixture')],links=[],networks=[dict(id='unknown',name='Unknown network',membershipConfidence='UNKNOWN')],omittedNodes=0,omittedLinks=0)


class TopologyTests(unittest.TestCase):
    def test_unknowns_are_valid_without_router_integration(self):
        value=fixture();self.assertIs(validate(value),value);self.assertEqual(value['links'],[])

    def test_layout_stable_across_refresh_and_order(self):
        value=fixture();self.assertEqual(positions(value['nodes']),positions(list(reversed(value['nodes']))))

    def test_confidence_and_dns_layers_remain_separate(self):
        value=fixture();value['links']=[dict(id='dns',**{'from':'fixture','to':'engine'},relationship='DNS activity',confidence='OBSERVED',explanation='Partial activity only',observedAtUtc=value['snapshotUtc'])]
        self.assertEqual(validate(value)['nodes'][1]['access'],'Unknown')
        value['nodes'][1]['coverage']='COMPLETE'
        with self.assertRaises(ValueError):validate(value)

    def test_expired_missing_malformed_duplicate_and_oversized_fail_closed(self):
        value=fixture();value['snapshotUtc']=(datetime.now(timezone.utc)-timedelta(seconds=11)).isoformat()
        with self.assertRaises(ValueError):validate(value)
        self.assertIsNone(validate(None))
        for mutate in (lambda v:v['nodes'].append(copy.deepcopy(v['nodes'][0])),lambda v:v['nodes'][0].update(name='bad\nlabel'),lambda v:v.update(nodes=v['nodes']*65),lambda v:v['nodes'][0].update(addresses=['not an address'])):
            value=fixture();mutate(value)
            with self.assertRaises(ValueError):validate(value)

    def test_wrong_links_cannot_invent_node_or_promote_confidence(self):
        value=fixture();value['links']=[dict(id='bad',**{'from':'missing','to':'engine'},relationship='Wi-Fi',confidence='PROVEN',explanation='Bad endpoint',observedAtUtc=value['snapshotUtc'])]
        with self.assertRaises(ValueError):validate(value)


if __name__=='__main__':unittest.main()
