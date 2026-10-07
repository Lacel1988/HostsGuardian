import unittest
from device_types import assess, for_row, TYPES
from datetime import datetime,timezone,timedelta

class DeviceTypesTests(unittest.TestCase):
    def test_retained_stale_conflict_and_user_authority(self):
        now=datetime.now(timezone.utc)
        last=dict(deviceType='TV',confidence='Medium',reason='Category agrees with renderer',assessedAtUtc=(now-timedelta(minutes=6)).isoformat(),evidence=[])
        retained=dict(classification=last,provenance=['SSDP · DeviceRole: MediaRenderer'],retainUntilUtc=(now+timedelta(hours=23)).isoformat())
        row={'lanObservation':{'classification':dict(deviceType='Unknown',confidence='Unknown'), 'lastReliableClassification':retained}}
        value=for_row(row)
        self.assertEqual((value['type']['id'],value['confidence'],value['freshness']),('TV','Medium','STALE'))
        self.assertEqual(value['lastClassified'],last['assessedAtUtc'])
        row['lanObservation']['classification']['conflictingEvidence']=True
        self.assertEqual(for_row(row)['freshness'],'CONFLICT')
        row['lanObservation']['identity']=dict(state='Registered',deviceType='Unknown')
        self.assertEqual(for_row(row)['source'],'USER-CONFIRMED')
        row['lanObservation'].pop('identity');retained['retainUntilUtc']=(now-timedelta(seconds=1)).isoformat()
        self.assertEqual(for_row(row)['type']['id'],'Unknown')
    def test_user_authority_and_explicit_unknown(self):
        self.assertEqual(assess('Phone',['office-printer'])['type']['id'],'Phone')
        self.assertEqual(assess('Unknown',['my-iphone'])['source'],'USER-CONFIRMED')
    def test_conservative_hostname_hints(self):
        value=assess('',['my-iphone'])
        self.assertEqual((value['type']['id'],value['source'],value['confidence']),('Phone','INFERRED','Low'))
        for names in ([],['Samsung'],['phone-printer'],['my-phone','other-phone']):
            self.assertEqual(assess('',names)['type']['id'],'Unknown')
    def test_legacy_and_missing_evidence(self):
        self.assertEqual(assess('LegacyType',['my-iphone'])['type']['id'],'Unknown')
        self.assertEqual(for_row({'networkEvidence':{'mac':'02:DE:AD:BE:EF:01','address':'192.0.2.1'}})['type']['id'],'Unknown')
    def test_single_vector_catalog(self):
        self.assertEqual(len(TYPES),13)
        self.assertEqual(len({t['iconKey'] for t in TYPES}),13)
        self.assertTrue(all(t['strokes'] and all(len(p)==2 for stroke in t['strokes'] for p in stroke) for t in TYPES))

    def test_shared_classification_conflict_and_user_precedence(self):
        c=dict(deviceType='TV',confidence='Medium',source='INFERRED',reason='Class-specific role',assessedAtUtc=datetime.now(timezone.utc).isoformat(),evidence=[])
        row={'lanObservation':{'classification':c,'identity':{'state':'Registered','deviceType':'Phone'}}}
        self.assertEqual(for_row(row)['source'],'USER-CONFIRMED')
        row['lanObservation']['identity']['deviceType']=''
        self.assertEqual(for_row(row)['type']['id'],'TV')
        c.update(deviceType='Unknown',confidence='Unknown',reason='Conflicting evidence')
        self.assertEqual(for_row(row)['type']['id'],'Unknown')
    def test_classification_expiry_and_malformed_fallback(self):
        row={'lanObservation':{'classification':dict(deviceType='Printer',confidence='High',reason='Old',assessedAtUtc=(datetime.now(timezone.utc)-timedelta(minutes=6)).isoformat())}}
        self.assertEqual(for_row(row)['type']['id'],'Unknown')
        row['lanObservation']['classification']={}
        self.assertEqual(for_row(row)['type']['id'],'Unknown')
