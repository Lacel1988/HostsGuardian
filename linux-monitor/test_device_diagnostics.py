import unittest
import copy
from datetime import datetime, timezone, timedelta
from device_diagnostics import DeviceAwareDiagnostics


class DeviceAwareTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.model = DeviceAwareDiagnostics()
        stamp = self.now.isoformat()
        self.row = dict(trackingId='a'*32, deviceId=None, identityState='Unknown', name='Unknown device', nameEvidence='UNKNOWN',
            lastObservedAddress='192.0.2.1', firstSeenUtc=stamp,lastSeenUtc=stamp,lastDnsActivityUtc=stamp,cumulativeReceived=10,
            window=dict(received=10,allowed=7,policyBlocked=1,failed=2,servfail=2,rejected=0,capacityDropped=0,cancelled=0,tcpConnectionsRejected=0))
        self.value = dict(instanceId='fixture',snapshotUtc=stamp,counters=dict(received=10),devices=dict(schemaVersion=1,instanceId='fixture',
            snapshotUtc=stamp,policyRevision=1,windowSeconds=600,maximumSources=64,evictedSources=0,devices=[self.row]))
    def test_exact_interval_rate_contribution_and_failure_context(self):
        self.model.accept(copy.deepcopy(self.value)); self.assertIsNone(self.model.rows[0]['rate'])
        self.value['snapshotUtc'] = self.value['devices']['snapshotUtc'] = (self.now+timedelta(seconds=2)).isoformat()
        self.value['counters']['received']=30; self.row['cumulativeReceived']=30
        self.model.accept(copy.deepcopy(self.value))
        self.assertEqual(self.model.rows[0]['rate'],10); self.assertEqual(self.model.rows[0]['share'],100)
        self.assertIn('not proof of cause',self.model.text()); self.assertIn('192.0.2.1',self.model.text())
    def test_confirmed_alias_updates_without_identity_database(self):
        self.model.accept(copy.deepcopy(self.value))
        self.value['snapshotUtc']=self.value['devices']['snapshotUtc']=(self.now+timedelta(seconds=2)).isoformat()
        self.row.update(name='Confirmed fixture alias',nameEvidence='USER-CONFIRMED',deviceId='00000000-0000-0000-0000-000000000001')
        self.model.accept(copy.deepcopy(self.value)); self.assertIn('Confirmed fixture alias [USER-CONFIRMED]',self.model.text())
    def test_restart_unknown_and_unsupported_do_not_fabricate_rates(self):
        self.model.accept(copy.deepcopy(self.value)); self.value['instanceId']=self.value['devices']['instanceId']='new'
        self.model.accept(copy.deepcopy(self.value)); self.assertIsNone(self.model.rows[0]['rate'])
        self.model.accept(dict(instanceId='old')); self.assertEqual(self.model.rows,[])
    def test_passive_network_evidence_is_readonly_and_bounded(self):
        self.row['networkEvidence']=dict(address='192.0.2.1',mac='02:00:00:00:00:01',hostname='',provenance='OBSERVED: kernel neighbour cache',observedAtUtc=self.now.isoformat())
        self.model.accept(self.value)
        self.assertIn('02:00:00:00:00:01',self.model.text()); self.assertIsNone(self.model.rows[0]['deviceId'])
        self.row['networkEvidence']['hostname']='x'*129
        self.model.accept(self.value);self.assertEqual(self.model.rows,[])
    def test_invalid_and_unbounded_device_data_isolated(self):
        self.value['devices']['devices']=[self.row]*65; self.model.accept(self.value)
        self.assertEqual(self.model.rows,[]); self.assertIn('aggregate diagnostics remain separate',self.model.message)

    def lan(self,address='2001:db8::238',mac='02:00:00:00:00:01',identifier='00000000-0000-0000-0000-000000000042'):
        return dict(observationDeviceId=identifier,stability='SESSION / PROVISIONAL',presence='OBSERVED',firstObservedUtc=self.now.isoformat(),lastObservedUtc=self.now.isoformat(),dnsActivity='NOT OBSERVED',coverage='UNKNOWN',resolverPath='UNKNOWN',explanation='LAN observation does not establish DNS path.',evidence=[dict(address=address,mac=mac,hostname='',provenance='OBSERVED: kernel NDP cache',observedAtUtc=self.now.isoformat(),interface='fixture',neighborState='STALE',privateMacPossible=True)])

    def test_control_plane_name_for_lan_only_device_preserves_observed_hostname(self):
        lan=self.lan();lan['identity']=dict(deviceId='00000000-0000-0000-0000-000000000099',friendlyName='User friendly fixture',observedHostname='Observed-host',state='Registered',confidence='USER-CONFIRMED',provenance='Explicit fixture registration + unique current MAC',groups=['Family'],deviceType='Phone',privateMacPossible=True)
        self.value['devices']['devices']=[];self.value['devices']['lanDevices']=[lan]
        self.model.accept(self.value);row=self.model.rows[0]
        self.assertEqual(row['name'],'User friendly fixture');self.assertEqual(row['deviceId'],lan['identity']['deviceId'])
        self.assertEqual(row['lanObservation']['identity']['observedHostname'],'Observed-host')
        self.assertEqual(row['window']['received'],0);self.assertEqual(row['lanObservation']['coverage'],'UNKNOWN')
        self.assertNotEqual(row['deviceId'],lan['observationDeviceId'])

    def test_ambiguous_control_plane_identity_is_not_named_or_merged(self):
        lan=self.lan();lan['identity']=dict(deviceId=None,friendlyName='',observedHostname='',state='Ambiguous',confidence='UNKNOWN',provenance='Conflicting fixture registration',groups=[],deviceType='')
        self.value['devices']['devices']=[];self.value['devices']['lanDevices']=[lan]
        self.model.accept(self.value);self.assertEqual(self.model.rows[0]['name'],'Unknown device');self.assertIsNone(self.model.rows[0]['deviceId'])
        lan['identity']['deviceId']='00000000-0000-0000-0000-000000000099'
        self.model.accept(self.value);self.assertEqual(self.model.rows,[])

    def test_independent_lan_device_present_with_zero_dns(self):
        self.value['devices']['devices']=[]; self.value['devices']['lanDevices']=[self.lan()]
        self.model.accept(self.value)
        self.assertEqual(len(self.model.rows),1)
        row=self.model.rows[0]
        self.assertEqual(row['window']['received'],0);self.assertIsNone(row['deviceId'])
        self.assertEqual(row['lanObservation']['coverage'],'UNKNOWN');self.assertIsNone(row['rate'])

    def test_lan_correlates_source_without_monitor_identity_registry(self):
        self.value['devices']['lanDevices']=[self.lan(self.row['lastObservedAddress'])]
        self.model.accept(self.value)
        self.assertEqual(len(self.model.rows),1);self.assertEqual(self.model.rows[0]['window']['received'],self.row['window']['received'])
        self.assertIsNone(self.model.rows[0]['deviceId'])

    def test_conflicting_bindings_do_not_merge_or_duplicate_dns_counts(self):
        self.value['devices']['lanDevices']=[self.lan(self.row['lastObservedAddress']),self.lan(self.row['lastObservedAddress'],'02:00:00:00:00:02','00000000-0000-0000-0000-000000000043')]
        self.model.accept(self.value)
        self.assertEqual(len(self.model.rows),3)
        self.assertEqual(sum(r['window']['received'] for r in self.model.rows),self.row['window']['received'])

    def test_unjustified_complete_lan_coverage_rejected(self):
        lan=self.lan();lan['coverage']='COMPLETE';self.value['devices']['lanDevices']=[lan]
        self.model.accept(self.value);self.assertEqual(self.model.rows,[])

    def test_registered_display_survives_mixed_dns_attribution(self):
        lan=self.lan(self.row['lastObservedAddress'])
        identifier='00000000-0000-0000-0000-000000000099'
        lan['identity']=dict(deviceId=identifier,friendlyName='Registered appliance',observedHostname='',state='Registered',confidence='USER-CONFIRMED',provenance='Explicit registration',groups=[],deviceType='TV')
        registered=copy.deepcopy(self.row)
        registered.update(trackingId='b'*32,deviceId=identifier,name='Registered appliance',nameEvidence='USER-CONFIRMED',identityState='Validated')
        registered['window']['received']=58
        self.row['window']['received']=40
        self.value['devices']['devices']=[registered,self.row]
        self.value['devices']['lanDevices']=[lan]
        self.model.accept(self.value)
        row=self.model.rows[0]
        self.assertEqual(row['name'],'Registered appliance')
        self.assertEqual(row['identityState'],'Registered')
        self.assertTrue(row['dnsIdentityConflict'])
        self.assertEqual(row['dnsAttribution'],dict(attributed=58,unresolved=40,deviceIds=[identifier],state='MIXED'))
        self.assertIsNone(self.row['deviceId'])
