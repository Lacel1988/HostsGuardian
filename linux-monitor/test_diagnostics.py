import unittest
import copy
import json
from datetime import datetime, timezone, timedelta
from diagnostics import LiveHistory, graph_scale, validate

class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.tick = 0
        self.history = LiveHistory(lambda: self.tick)
        self.value = {'schemaVersion': 1, 'instanceId': 'fixture', 'snapshotUtc': self.now.isoformat(),
            'counters': {k: 0 for k in ('received','udp','tcp','allowed','policyBlocked','failed','rejected','capacityDropped','cancelled','servfail',
                'upstreamAttempts','upstreamTimeouts','upstreamFailures','upstreamRetries','fallbackAttempts','tcpConnectionsRejected','transportFailures')},
            'pressure': dict(currentRequests=0,peakRequests=0,udpCurrent=0,udpCapacity=16,tcpCurrentRequests=0,tcpConnections=0,tcpConnectionCapacity=16,capacityDrops=0),
            'upstreamLatency': dict(samples=0,recentMs=None,p50Ms=None,p95Ms=None),
            'processingLatency': dict(samples=0,recentMs=None,p50Ms=None,p95Ms=None),
            'resources': dict(uptimeSeconds=0,cpuPercent=None,workingSetBytes=10000,processId=123),
            'health':'Healthy','components': [],'resolvers': []}
    def advance(self, count=0, seconds=1):
        self.tick += seconds
        self.value['snapshotUtc'] = (self.now + timedelta(seconds=self.tick)).isoformat()
        self.value['resources']['uptimeSeconds'] = self.tick
        self.value['counters']['received'] += count
        return self.history.accept(copy.deepcopy(self.value), self.now + timedelta(seconds=self.tick))
    def test_zero_traffic_and_insufficient_samples(self):
        self.assertTrue(self.history.accept(copy.deepcopy(self.value),self.now))
        self.assertIsNone(self.history.rate)
        self.advance();self.assertEqual(self.history.rate,0)
        self.assertIsNone(self.history.samples[-1][2])
    def test_rate_uses_actual_engine_elapsed_time(self):
        self.history.accept(copy.deepcopy(self.value),self.now)
        self.advance(20,2);self.assertEqual(self.history.rate,10)
    def test_duplicates_not_fabricated(self):
        self.history.accept(copy.deepcopy(self.value),self.now)
        self.tick=1;self.history.accept(copy.deepcopy(self.value),self.now)
        self.assertEqual(len(self.history.samples),1)
    def test_blocked_only_latency_missing_is_not_error(self):
        self.value['counters']['received']=self.value['counters']['policyBlocked']=40
        self.history.accept(copy.deepcopy(self.value),self.now)
        self.assertEqual(self.history.current['health'],'Healthy')
        self.assertIsNone(self.history.current['upstreamLatency']['p95Ms'])
    def test_latency_is_separate_and_percentiles_preserved(self):
        self.value['upstreamLatency']=dict(samples=20,recentMs=15,p50Ms=10,p95Ms=40)
        self.value['processingLatency']=dict(samples=40,recentMs=20,p50Ms=12,p95Ms=60)
        self.history.accept(copy.deepcopy(self.value),self.now)
        self.assertEqual(self.history.samples[-1][2:],(10,40))
    def test_unavailable_clears_current_but_preserves_gap_history(self):
        self.history.accept(copy.deepcopy(self.value),self.now)
        self.tick=2;self.history.missing()
        self.assertFalse(self.history.available);self.assertIsNone(self.history.current)
        self.assertIsNone(self.history.samples[-1][1])
        self.advance(20);self.assertIsNone(self.history.rate)
    def test_stale_future_invalid_and_nan_refused(self):
        for change in ('stale','future','nan','counter','schema'):
            value=copy.deepcopy(self.value)
            if change=='stale':value['snapshotUtc']=(self.now-timedelta(seconds=11)).isoformat()
            if change=='future':value['snapshotUtc']=(self.now+timedelta(seconds=3)).isoformat()
            if change=='nan':value['upstreamLatency']['p95Ms']=float('nan')
            if change=='counter':value['counters']['received']=-1
            if change=='schema':value['schemaVersion']=99
            self.assertFalse(self.history.accept(value,self.now))
            self.assertIsNone(self.history.current)
    def test_restart_resets_history_and_delta(self):
        self.history.accept(copy.deepcopy(self.value),self.now);self.advance(10)
        self.value['instanceId']='new';self.advance(10)
        self.assertIsNone(self.history.rate);self.assertEqual(len(self.history.samples),1)
    def test_bounded_history_by_count_and_elapsed_window(self):
        for _ in range(2000):self.advance(1)
        self.assertLessEqual(len(self.history.samples),600)
        self.tick+=601;self.history.missing();self.assertEqual(len(self.history.samples),1)
    def test_counter_reset_and_long_gap_do_not_create_negative_or_misleading_rate(self):
        self.value['counters']['received']=100
        self.history.accept(copy.deepcopy(self.value),self.now)
        self.value['counters']['received']=0;self.advance();self.assertIsNone(self.history.rate)
        self.advance(100,20);self.assertIsNone(self.history.rate)
    def test_graph_zero_origin_scale_and_spike_not_clipped(self):
        self.assertEqual(graph_scale([None,0,0],10),10)
        self.assertGreater(graph_scale([1,10000,1],10),10000)
    def test_ui_has_no_analytics_policy_or_secret_widgets_and_packages_module(self):
        from pathlib import Path
        source=Path(__file__).with_name('monitor.py').read_text(encoding='utf-8')
        for forbidden in ('ApiToken','CredentialPath','DeleteDevice','ReplacePolicy','dns-observations'):
            self.assertNotIn(forbidden,source)
        self.assertIn('diagnostics.py usr/lib/hostsguardian-monitor',(Path(__file__).parent / 'debian/install').read_text(encoding='utf-8'))

if __name__=='__main__':unittest.main()
