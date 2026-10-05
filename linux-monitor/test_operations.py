import copy
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from operations import engine_state, overview, confirmation_text, incident_rows, validate_events, details_text
import test_monitor
import test_diagnostics


class OperationsTests(unittest.TestCase):
    def setUp(self):
        old = test_monitor.MonitorTests(); old.setUp(); self.snapshot = old.value
        diagnostic = test_diagnostics.DiagnosticsTests(); diagnostic.setUp(); self.diagnostic = diagnostic.value
        self.diagnostic['resources']['revision'] = '1.0.0.0'
        self.unit = dict(ActiveState='active', SubState='running', MainPID=123)
        self.diagnostic['components'] = [dict(component='Listeners', state='Healthy', incidentId=None, sinceUtc=None)]
        self.snapshot['diagnostics'] = self.diagnostic

    def batch(self):
        return dict(schemaVersion=1, instanceId='fixture', latestSequence=3, cursorGap=False,
                    events=[dict(sequence=i+1, instanceId='fixture', incidentId='fixture:1', component='Upstream',
                                 type='UPSTREAM_'+suffix, severity=severity, occurredAtUtc=datetime.now(timezone.utc).isoformat(),
                                 state=state, summaryId='engine.upstream_'+suffix.lower(), recoveryOf='fixture:1' if severity=='Recovery' else None)
                            for i, (suffix,severity,state) in enumerate((('DEGRADED','Warning','Degraded'),('CRITICAL','Critical','Critical'),('RECOVERED','Recovery','Healthy')))])

    def test_state_requires_actual_process(self):
        self.assertEqual(engine_state(self.unit),'Running')
        for change in (dict(MainPID=0),dict(SubState='exited'),dict(MainPID='123')):
            self.assertEqual(engine_state(self.unit | change),'Unknown')
        for active,state in (('inactive','Stopped'),('failed','Failed'),('activating','Starting'),('deactivating','Stopping'),('garbage','Unknown')):
            self.assertEqual(engine_state(dict(ActiveState=active)),state)

    def test_stopped_never_uses_lingering_snapshot(self):
        value=overview(dict(ActiveState='inactive'),self.snapshot,self.diagnostic)
        self.assertEqual(value['engine'],'Stopped');self.assertEqual(value['dns'],'Unknown')
        self.assertEqual(value['health'],'Unknown')

    def test_running_without_telemetry_is_not_healthy(self):
        value=overview(self.unit,None)
        self.assertEqual(value['engine'],'Running');self.assertEqual(value['health'],'Unknown')

    def test_running_overview_exposes_evidence_limits(self):
        value=overview(self.unit,self.snapshot,self.diagnostic)
        self.assertIn('PID 123',value['identity']);self.assertIn('1.0.0.0',value['identity'])
        self.assertEqual(value['upstream'],'Unknown');self.assertIn('does not prove',value['evidence'])
        self.assertIn('Loaded',value['policy'])

    def test_confirmation_only_known_actions(self):
        for action in ('start','stop','restart'):
            title,body=confirmation_text(action)
            self.assertIn(action.capitalize(),title);self.assertIn('authorization',body);self.assertIn('actual service state',body)
        for action in ('enable','reload','restart other.service',''):
            with self.assertRaises(ValueError):confirmation_text(action)

    def test_events_preserve_occurrence_and_relationship(self):
        self.snapshot['operationalEvents']=self.batch()
        note,rows=incident_rows(self.snapshot,self.diagnostic)
        self.assertEqual([r[0] for r in rows],['Recovery','Critical','Warning'])
        self.assertIn('Recovery of fixture:1',rows[0][2])
        self.assertIn(self.snapshot['operationalEvents']['events'][0]['occurredAtUtc'],rows[-1][2])

    def test_old_engine_no_fabricated_recovery(self):
        self.diagnostic['components'][0].update(state='Degraded',incidentId='fixture:2',sinceUtc='2026-10-05T10:00:00+00:00')
        note,rows=incident_rows(self.snapshot,self.diagnostic)
        self.assertIn('unavailable',note);self.assertEqual(len(rows),1)
        self.assertNotIn('Recovery',str(rows))

    def test_event_bounds_instance_order_and_severity(self):
        for alter in (lambda b:b.update(instanceId='old'),lambda b:b.update(events=b['events']*22),
                      lambda b:b['events'][0].update(sequence=9),lambda b:b['events'][0].update(severity='bogus'),
                      lambda b:b['events'][0].update(incidentId='x'*141),lambda b:b['events'][0].update(type='UPSTREAM_RECOVERED')):
            b=self.batch();alter(b)
            with self.assertRaises(ValueError):validate_events(b,'fixture')

    def test_event_gap_and_absence_truthful(self):
        b=self.batch();b['cursorGap']=True;self.snapshot['operationalEvents']=b
        self.assertIn('no longer retained',incident_rows(self.snapshot,self.diagnostic)[0])
        self.assertEqual(incident_rows(None,None)[1],[])

    def test_details_preserve_all_counters_and_transports(self):
        text=details_text(self.unit,self.snapshot,self.diagnostic)
        for field in self.diagnostic['counters']:self.assertIn(field+':',text)
        for phrase in ('freshness bound','connections','processingLatency','Systemd PID','Engine assembly'):
            self.assertIn(phrase,text)

    def test_package_one_launcher_and_same_autostart(self):
        root=Path(__file__).parent
        entries=list((root/'packaging').glob('*.desktop'));self.assertEqual(len(entries),1)
        desktop=entries[0].read_text();self.assertIn('Name=HostsGuardian Monitor',desktop)
        self.assertIn('Exec=/usr/bin/hostsguardian-monitor',desktop)
        layout=(root/'debian/install').read_text()
        self.assertEqual(layout.count('packaging/hostsguardian-monitor.desktop'),2)
        self.assertIn('etc/xdg/autostart',layout);self.assertNotIn('49-hostsguardian-monitor.rules',layout)
        self.assertNotIn('monitor-status.conf',layout)
        self.assertIn('operations.py usr/lib/hostsguardian-monitor',layout)

    def test_presentation_has_no_control_or_secret_access(self):
        source=Path(__file__).with_name('operations.py').read_text()
        for forbidden in ('open(', 'read_text(', 'subprocess','urllib','Authorization','management-token','ReplacePolicy'):
            self.assertNotIn(forbidden,source)

if __name__=='__main__':unittest.main()
