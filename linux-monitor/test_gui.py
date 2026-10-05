"""GTK fixtures never connect to systemd or operate production services."""
import copy
import os
import uuid
import unittest
from unittest.mock import Mock
import test_monitor
import test_diagnostics
try:
    from monitor import Monitor, SystemdClient
    from gi.repository import Gtk, GLib
    GTK_AVAILABLE = bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))
except ImportError:
    GTK_AVAILABLE = False

@unittest.skipUnless(GTK_AVAILABLE, 'GTK graphical session required')
class GuiTests(unittest.TestCase):
    def setUp(self):
        fixture=test_monitor.MonitorTests();fixture.setUp();self.snapshot=fixture.value
        fixture=test_diagnostics.DiagnosticsTests();fixture.setUp();self.diagnostic=fixture.value
        self.snapshot['diagnostics']=self.diagnostic
        self.unit=dict(ActiveState='active',SubState='running',MainPID=123)
        self.client=Mock();self.client.status.return_value=(self.unit,self.snapshot)
        self.app=Monitor();self.app.set_application_id('org.hostsguardian.UnifiedTests.t'+uuid.uuid4().hex);self.app.client=self.client
        def synchronous(action, completed):
            try:result,error=action(),None
            except Exception:result,error=None,'Local service operation unavailable or authorization refused.'
            completed(result,error)
        self.app.run_worker=synchronous
        self.app.register(None);self.app.activate();self.drain()
    def drain(self):
        context=GLib.MainContext.default()
        for _ in range(100):
            if not context.pending():break
            context.iteration(False)
    def tearDown(self):
        for window in list(self.app.get_windows()):window.destroy()
        if not self.app.closed:self.app.shutdown_monitor(self.app)
        self.drain()
    def dialog(self):
        return next(w for w in self.app.get_windows() if isinstance(w,Gtk.MessageDialog))
    def test_running_stopped_failed_readback(self):
        self.assertEqual(self.app.engine_label.get_text(),'Running')
        for active,label in (('inactive','Stopped'),('failed','Failed')):
            self.app.show_status((dict(ActiveState=active,SubState='dead',MainPID=0),None),None)
            self.assertEqual(self.app.engine_label.get_text(),label)
            self.assertEqual(self.app.rate_label.get_text(),'— queries / s')
    def test_confirmation_decline_never_operates(self):
        self.app.confirm('stop');self.dialog().response(Gtk.ResponseType.NO);self.drain()
        self.client.control.assert_not_called()
    def test_request_then_actual_readback(self):
        self.client.control.return_value='Action requested; waiting for observed state.'
        self.app.confirm('stop');self.dialog().response(Gtk.ResponseType.YES);self.drain()
        self.client.control.assert_called_once_with('stop')
        self.assertEqual(self.app.engine_label.get_text(),'Running')
        self.client.status.return_value=(dict(ActiveState='inactive',SubState='dead',MainPID=0),None)
        self.app.poll();self.assertEqual(self.app.engine_label.get_text(),'Stopped')
        self.client.status.return_value=(self.unit,self.snapshot)
        self.app.confirm('start');self.dialog().response(Gtk.ResponseType.YES);self.drain()
        self.assertEqual(self.app.engine_label.get_text(),'Running')
    def test_authorization_failure_does_not_invent_success(self):
        self.client.control.side_effect=PermissionError('fixture refusal')
        self.app.confirm('restart');self.dialog().response(Gtk.ResponseType.YES);self.drain()
        self.assertIn('authorization refused',self.app.notice.get_text())
        self.assertEqual(self.app.engine_label.get_text(),'Running')
    def test_duplicate_confirmation_and_pending_blocked(self):
        self.app.confirm('restart');self.app.confirm('restart')
        self.assertEqual(sum(isinstance(w,Gtk.MessageDialog) for w in self.app.get_windows()),1)
        self.dialog().response(Gtk.ResponseType.NO)
        self.app.pending=True;self.app.confirm('stop');self.client.control.assert_not_called()
    def test_stale_unavailable_and_restart_reconnect(self):
        stale=copy.deepcopy(self.snapshot);stale['diagnostics']['snapshotUtc']='2020-01-01T00:00:00+00:00'
        self.app.show_status((self.unit,stale),None)
        self.assertIsNone(self.app.history.current);self.assertEqual(self.app.health_label.get_text(),'UNKNOWN')
        self.app.show_status(({},None),'fixture failure');self.assertEqual(self.app.engine_label.get_text(),'Unknown')
        new=copy.deepcopy(self.snapshot);new['diagnostics']['instanceId']='restarted'
        self.app.show_status((self.unit,new),None)
        self.assertEqual(self.app.history.current['instanceId'],'restarted');self.assertIsNone(self.app.history.rate)
    def test_wrong_diagnostic_pid_is_not_current(self):
        snapshot=copy.deepcopy(self.snapshot);snapshot['diagnostics']['resources']['processId']=999
        self.app.show_status((self.unit,snapshot),None)
        self.assertIsNone(self.app.history.current);self.assertEqual(self.app.health_label.get_text(),'UNKNOWN')

    def test_close_never_calls_service_control(self):
        self.app.shutdown_monitor(self.app)
        self.client.control.assert_not_called();self.assertTrue(self.app.closed)
    def test_close_with_confirmation_never_operates(self):
        self.app.confirm('stop');dialog=self.dialog()
        self.app.close_window(self.app.window)
        dialog.response(Gtk.ResponseType.YES)
        self.client.control.assert_not_called();self.assertTrue(self.app.closed)

    def test_navigation_and_details(self):
        self.assertEqual(self.app.stack.get_visible_child_name(),'overview')
        for page in ('overview','diagnostics','incidents','details'):self.assertIsNotNone(self.app.stack.get_child_by_name(page))
        buf=self.app.details.get_buffer();text=buf.get_text(buf.get_start_iter(),buf.get_end_iter(),False)
        self.assertIn('capacityDropped',text);self.assertIn('history unavailable',self.app.incident_note.get_text())
    def test_fixed_unit_client_interactive_restrictions(self):
        client=SystemdClient.__new__(SystemdClient);client.call=Mock(return_value=())
        for verb,method in (('start','StartUnit'),('stop','StopUnit'),('restart','RestartUnit')):
            client.control(verb);args,kwargs=client.call.call_args
            self.assertEqual(args[2],method);self.assertTrue(kwargs['interactive'])
            self.assertEqual(args[3].unpack(),('hostsguardian-engine.service','replace'))
        count=client.call.call_count
        with self.assertRaises(ValueError):client.control('reload')
        self.assertEqual(client.call.call_count,count)

if __name__=='__main__':unittest.main()
