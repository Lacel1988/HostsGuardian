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
    def test_topology_missing_cairo_bridge_keeps_list_and_details(self):
        from unittest.mock import patch
        from test_topology import fixture
        from topology_ui import TopologyView
        with patch('topology_ui.CAIRO_AVAILABLE',False):
            from datetime import datetime,timezone
            view=TopologyView();view.render(fixture());view.validator_health(dict(state='UNAVAILABLE',reason='Fixture only',checkedAtUtc=datetime.now(timezone.utc).isoformat()))
            self.assertIsNotNone(view.list.get_first_child());self.assertIn('Unknown fixture',view.details.get_text())
            self.assertIn('UNAVAILABLE',view.validator_note.get_text())
            view.validator_health(dict(state='READY',reason='Old evidence',checkedAtUtc='2000-01-01T00:00:00Z'))
            self.assertIn('UNKNOWN',view.validator_note.get_text())

    def test_realized_topology_native_cairo_draw_callback(self):
        import time
        from unittest.mock import patch
        from test_topology import fixture
        from topology_ui import TopologyView,CAIRO_AVAILABLE
        if not CAIRO_AVAILABLE:self.skipTest('Explicit python3-gi-cairo bridge prerequisite absent')
        calls=[];original=TopologyView.draw
        def draw(view,*args):
            original(view,*args);calls.append(True)
        with patch.object(TopologyView,'draw',draw):
            view=TopologyView();view.render(fixture());window=Gtk.Window();window.set_default_size(1000,650);window.set_child(view);window.present()
            deadline=time.monotonic()+3
            try:
                while not calls and time.monotonic()<deadline:self.drain();time.sleep(.01)
                self.assertTrue(calls,'Native Gtk.DrawingArea Cairo callback was not realized')
            finally:window.destroy();self.drain()

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
    def test_topology_graph_selection_layers_unknowns_and_stable_refresh(self):
        from test_topology import fixture
        view=self.app.topology_view;value=fixture();view.render(value)
        self.app.stack.set_visible_child_name('topology');self.drain()
        self.assertEqual(self.app.page_heading.get_text(),'TOPOLOGY')
        self.assertIsInstance(view.canvas,Gtk.DrawingArea)
        view.selected='fixture';view.show_details();view.render(value)
        self.assertEqual(view.selected,'fixture');self.assertIn('Unknown',view.details.get_text())
        view.layer.set_selected(1);self.drain()
        view.render(None);self.assertIsNone(view.selected)
        self.client.control.assert_not_called()
    def test_device_diagnostics_visible_and_selected_page_is_explicit(self):
        self.app.stack.set_visible_child_name('diagnostics');self.drain()
        self.assertEqual(self.app.page_heading.get_text(),'DIAGNOSTICS')
        page=self.app.stack.get_child_by_name('diagnostics')
        self.assertIsInstance(page,Gtk.ScrolledWindow)
        link=self.app.diagnostics_page.get_last_child()
        self.assertIsInstance(link,Gtk.Button)
        link.emit('clicked');self.drain()
        self.assertIs(self.app.stack.get_visible_child(),self.app.device_view)
        self.assertEqual(self.app.page_heading.get_text(),'DEVICES')
        self.assertEqual(self.app.device_view.scroll.get_policy()[1],Gtk.PolicyType.ALWAYS)
        self.assertTrue(self.app.device_view.panes.get_vexpand())
    def test_independent_lan_device_without_dns_remains_visible_and_selectable(self):
        import test_device_diagnostics
        fixture=test_device_diagnostics.DeviceAwareTests();fixture.setUp()
        fixture.value['devices']['devices']=[];fixture.value['devices']['lanDevices']=[fixture.lan()]
        model=self.app.device_diagnostics;model.accept(fixture.value);view=self.app.device_view;view.render(model);self.drain()
        self.assertEqual(len(model.rows),1)
        self.assertIsNotNone(view.list.get_row_at_index(0))
        self.assertIn('Unknown device',view.detail_title.get_text())
        self.assertIn('LAN observation does not establish DNS path',view.technical_text.get_text())
    def test_compact_device_rows_selection_and_refresh_preserve_uncertain_identity(self):
        import test_device_diagnostics
        fixture=test_device_diagnostics.DeviceAwareTests();fixture.setUp()
        model=self.app.device_diagnostics;model.accept(copy.deepcopy(fixture.value))
        self.app.device_view.render(model)
        self.assertEqual(self.app.device_view.list.get_row_at_index(0).tracking,'a'*32)
        self.assertIn('Unknown device',self.app.device_view.detail_title.get_text())
        other=copy.deepcopy(fixture.row);other['trackingId']='b'*32;other['lastObservedAddress']='192.0.2.2'
        fixture.value['devices']['devices'].append(other);model.accept(fixture.value)
        # Same-time updates are deliberately ignored; new samples trigger a coherent rebuild.
        model.previous=None;model.accept(fixture.value);self.app.device_view.render(model)
        self.app.device_view.list.select_row(self.app.device_view.list.get_row_at_index(1))
        self.assertEqual(self.app.device_view.selected_tracking,'b'*32)
        self.app.device_view.render(model);self.assertEqual(self.app.device_view.selected_tracking,'b'*32)
        self.assertFalse(self.app.device_view.technical.get_expanded())
        model.accept(None);self.app.device_view.render(model)
        self.assertIsNone(self.app.device_view.selected_tracking)
        self.assertIsNone(self.app.device_view.list.get_row_at_index(0))
        self.client.control.assert_not_called()
    def test_all_sources_have_independent_list_and_detail_scroll_panes(self):
        import test_device_diagnostics
        fixture=test_device_diagnostics.DeviceAwareTests();fixture.setUp()
        fixture.value['devices']['devices']=[]
        for index in range(64):
            row=copy.deepcopy(fixture.row);row['trackingId']=f'{index:032x}';row['lastObservedAddress']=f'2001:db8::{index+1:x}'
            fixture.value['devices']['devices'].append(row)
        model=self.app.device_diagnostics;model.accept(fixture.value);view=self.app.device_view;view.render(model)
        self.assertIn('64 device/source rows',view.summary.get_text())
        self.assertIs(view.panes.get_start_child(),view.scroll)
        self.assertIs(view.panes.get_end_child(),view.detail_scroll)
        self.assertIsNot(view.scroll.get_vadjustment(),view.detail_scroll.get_vadjustment())
        self.assertIsNotNone(view.list.get_row_at_index(63));self.assertIsNone(view.list.get_row_at_index(64))
        view.list.select_row(view.list.get_row_at_index(63));self.assertIn('2001:db8::40',view.detail_title.get_text())
        self.client.control.assert_not_called()

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

    def test_shared_vector_type_icons_keep_text_and_uncertainty(self):
        from device_diagnostics_ui import DeviceTypeIcon
        from device_types import assess
        for confirmed,names,key in [('Phone',['office-printer'],'device-phone'),('Unknown',['my-iphone'],'device-unknown'),('',[],'device-unknown'),('',['office-printer'],'device-printer')]:
            icon=DeviceTypeIcon(assess(confirmed,names))
            self.assertEqual(icon.icon_key,key)
            self.assertTrue(icon.get_tooltip_text())
            self.assertGreater(len(icon.definition['strokes']),0)

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
