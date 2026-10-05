#!/usr/bin/python3
"""Unprivileged GTK monitor. Closing it never issues a service operation."""
import os
import sys
import math
from diagnostics import LiveHistory, graph_scale, WINDOW_SECONDS
from operations import overview, incident_rows, details_text, confirmation_text
from concurrent.futures import ThreadPoolExecutor
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Graphene", "1.0")
from gi.repository import Gio, GLib, Gtk, Gdk, Graphene
from monitor_core import UNIT, STATUS_PATH, control_request, read_snapshot, describe


class GraphCanvas(Gtk.Widget):
    def __init__(self, draw):
        super().__init__()
        self.draw = draw
        self.set_hexpand(True); self.set_vexpand(True)
        self.set_size_request(120, 110)
    def do_snapshot(self, snapshot):
        self.draw(snapshot, self.get_width(), self.get_height())


class SystemdClient:
    def __init__(self):
        self.bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

    def call(self, path, interface, method, parameters, interactive=False):
        flags = Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION if interactive else Gio.DBusCallFlags.NONE
        return self.bus.call_sync("org.freedesktop.systemd1", path, interface, method,
                                  parameters, None, flags, 30000 if interactive else 2000, None).unpack()

    def status(self):
        path = self.call("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnit", GLib.Variant("(s)", (UNIT,)))[0]
        unit = self.call(path, "org.freedesktop.DBus.Properties", "GetAll", GLib.Variant("(s)", ("org.freedesktop.systemd1.Unit",)))[0]
        service = self.call(path, "org.freedesktop.DBus.Properties", "GetAll", GLib.Variant("(s)", ("org.freedesktop.systemd1.Service",)))[0]
        main_pid = service.get("MainPID", 0)
        unit["MainPID"] = main_pid
        snapshot = None
        if unit.get("ActiveState") == "active" and main_pid > 0:
            try:
                uid = os.stat(f"/proc/{main_pid}").st_uid
                snapshot = read_snapshot(STATUS_PATH, main_pid, expected_uid=uid)
            except (OSError, ValueError, KeyError, TypeError):
                pass
        return unit, snapshot

    def control(self, verb):
        method, args = control_request(verb)
        self.call("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", method, GLib.Variant("(ss)", args), interactive=True)
        return "Action requested; waiting for observed systemd and Engine state."


class Monitor(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.hostsguardian.Monitor")
        self.pool = ThreadPoolExecutor(max_workers=1)
        self.pending = False
        self.closed = False
        self.confirming = False
        self.client = None
        self.timer = None
        self.history = LiveHistory()
        self.connect("activate", self.activate_window)
        self.connect("shutdown", self.shutdown_monitor)

    def activate_window(self, app):
        if self.get_active_window():
            self.get_active_window().present()
            return
        self.window = Gtk.ApplicationWindow(application=self, title="HostsGuardian Monitor")
        self.window.set_default_size(1100, 850)
        self.window.connect("close-request", self.close_window)
        css = Gtk.CssProvider()
        css.load_from_data(b"""
            window { background: #0b1116; color: #dce8e7; }
            .brand { color: #6fe5a5; font-size: 14px; font-weight: 800; letter-spacing: 2px; }
            .heading { font-size: 25px; font-weight: 700; }
            .card { background: #121e25; border: 1px solid #23333c; border-radius: 16px; padding: 20px; }
            .caption { color: #8cabae; font-size: 12px; font-weight: 600; }
            .metric { font-size: 36px; font-weight: 700; color: #f0faf6; }
            .muted { color: #91a6ad; }
            .healthy { color: #6fe5a5; }
            .degraded { color: #ffc878; }
            .critical { color: #ff7d83; font-weight: 800; }
            button { background: #17262c; color: #dce8e7; border-color: #30424a; }
            textview, textview text { background: #121e25; color: #adc3ca; }
        """)
        Gtk.StyleContext.add_provider_for_display(self.window.get_display(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        layout = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        for name in ("top", "bottom", "start", "end"):
            getattr(layout, "set_margin_" + name)(24)
        layout.append(self.label("HOSTSGUARDIAN   /   LINUX MONITOR", "brand"))
        layout.append(self.label("HostsGuardian Monitor", "heading"))
        self.summary = self.label("Connecting to local Engine…", "muted")
        self.summary.set_wrap(True)
        layout.append(self.summary)
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_vexpand(True)
        switcher = Gtk.StackSwitcher(stack=self.stack, halign=Gtk.Align.START)
        layout.append(switcher)
        self.overview_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        hero.add_css_class("card")
        hero.append(self.label("ENGINE / LOCAL OPERATIONS", "caption"))
        self.engine_label = self.label("Unknown", "metric")
        self.identity_label = self.label("PID — · Uptime — · Engine —", "muted")
        self.identity_label.set_wrap(True)
        hero.append(self.engine_label); hero.append(self.identity_label)
        buttons = Gtk.Box(spacing=8); self.buttons = []
        for label, verb in (("Start Engine", "start"), ("Stop Engine", "stop"), ("Restart Engine", "restart")):
            button = Gtk.Button(label=label)
            button.connect("clicked", lambda _button, operation=verb: self.confirm(operation))
            buttons.append(button); self.buttons.append(button)
        hero.append(buttons)
        self.overview_page.append(hero)
        overview_grid = Gtk.Grid(column_spacing=16, row_spacing=16, column_homogeneous=True)
        self.overview_labels = {}
        for i, (key, title) in enumerate((("dns", "DNS LISTENERS / HEALTH"), ("api", "MANAGEMENT API"),
                                         ("upstream", "UPSTREAM EVIDENCE"), ("policy", "POLICY / PERSISTENCE"))):
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            box.add_css_class("card"); box.append(self.label(title, "caption"))
            value = self.label("Unknown", "muted"); value.set_wrap(True)
            box.append(value); self.overview_labels[key] = value
            overview_grid.attach(box, i % 2, i // 2, 1, 1)
        self.overview_page.append(overview_grid)
        self.evidence_label = self.label("Awaiting fresh Engine evidence", "muted")
        self.evidence_label.set_wrap(True); self.overview_page.append(self.evidence_label)
        self.overview_page.append(self.label("Engine runs independently under systemd. Policy decisions remain in the Windows Control Center.", "caption"))
        self.stack.add_titled(self.overview_page, "overview", "Overview")
        self.diagnostics_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.grid = Gtk.Grid(column_spacing=16, row_spacing=16, column_homogeneous=True, row_homogeneous=True)
        self.grid.set_vexpand(True)
        activity = self.card("DNS ACTIVITY", 0, 0)
        self.rate_label = self.label("— queries / s", "metric")
        self.peak_label = self.label("Waiting for two samples", "muted")
        activity.append(self.rate_label); activity.append(self.peak_label)
        self.activity_graph = self.graph(False); activity.append(self.activity_graph)
        latency = self.card("UPSTREAM LATENCY", 1, 0)
        self.latency_label = self.label("— ms", "metric")
        self.percentiles = self.label("P50 —    P95 —  •  successful resolver attempts", "muted")
        latency.append(self.latency_label); latency.append(self.percentiles)
        self.latency_graph = self.graph(True); latency.append(self.latency_graph)
        results = self.card("DNS RESULTS", 0, 1)
        self.result_labels = {}
        for field, title in (("allowed", "Allowed / forwarded"), ("policyBlocked", "Policy blocked"), ("failed", "Failed / SERVFAIL"), ("rejected", "Dropped / rejected")):
            row = Gtk.Box(spacing=8)
            row.append(self.label(title, "healthy" if field == "policyBlocked" else "muted"))
            value = Gtk.Label(label="—", xalign=1, hexpand=True)
            row.append(value); results.append(row); self.result_labels[field] = value
        self.result_note = self.label("Since Engine start. Policy blocks are successful filtering.", "caption")
        self.result_note.set_wrap(True); results.append(self.result_note)
        pressure = self.card("ENGINE PRESSURE / HEALTH", 1, 1)
        self.health_label = self.label("UNKNOWN", "metric")
        self.pressure_label = self.label("Capacity evidence unavailable", "muted")
        self.resource_label = self.label("CPU —   RAM —   Uptime —", "muted")
        self.component_label = self.label("", "caption"); self.component_label.set_wrap(True)
        for widget in (self.health_label, self.pressure_label, self.resource_label, self.component_label): pressure.append(widget)
        self.diagnostics_page.append(self.grid)
        self.stack.add_titled(self.diagnostics_page, "diagnostics", "Diagnostics")
        incidents = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.incident_note = self.label("Awaiting fresh incident evidence", "muted")
        self.incident_note.set_wrap(True); incidents.append(self.incident_note)
        self.incident_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        incidents.append(self.incident_box)
        log_expander = Gtk.Expander(label="Recent operational messages · up to 64")
        self.events = Gtk.TextView(editable=False, cursor_visible=False)
        self.events.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        log_scroll = Gtk.ScrolledWindow(min_content_height=180); log_scroll.set_child(self.events)
        log_expander.set_child(log_scroll); incidents.append(log_expander)
        self.stack.add_titled(incidents, "incidents", "Events / Incidents")
        details_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        details_page.append(self.label("Engine-owned technical evidence · read only", "muted"))
        self.details_expander = Gtk.Expander(label="Listeners, runtime identity, counters and capacity")
        self.details = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
        self.details.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        detail_scroll = Gtk.ScrolledWindow(min_content_height=480); detail_scroll.set_child(self.details)
        self.details_expander.set_child(detail_scroll); details_page.append(self.details_expander)
        self.stack.add_titled(details_page, "details", "Details")
        layout.append(self.stack)
        self.notice = self.label("Engine service continues when this window closes.", "muted")
        layout.append(self.notice)
        outer = Gtk.ScrolledWindow(); outer.set_child(layout)
        self.window.set_child(outer); self.window.present()
        self.timer = GLib.timeout_add(1000, self.poll)
        self.poll()

    @staticmethod
    def label(text, style=None):
        widget = Gtk.Label(label=text, xalign=0)
        if style: widget.add_css_class(style)
        return widget

    def card(self, title, column, row):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.add_css_class("card"); box.append(self.label(title, "caption"))
        self.grid.attach(box, column, row, 1, 1)
        return box

    def graph(self, latency):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True, vexpand=True)
        chart = Gtk.Box(spacing=8, hexpand=True, vexpand=True)
        axes = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        upper = self.label("100" if latency else "10", "caption")
        axes.append(upper); axes.append(Gtk.Box(vexpand=True)); axes.append(self.label("0", "caption"))
        chart.append(axes)
        canvas = GraphCanvas(lambda snap, w, h: self.draw_graph(snap, w, h, latency))
        chart.append(canvas); box.append(chart)
        footer = Gtk.Box(spacing=8)
        footer.append(self.label("−10 min", "caption"))
        if latency:
            legend = Gtk.Label(label="P50  /  P95", hexpand=True); legend.add_css_class("caption"); footer.append(legend)
        footer.append(Gtk.Label(label="now", xalign=1, hexpand=True)); box.append(footer)
        box.canvas = canvas; box.upper = upper; box.latency = latency
        return box

    @staticmethod
    def color(text):
        value = Gdk.RGBA(); value.parse(text); return value

    @staticmethod
    def rectangle(x, y, w, h):
        rect = Graphene.Rect(); rect.init(x, y, max(0, w), max(0, h)); return rect

    def draw_graph(self, snapshot, width, height, latency):
        samples = list(self.history.samples)
        series = (2, 3) if latency else (1,)
        ceiling = graph_scale([s[i] for s in samples for i in series], 100 if latency else 10)
        top, bottom = 3, height - 3
        plot_height = max(1, bottom - top)
        for fraction in (0, .5, 1):
            y = bottom - fraction * plot_height
            snapshot.append_color(self.color("#2b3d47"), self.rectangle(0, y, width, 1))
        now = self.history.clock()
        for index, color in zip(series, ("#6be0a8", "#61b3f5")):
            previous = None
            native_color = self.color(color)
            for sample in samples:
                x = (1 - (now - sample[0]) / WINDOW_SECONDS) * width
                value = sample[index]
                if value is None or x < 0:
                    previous = None; continue
                y = bottom - min(value / ceiling, 1) * plot_height
                if previous is not None and sample[0] - previous[2] <= 5:
                    dx, dy = x - previous[0], y - previous[1]
                    point = Graphene.Point(); point.init(previous[0], previous[1])
                    snapshot.save(); snapshot.translate(point)
                    snapshot.rotate(math.degrees(math.atan2(dy, dx)))
                    snapshot.append_color(native_color, self.rectangle(0, -1, math.hypot(dx, dy), 2))
                    snapshot.restore()
                previous = (x, y, sample[0])

    @staticmethod
    def number(value, suffix=""):
        return "—" if value is None else f"{value:,.1f}{suffix}"

    def render_diagnostics(self):
        value = self.history.current
        if value is None:
            self.rate_label.set_text("— queries / s"); self.latency_label.set_text("— ms")
            self.percentiles.set_text("Upstream latency unavailable")
            self.health_label.set_text("UNKNOWN"); self.pressure_label.set_text(self.history.message)
            self.resource_label.set_text("CPU —   RAM —   Uptime —"); self.component_label.set_text("")
            self.peak_label.set_text("No fresh diagnostic evidence")
            for widget in self.result_labels.values(): widget.set_text("—")
        else:
            self.rate_label.set_text(self.number(self.history.rate) + " queries / s")
            self.peak_label.set_text(f"Recent peak {self.history.peak:,.1f} / s  •  10 minute window")
            latency = value["upstreamLatency"]
            self.latency_label.set_text(self.number(latency["recentMs"], " ms"))
            self.percentiles.set_text("P50 " + self.number(latency["p50Ms"], " ms") + "    P95 " + self.number(latency["p95Ms"], " ms"))
            if latency["samples"] == 0: self.percentiles.set_text("No successful upstream samples in the last 60 s")
            counts = value["counters"]
            total = sum(counts[k] for k in self.result_labels)
            for field, widget in self.result_labels.items():
                count = counts[field]; widget.set_text(f"{count:,}   {count / total * 100 if total else 0:.1f}%")
            pressure = value["pressure"]; resources = value["resources"]
            self.health_label.set_text(value["health"].upper())
            self.pressure_label.set_text(f"UDP requests {pressure['udpCurrent']} / {pressure['udpCapacity']}    TCP connections {pressure['tcpConnections']} / {pressure['tcpConnectionCapacity']}")
            self.resource_label.set_text("CPU " + self.number(resources["cpuPercent"], "%") + "   RAM " + self.number(None if resources["workingSetBytes"] is None else resources["workingSetBytes"] / 1048576, " MiB") + f"   Uptime {resources['uptimeSeconds'] / 3600:.1f} h")
            self.component_label.set_text("  ·  ".join(f"{c['component']}: {c['state']}" for c in value["components"]))
        for style in ("healthy", "degraded", "critical"): self.health_label.remove_css_class(style)
        if value: self.health_label.add_css_class(value["health"].lower())
        for graph in (self.activity_graph, self.latency_graph):
            indices = (2, 3) if graph.latency else (1,)
            ceiling = graph_scale([s[i] for s in self.history.samples for i in indices], 100 if graph.latency else 10)
            graph.upper.set_text(f"{ceiling:g}" + (" ms" if graph.latency else " / s"))
            graph.canvas.queue_draw()

    def run_worker(self, action, completed):
        if self.pending or self.closed:
            return
        self.pending = True
        for button in self.buttons:
            button.set_sensitive(False)
        def work():
            try:
                if self.client is None:
                    self.client = SystemdClient()
                result, error = action(), None
            except Exception:
                result, error = None, "Local service operation unavailable or authorization refused."
            GLib.idle_add(finish, result, error)
        def finish(result, error):
            if self.closed:
                return False
            self.pending = False
            for button in self.buttons:
                button.set_sensitive(True)
            completed(result, error)
            return False
        self.pool.submit(work)

    def poll(self):
        self.run_worker(lambda: self.client.status(), self.show_status)
        return not self.closed

    def show_status(self, result, error):
        unit, snapshot = ({}, None) if error else result
        if snapshot is not None and snapshot.get("diagnostics") and snapshot["diagnostics"].get("resources", {}).get("processId") == unit.get("MainPID"):
            self.history.accept(snapshot["diagnostics"])
        else:
            self.history.missing("Missing, stale or unavailable Engine diagnostics")
        diagnostic = self.history.current
        try:
            view = overview(unit, snapshot, diagnostic)
            self.summary.set_text(f"Engine: {view['engine']} · Health: {view['health']}")
            self.engine_label.set_text(view["engine"])
            self.identity_label.set_text(view["identity"])
            for key, widget in self.overview_labels.items(): widget.set_text(view[key])
            self.evidence_label.set_text(view["evidence"])
            for style in ("healthy", "degraded", "critical"): self.engine_label.remove_css_class(style)
            if view["engine"] == "Running": self.engine_label.add_css_class("healthy")
            elif view["engine"] == "Failed": self.engine_label.add_css_class("critical")
            self.details.get_buffer().set_text(details_text(unit, snapshot, diagnostic))
            note, rows = incident_rows(snapshot, diagnostic)
            self.incident_note.set_text(note)
            child = self.incident_box.get_first_child()
            while child:
                following = child.get_next_sibling(); self.incident_box.remove(child); child = following
            if not rows:
                self.incident_box.append(self.label("No incident entries available" if diagnostic else "Incident state unknown", "muted"))
            for kind, title, evidence in rows:
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8); box.add_css_class("card")
                style = "critical" if kind == "Critical" else "healthy" if kind == "Recovery" else "degraded"
                box.append(self.label(title, style))
                label = self.label(evidence, "muted"); label.set_wrap(True); box.append(label)
                self.incident_box.append(box)
            lines = [] if snapshot is None else [f"{event.get('atUtc', '?')} [{event['level']}] {event['component']}: {event['message']}" for event in snapshot["events"]]
            self.events.get_buffer().set_text("\n".join(lines))
        except (ValueError, KeyError, TypeError, OverflowError):
            self.history.missing("Invalid local Engine evidence")
            self.summary.set_text("Engine evidence unavailable")
            self.engine_label.set_text("Unknown"); self.identity_label.set_text("Runtime evidence unavailable")
            for widget in self.overview_labels.values(): widget.set_text("Unknown")
            self.evidence_label.set_text("Invalid local Engine evidence")
            self.events.get_buffer().set_text(""); self.details.get_buffer().set_text("")
            self.incident_note.set_text("Incident state unknown")
            child = self.incident_box.get_first_child()
            while child:
                following = child.get_next_sibling(); self.incident_box.remove(child); child = following
        self.render_diagnostics()

    def confirm(self, verb):
        if self.pending or self.closed or self.confirming:
            return
        title, explanation = confirmation_text(verb)
        dialog = Gtk.MessageDialog(application=self, transient_for=self.window, modal=True,
                                   message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.YES_NO,
                                   text=title, secondary_text=explanation)
        def response(box, answer):
            box.destroy()
            self.confirming = False
            if answer == Gtk.ResponseType.YES and not self.closed:
                self.run_worker(lambda: self.client.control(verb), self.control_finished)
        self.confirming = True
        dialog.connect("response", response)
        dialog.present()

    def control_finished(self, result, error):
        self.notice.set_text(error or result)
        self.poll()

    def close_window(self, _window):
        self.shutdown_monitor(self)
        for window in list(self.get_windows()):
            if window is not self.window: window.destroy()
        return False

    def shutdown_monitor(self, _app):
        if self.closed:
            return
        self.closed = True
        if self.timer:
            GLib.source_remove(self.timer)
            self.timer = None
        self.pool.shutdown(wait=False, cancel_futures=True)
        # No StopUnit, signal, child Engine, bearer credential or policy mutation.


if __name__ == "__main__":
    if os.geteuid() == 0:
        raise SystemExit("The monitor must run as a graphical-session user, never root.")
    Monitor().run(sys.argv)
