"""Compact, selectable read-only device diagnostics. No identity or policy writes."""
from datetime import datetime, timezone
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Graphene","1.0")
from gi.repository import Gtk, GLib, Gdk, Graphene
from device_diagnostics import stamp
from device_types import for_row, label as type_label
import math

class DeviceTypeIcon(Gtk.Widget):
    def __init__(self,assessment):
        super().__init__();self.definition=assessment["type"];self.icon_key=self.definition["iconKey"];self.set_size_request(28,28)
        self.set_valign(Gtk.Align.START);self.set_tooltip_text(type_label(assessment))
    def do_snapshot(self,snapshot):
        color=Gdk.RGBA();color.parse("#6fe5a5");scale=min(self.get_width(),self.get_height())/24
        for stroke in self.definition["strokes"]:
            for (x,y),(end_x,end_y) in zip(stroke,stroke[1:]):
                dx=(end_x-x)*scale;dy=(end_y-y)*scale
                snapshot.save();point=Graphene.Point();point.init(x*scale,y*scale);snapshot.translate(point)
                snapshot.rotate(math.degrees(math.atan2(dy,dx)))
                rect=Graphene.Rect();rect.init(0,-.9*scale,math.hypot(dx,dy),1.8*scale);snapshot.append_color(color,rect);snapshot.restore()


def display_time(value):
    return stamp(value).astimezone().strftime('%H:%M:%S') if value else 'Not observed'


def identity_label(row):
    name={'UNKNOWN':'Name unknown','OBSERVED':'Observed name','INFERRED':'Suggested name','USER-CONFIRMED':'Confirmed name'}[row['nameEvidence']]
    identity='Identity unknown' if row['identityState']=='Unknown' else 'Identity: '+row['identityState']
    return identity+' · '+name


def observation(row, now):
    value=row.get('lastDnsActivityUtc')
    if value and 0 <= (now-stamp(value)).total_seconds() <= 60:
        return 'DNS observed recently'
    return 'No recent DNS observed'


class DeviceDiagnosticsView(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_vexpand(True)
        self.selected_tracking=None; self.rows={};self.rendering=False;self.last_signature=None
        self.summary=Gtk.Label(xalign=0,wrap=True)
        self.append(self.summary)
        panes=Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        panes.set_wide_handle(True);panes.set_position(330);panes.set_vexpand(True);self.append(panes);self.panes=panes
        self.list=Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.list.add_css_class("device-list");self.list.connect('row-selected',self.on_selected)
        scroll=Gtk.ScrolledWindow(min_content_height=300,vexpand=True)
        scroll.set_policy(Gtk.PolicyType.NEVER,Gtk.PolicyType.ALWAYS)
        scroll.set_child(self.list);scroll.set_size_request(280,-1);panes.set_start_child(scroll);self.scroll=scroll
        detail=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=8)
        self.detail_title=Gtk.Label(label='Select a device to inspect its evidence',xalign=0,wrap=True)
        self.detail_title.add_css_class('device-name');detail.append(self.detail_title)
        self.detail_grid=Gtk.Grid(column_spacing=12,row_spacing=4);detail.append(self.detail_grid)
        self.technical=Gtk.Expander(label='Evidence and technical caveats')
        self.technical_text=Gtk.Label(xalign=0,wrap=True,selectable=True)
        self.technical.set_child(self.technical_text);detail.append(self.technical)
        detail_scroll=Gtk.ScrolledWindow(min_content_height=300,vexpand=True)
        detail_scroll.set_policy(Gtk.PolicyType.NEVER,Gtk.PolicyType.ALWAYS);detail_scroll.set_child(detail)
        panes.set_end_child(detail_scroll);self.detail_scroll=detail_scroll

    @staticmethod
    def clear(container):
        child=container.get_first_child()
        while child:
            following=child.get_next_sibling();container.remove(child);child=following

    def render(self,model):
        now=datetime.now(timezone.utc)
        signature=(model.message if not model.rows else '',tuple((row['trackingId'],row['name'],row['identityState'],row['nameEvidence'],row.get('deviceType',''),row['lastObservedAddress'],row['deviceId'],row['lastSeenUtc'],row['lastDnsActivityUtc'],row['rate'],row['share'],row['highContribution'],tuple(sorted(row['window'].items())),tuple((row.get('networkEvidence') or {}).get(key,'') for key in ('mac','hostname','provenance')),repr(row.get('lanObservation')),observation(row,now)) for row in model.rows))
        if signature==self.last_signature:return
        self.last_signature=signature
        position=self.scroll.get_vadjustment().get_value()
        had_focus=self.list.get_focus_child() is not None
        self.rendering=True
        self.rows={row['trackingId']:row for row in model.rows}
        self.summary.set_text(f'{len(model.rows)} device/source rows · most active first · scroll the left list to see all sources' if model.rows else 'No attributable device evidence available')
        self.summary.set_tooltip_text(model.message)
        self.clear(self.list)
        selected=None;now=datetime.now(timezone.utc)
        for index,row in enumerate(model.rows):
            widget=Gtk.ListBoxRow();widget.tracking=row['trackingId']
            box=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=3);box.set_margin_top(6);box.set_margin_bottom(6)
            assessment=for_row(row)
            title_text=row['name'] if row['nameEvidence'] in ('USER-CONFIRMED','OBSERVED') else 'Likely '+assessment['type']['label'] if assessment['source']=='INFERRED' else row['name']
            title=Gtk.Label(label=title_text,xalign=0,wrap=True);title.add_css_class('device-name');box.append(title)
            hint=Gtk.Label(label=type_label(assessment),xalign=0,wrap=True);hint.add_css_class('muted');box.append(hint)
            counts=row['window'];lan=row.get('lanObservation')
            address=row['lastObservedAddress'] or 'Address unknown'
            subtitle=Gtk.Label(label=address,xalign=0,wrap=True);subtitle.add_css_class('muted');box.append(subtitle)
            state='Presence observed' if lan else 'Presence unknown'
            activity=f"{counts['received']} DNS · {counts['policyBlocked']} blocked · {counts['failed']} failed" if counts['received'] else 'DNS not observed'
            text=Gtk.Label(label=state+' · '+activity,xalign=0,wrap=True)
            text.add_css_class('warning' if counts['failed'] else 'muted');box.append(text)
            content=Gtk.Box(spacing=8);content.append(DeviceTypeIcon(assessment));content.append(box);box.set_hexpand(True)
            widget.set_child(content);self.list.append(widget)
            if row['trackingId']==self.selected_tracking:selected=widget
        self.rendering=False
        if selected is None:selected=self.list.get_row_at_index(0)
        self.list.select_row(selected)
        def restore_scroll():
            adjustment=self.scroll.get_vadjustment()
            adjustment.set_value(min(position,max(0,adjustment.get_upper()-adjustment.get_page_size())))
            return False
        GLib.idle_add(restore_scroll)
        if selected:
            self.show_detail(self.rows[selected.tracking])
            if had_focus:selected.grab_focus()
        else:
            self.selected_tracking=None;self.clear(self.detail_grid);self.detail_title.set_text('No device selected')
            self.technical_text.set_text(model.message);self.technical.set_expanded(False)

    def on_selected(self,_list,widget):
        if not self.rendering and widget:self.show_detail(self.rows[widget.tracking])

    def show_detail(self,row):
        self.selected_tracking=row['trackingId'];self.detail_title.set_text(row['name']+' · '+(row['lastObservedAddress'] or 'Unknown address'))
        self.clear(self.detail_grid)
        network=row.get('networkEvidence') or {};counts=row['window']
        lan=row.get('lanObservation');identity=(lan or {}).get('identity') or {}
        assessment=for_row(row)
        evidence=(lan or {}).get('evidence') or ([network] if network else [])
        addresses=list(dict.fromkeys(e['address'] for e in evidence))
        ipv4=' · '.join(a for a in addresses if ':' not in a) or 'Not observed'
        ipv6=' · '.join(a for a in addresses if ':' in a) or 'Not observed'
        cached=any(e.get('neighborState')=='STALE' for e in evidence)
        presence=('Observed (cached neighbour evidence)' if cached else 'Observed network evidence') if lan else 'Independent presence unknown'
        values=[('IDENTITY',identity_label(row)),('Device type',type_label(assessment)),('Friendly name',identity.get('friendlyName') or (row['name'] if row['nameEvidence']=='USER-CONFIRMED' else 'Not assigned')),
                ('Observed hostname',identity.get('observedHostname') or network.get('hostname') or 'Not observed'),
                ('Groups',', '.join(identity.get('groups',[])) or 'None confirmed'),
                ('PRESENCE',presence),('Last observed',display_time(row['lastSeenUtc'])),
                ('Evidence read',display_time(network.get('readAtUtc'))),('Last confirmation',display_time(network.get('confirmedAtUtc'))),
                ('NETWORK · IPv4',ipv4),('IPv6',ipv6),('MAC evidence',' · '.join(dict.fromkeys(e.get('mac','') for e in evidence if e.get('mac'))) or 'Not observed'),
                ('DNS ACTIVITY',(lan or {}).get('dnsActivity','OBSERVED' if counts['received'] else 'NOT OBSERVED')),
                ('Last DNS',display_time(row.get('lastDnsActivityUtc'))),
                ('DNS attribution',str(row.get('dnsAttribution',{}).get('state','UNKNOWN'))+' - attributed '+str(row.get('dnsAttribution',{}).get('attributed',0))+' - unresolved '+str(row.get('dnsAttribution',{}).get('unresolved',0))),
                ('Allowed / blocked',f"{counts['allowed']} / {counts['policyBlocked']}"),
                ('Failed / dropped',f"{counts['failed']} / {counts['rejected']}"),
                ('DNS COVERAGE',(lan or {}).get('coverage','UNKNOWN')),
                ('Resolver path',(lan or {}).get('resolverPath','UNKNOWN')),
                ('Why',(lan or {}).get('explanation','DNS observations do not prove exclusive coverage.'))]
        for index,(key,value) in enumerate(values):
            label=Gtk.Label(label=key,xalign=0);label.add_css_class('caption' if key.isupper() else 'muted')
            content=Gtk.Label(label=value,xalign=0,wrap=True,selectable=True);content.set_hexpand(True)
            self.detail_grid.attach(label,0,index,1,1);self.detail_grid.attach(content,1,index,1,1)
        notes=["Type provenance: "+assessment["provenance"],"Semantic icon: "+assessment["type"]["iconKey"],"First observed: "+row['firstSeenUtc'],"Last observed: "+row['lastSeenUtc'],
               'Identity evidence: '+(network.get('provenance') or 'No network identity evidence'),
               'Cache presence and recent DNS do not prove that a device is currently online.',
               'Unknown source addresses are not stable DeviceIds. Missing DNS does not prove inactivity.',
               'Management, aliases and policy remain in WPF; this view is read-only.',
               f"Rejected TCP connections: {counts['tcpConnectionsRejected']} (connections, not DNS queries)."]
        if identity:notes += ['Registration DeviceId: '+str(identity.get('deviceId') or 'Unassigned'), 'Identity association: '+identity.get('provenance','Unknown'), 'Private MAC possible: '+str(identity.get('privateMacPossible',False))]
        if lan:
            notes += ['Fingerprint evidence: '+e['provider']+' · '+e['kind']+': '+e['value'] for e in (lan.get('classification') or {}).get('evidence',[])]
            notes += [lan['explanation'],'Observation ID: '+lan['observationDeviceId']+' · '+lan['stability'],'Evidence entries omitted by payload limit: '+str(lan.get('evidenceOmitted',0))]
            notes += [e['address']+' · '+(e['mac'] or 'MAC unknown')+' · '+e['provenance']+' · private MAC possible: '+str(e.get('privateMacPossible',False)) for e in lan['evidence']]
        if row['share'] is not None:notes.append(f"Share of aggregate sample interval: {row['share']:.1f}%")
        if counts['failed']:notes.append('Observed failures are diagnostic context, not proof of an incident cause.')
        if row['highContribution']:notes.append('High relative contribution is inferred and informational, not a health fault.')
        self.technical_text.set_text('\n'.join(notes))
