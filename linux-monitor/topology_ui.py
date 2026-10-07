"""Read-only graphical topology with selectable evidence; no invented physical links."""
import math
from datetime import datetime,timezone
import gi
gi.require_version('Gtk','4.0')
try:
    gi.require_foreign('cairo')
    CAIRO_AVAILABLE = True
except ImportError:
    CAIRO_AVAILABLE = False
from gi.repository import Gtk
from topology import validate, positions
from device_types import find


class TopologyView(Gtk.Box):
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL,spacing=8)
        self.snapshot=None;self.selected=None;self.layout={};self.signature=None
        self.note=Gtk.Label(label='Topology unavailable from this Engine',xalign=0,wrap=True);self.append(self.note)
        controls=Gtk.Box(spacing=12)
        self.layer=Gtk.DropDown.new_from_strings(['Access evidence','DNS / HostsGuardian','All evidence'])
        self.layer.connect('notify::selected',lambda *_:self.canvas.queue_draw());controls.append(self.layer)
        controls.append(Gtk.Label(label='Solid: observed/proven   Dashed: inferred   Dotted: unknown; no line means no relationship evidence',wrap=True));self.append(controls)
        self.panes=Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL);self.panes.set_position(760);self.append(self.panes);self.panes.set_vexpand(True)
        self.canvas=Gtk.DrawingArea()
        if CAIRO_AVAILABLE:self.canvas.set_draw_func(self.draw)
        else:
            self.append(Gtk.Label(label='Topology graph unavailable: install the reviewed python3-gi-cairo prerequisite. Device list/details remain available.',wrap=True,xalign=0))
        click=Gtk.GestureClick();click.connect('pressed',self.click);self.canvas.add_controller(click)
        scroll=Gtk.ScrolledWindow(hexpand=True,vexpand=True);scroll.set_child(self.canvas);self.panes.set_start_child(scroll)
        right=Gtk.Box(orientation=Gtk.Orientation.VERTICAL,spacing=8)
        right.append(Gtk.Label(label='Select a node - WHO / PRESENCE / ACCESS / DNS / BINDING / WHY',wrap=True))
        self.list=Gtk.ListBox();self.list.connect('row-selected',self.select_row)
        list_scroll=Gtk.ScrolledWindow(min_content_height=150);list_scroll.set_child(self.list);right.append(list_scroll)
        self.details=Gtk.Label(xalign=0,yalign=0,wrap=True,selectable=True)
        detail_scroll=Gtk.ScrolledWindow(hexpand=True,vexpand=True);detail_scroll.set_child(self.details);right.append(detail_scroll)
        self.panes.set_end_child(right)

    def render(self,value):
        try:value=validate(value)
        except (ValueError,KeyError,TypeError,AttributeError,OverflowError):value=None
        # Snapshot timestamps alone do not rebuild an unchanged graph.
        signature=repr([{k:v for k,v in n.items() if k!='evidence'} for n in (value or {}).get('nodes',[])])+repr([{k:v for k,v in e.items() if k!='observedAtUtc'} for e in (value or {}).get('links',[])])
        self.snapshot=value
        if value is None:
            self.note.set_text('Topology unavailable or expired; no relationships assumed')
        else:
            counts={kind:sum(n['kind']==kind for n in value['nodes']) for kind in ('Registered','Provisional')}
            self.note.set_text(f"Registered nodes {counts['Registered']} - provisional observations {counts['Provisional']} - omitted nodes {value['omittedNodes']}. Access technology remains unknown without infrastructure evidence.")
        if signature==self.signature:
            self.show_details();return
        self.signature=signature;nodes=(value or {}).get('nodes',[]);self.layout=positions(nodes)
        if self.selected not in self.layout:self.selected=nodes[0]['id'] if nodes else None
        child=self.list.get_first_child()
        while child:
            following=child.get_next_sibling();self.list.remove(child);child=following
        for node in sorted(nodes,key=lambda n:n['id']):
            row=Gtk.ListBoxRow();row.node_id=node['id'];row.set_child(Gtk.Label(label=node['name']+' - '+node['presence'],xalign=0,wrap=True));self.list.append(row)
            if node['id']==self.selected:self.list.select_row(row)
        self.canvas.set_content_width(1000);self.canvas.set_content_height(max(420,math.ceil(len(nodes)/4)*175+50));self.canvas.queue_draw();self.show_details()

    def validator_health(self,value):
        if not hasattr(self,'validator_note'):
            self.validator_note=Gtk.Label(xalign=0,wrap=True);self.prepend(self.validator_note)
        if not isinstance(value,dict):
            self.validator_note.set_text('Active validator: not configured / no current health evidence');return
        try:
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(value['checkedAtUtc'].replace('Z','+00:00'))).total_seconds()
            if not 0<=age<10:raise ValueError('Stale validator health')
        except (ValueError,KeyError,TypeError,AttributeError):
            self.validator_note.set_text('Active validator: UNKNOWN - health evidence missing or stale; DNS remains independent.');return
        state=value.get('state','UNKNOWN');reason=value.get('reason','Unknown')
        self.validator_note.set_text('Active validator: '+str(state)[:32]+' - '+str(reason)[:200]+'. DNS remains independent; missing validation does not establish identity.')

    def select_row(self,box,row):
        if row:self.selected=row.node_id;self.show_details();self.canvas.queue_draw()

    def click(self,gesture,count,x,y):
        for node,(left,top) in self.layout.items():
            if left<=x<=left+210 and top<=y<=top+145:
                self.selected=node;self.show_details();self.canvas.queue_draw();break

    def show_details(self):
        node=next((n for n in (self.snapshot or {}).get('nodes',[]) if n['id']==self.selected),None)
        if not node:self.details.set_text('No current topology evidence');return
        lines=[node['name'],f"Identity: {node['kind']} - DeviceId {node['deviceId'] or 'Unknown'}",f"Type: {node['deviceType'] or 'Unknown'}",f"Presence: {node['presence']}",f"Access: {node['access']}",
               'IP: '+(' / '.join(node['addresses']) or 'Not currently correlated'),'MAC evidence: '+(' / '.join(node['macs']) or 'Unknown'),
               f"DNS activity: {node['dnsActivity']} - coverage {node['coverage']}",f"Binding: {node['binding']}",f"Policy identity: {node['policyIdentity']}",'WHY / EVIDENCE']
        for e in node['evidence']:lines += [e['confidence']+' - '+e['provider'],e['explanation'],'Observed: '+str(e['observedAtUtc'])+'; read: '+str(e['readAtUtc'])+'; confirmed: '+str(e['confirmedAtUtc'])]
        for edge in self.snapshot['links']:
            if node['id'] in (edge['from'],edge['to']):lines += [edge['relationship']+' - '+edge['confidence'],edge['explanation']]
        lines+=['Available network evidence (not membership of this device): '+', '.join(n['name']+' ('+n['membershipConfidence']+')' for n in self.snapshot['networks']),
                'Network membership is not a policy group. Missing observation is not proof of offline state.']
        self.details.set_text('\n\n'.join(lines))

    def draw(self,area,cr,width,height):
        cr.set_source_rgb(.06,.09,.08);cr.paint()
        if not self.snapshot:return
        layer=self.layer.get_selected()
        for edge in self.snapshot['links']:
            dns='DNS' in edge['relationship']
            if layer==0 and dns or layer==1 and not dns:continue
            x,y=self.layout[edge['from']];tx,ty=self.layout[edge['to']]
            cr.set_source_rgb(.45,.65,.55);cr.set_line_width(2);cr.set_dash([7,5] if edge['confidence']=='INFERRED' else [2,5] if edge['confidence']=='UNKNOWN' else [])
            cr.move_to(x+105,y+52);cr.line_to(tx+105,ty+52);cr.stroke()
        cr.set_dash([])
        for node in self.snapshot['nodes']:
            x,y=self.layout[node['id']];cr.set_source_rgb(.12,.24,.18);cr.rectangle(x,y,210,145);cr.fill_preserve()
            cr.set_source_rgb(.4,.9,.6 if node['id']==self.selected else .4);cr.set_line_width(3 if node['id']==self.selected else 1);cr.stroke()
            icon=find(node['deviceType']) or find('Unknown')
            cr.set_line_width(1.5)
            for stroke in icon['strokes']:
                cr.move_to(x+180+stroke[0][0],y+6+stroke[0][1])
                for px,py in stroke[1:]:cr.line_to(x+180+px,y+6+py)
                cr.stroke()
            cr.select_font_face('Sans');cr.set_font_size(13);cr.set_source_rgb(.9,.96,.92)
            # Shape + type text is accessible without color; full names remain in selected details/list.
            for i,text in enumerate([node['name'][:25],node['kind']+' / '+(node['deviceType'] or 'Unknown'),node['addresses'][0] if node['addresses'] else 'Address unknown',node['presence'],node['access']+' - '+node['binding'], 'Network: '+(next((n['name'] for n in self.snapshot['networks'] if n['id']==node.get('networkId')), 'Unknown'))]):
                cr.move_to(x+8,y+20+i*22);cr.show_text(text[:29])
