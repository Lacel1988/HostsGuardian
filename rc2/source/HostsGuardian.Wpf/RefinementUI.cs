using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Automation;
using System.Windows.Input;
using System.Windows.Media;
namespace DesignPrototype;

public sealed partial class PrototypeWindow
{
    public bool ActivityFiltersOpen {get;set;}
    public int InsightHours {get;set;}=6;
    public string InsightDevice {get;set;}="";
    public string PickerSearch {get;private set;}="";
    public HashSet<string> PickerSelection {get;}=new();
    public bool PickerGlobal {get;private set;}
    public string AnalystName=>Loc.Pick("AI biztonsági elemző","AI Security Analyst");
    public sealed class DeviceChoice
    {
        readonly DemoDevice device;readonly HashSet<string> selected;readonly Action changed;
        public DeviceChoice(DemoDevice d,HashSet<string> s,Action update){device=d;selected=s;changed=update;}
        public bool Selected {get=>selected.Contains(device.Id);set{if(value)selected.Add(device.Id);else selected.Remove(device.Id);changed();}}
        public string Name=>device.Name;public string Address=>device.Address;public string Identity=>device.Identity;public string LastSeen=>device.LastSeen;
    }
    public IReadOnlyList<DemoDevice> SearchPicker(string query)=>Store.Devices.Where(d=>(d.Name+" "+d.Address).Contains(query,StringComparison.OrdinalIgnoreCase)).ToArray();
    public void OpenPolicy(string? id)
    {if(EngineMode){Message(Loc.Pick("Csak olvasási mód: módosítás nem engedélyezett.","Read-only mode: changes are disabled."));return;}
        if(!EnsureSession()||!Store.CanManage(Account)){Message(Loc.T("A módosításhoz Kezelő vagy Adminisztrátor demófiók szükséges."));return;}
        var existing=id==null?null:Store.Policies.Single(p=>p.Id==id);
        if(Account.Role=="Kezelő"&&existing!=null&&(existing.Global||existing.Targets.Any(d=>d!="device-1"))){Message(Loc.Pick("A Kezelő demóhatásköre: FixtureAlpha készüléke.","Operator demo scope: FixtureAlpha's device."));return;}
        editingId=id;draft=existing?.Copy()??new(){Name=Loc.Pick("Új demószabály","New demo policy"),Target="example.invalid",Creator=Account.Name,DeviceId=Account.Role=="Kezelő"?"device-1":""};
        PickerSelection.Clear();PickerSelection.UnionWith(draft.Targets);PickerGlobal=draft.Global;PickerSearch="";
        TextBox name=Input(draft.Name,"PolicyName"),target=Input(draft.Target,"PolicyTarget"),days=Input(draft.Days,"PolicyDays"),start=Input(draft.Start,"PolicyStart"),end=Input(draft.End,"PolicyEnd"),notice=Input(draft.Notice.ToString(),"PolicyNotice");
        var content=Ui.Stack(Field("Név",name),Field("Domain vagy csoport",target),Check("Tiltás",draft.Block,v=>draft.Block=v,"PolicyBlock"));
        var summary=Ui.Text("",13,"#B6C6DA");var warning=Ui.Text("",13,"#FFD58A");
        void UpdateSelection(){summary.Text=Loc.Pick($"{PickerSelection.Count} kiválasztott eszköz",$"{PickerSelection.Count} selected devices");int uncertain=Store.Devices.Count(d=>PickerSelection.Contains(d.Id)&&!d.Certain);warning.Text=uncertain==0?"":Loc.Pick($"Figyelem: {uncertain} eszköz azonosítása következtetett; a hatókör nem igazolt védelem.",$"Caution: {uncertain} selected identities are inferred; scope is not verified protection.");}
        var search=Input("","DevicePickerSearch");var grid=new DataGrid{AutoGenerateColumns=false,IsReadOnly=false,Height=Compact?170:200,Margin=new Thickness(0,4,0,8)};
        AutomationProperties.SetAutomationId(grid,"DevicePickerGrid");
        grid.Columns.Add(new DataGridCheckBoxColumn{Header=Loc.Pick("Jelölés","Select"),Binding=new Binding(nameof(DeviceChoice.Selected)){Mode=BindingMode.TwoWay,UpdateSourceTrigger=UpdateSourceTrigger.PropertyChanged},Width=85});
        foreach(var c in new[]{("Név","Name",180),("IP-címek","Address",170),("Azonosítás","Identity",150),("Utolsó megfigyelés","LastSeen",175)})grid.Columns.Add(new DataGridTextColumn{Header=Loc.T(c.Item1),Binding=new Binding(c.Item2),Width=c.Item3,IsReadOnly=true,ElementStyle=(Style)Application.Current.FindResource("GridText")});
        void Filter(){PickerSearch=search.Text;grid.ItemsSource=SearchPicker(PickerSearch).Select(d=>new DeviceChoice(d,PickerSelection,UpdateSelection)).ToArray();}
        search.TextChanged+=(_,_)=>Filter();Filter();UpdateSelection();
        var picker=Ui.Stack(Field(Loc.Pick("Eszköz keresése név vagy IP-cím alapján","Find device by name or IP address"),search),summary,grid,warning);picker.IsEnabled=!PickerGlobal;
        content.Children.Add(Check(Loc.Pick("Globális szabály – minden ismert eszköz","Global rule – all known devices"),PickerGlobal,v=>{PickerGlobal=v;picker.IsEnabled=!v;},"PolicyGlobal"));content.Children.Add(Ui.Text(Loc.Pick("Kiválasztott eszközök","Selected devices"),15,bold:true));content.Children.Add(picker);
        content.Children.Add(Check("Időzített",draft.Scheduled,v=>draft.Scheduled=v,"PolicyScheduled"));
        days.ToolTip=Loc.Pick("0=vasárnap, 1=hétfő … 6=szombat. Lista és tartomány is írható: 1-3,5. A tartomány mindkét vége aktív.","0=Sunday, 1=Monday … 6=Saturday. Lists and inclusive ranges are supported: 1-3,5.");
        var times=new WrapPanel();foreach(var field in new[]{Field(Loc.Pick("Napok (0–6; pl. 1-3,5)","Days (0–6; e.g. 1-3,5)"),days),Field("Kezdés (HH:mm)",start),Field("Befejezés (HH:mm)",end),Field("Értesítés (perc)",notice)}){field.Width=175;times.Children.Add(field);}content.Children.Add(times);
        var error=Ui.Text("",14,"#FFD58A");content.Children.Add(error);
        content.Children.Add(Actions(("Hatáselőnézet",()=>
        {
            if(!PickerGlobal&&PickerSelection.Count==0){error.Text=Loc.Pick("Válassz legalább egy eszközt vagy globális hatókört.","Select at least one device or choose global scope.");return;}
            draft.Name=name.Text.Trim();draft.Target=target.Text.Trim();draft.DeviceId="";draft.DeviceIds=PickerGlobal?Array.Empty<string>():PickerSelection.Order().ToArray();draft.Days=days.Text.Trim();draft.Start=start.Text.Trim();draft.End=end.Text.Trim();
            if(!int.TryParse(notice.Text,out int minutes)){error.Text=Loc.Pick("Érvénytelen értesítési idő.","Invalid notification time.");return;}draft.Notice=minutes;
            var failure=Store.ValidatePolicy(draft);if(failure!=null){error.Text=failure;return;}ShowImpact(draft,editingId);
        },"PreviewPolicy")));
        Modal(Loc.Pick("Szabályszerkesztő • közös fixture","Policy editor • shared fixture"),content);
    }
    public IReadOnlyList<(DateTime Start,DateTime End,int Count)> InsightBins()
    {
        var end=Store.Clock.Date.AddHours(17);int size=InsightHours/6;
        return Enumerable.Range(0,6).Select(i=>{var begin=end.AddHours(-InsightHours+i*size);return (begin,begin.AddHours(size),Store.NetworkEvents.Count(e=>e.Time>=begin&&e.Time<begin.AddHours(size)&&(InsightDevice==""||e.Device==InsightDevice)));}).ToArray();
    }
    void InsightsPage()
    {
        var bins=InsightBins();int observed=bins.Sum(b=>b.Count);
        var overview=new WrapPanel();foreach(var (title,value) in new[]{(Loc.Pick("Megfigyelt események","Observed events"),observed.ToString()),(Loc.Pick("Vizsgálandó megállapítások","Findings to review"),"1 / fixture"),(Loc.Pick("Lefedettség / enforcement","Coverage / enforcement"),Loc.T("Nem igazolt"))})
        {var card=Ui.Card(Ui.Stack(Ui.Text(title,12,"#B6C6DA",true),Ui.Text(value,22,bold:true)));card.Width=Compact?245:285;card.Padding=new Thickness(14);card.Margin=new Thickness(0,0,12,10);overview.Children.Add(card);}page.Children.Add(overview);
        var controls=new Grid();foreach(var width in new[]{GridLength.Auto,new GridLength(16),new GridLength(1,GridUnitType.Star),new GridLength(10),GridLength.Auto})controls.ColumnDefinitions.Add(new(){Width=width});
        var periods=Actions(new[]{6,12,24}.Select(h=>(h+Loc.Pick(" óra"," hours"),(Action)(()=>{InsightHours=h;BuildPage();AnimatePage();}),"InsightPeriod"+h)).ToArray());foreach(Button button in periods.Children){button.Height=38;button.Margin=new Thickness(0,0,8,10);}
        controls.Children.Add(Ui.Stack(Ui.Text(Loc.Pick("Időszak","Period"),12,"#B6C6DA"),periods));
        var device=Input(InsightDevice==""?"":Store.Devices.First(d=>d.Id==InsightDevice).Name,"InsightDeviceSearch");device.Height=38;device.Margin=new Thickness(0,0,0,10);
        var deviceField=Ui.Stack(Ui.Text(Loc.Pick("Eszközszűrés név alapján (üres = összes)","Filter by device name (empty = all)"),12,"#B6C6DA"),device);Grid.SetColumn(deviceField,2);controls.Children.Add(deviceField);
        var filter=Ui.Button("Szűrés",()=>{var text=device.Text.Trim();var matches=SearchPicker(text);if(text.Length==0){InsightDevice="";}else if(matches.Count==1){InsightDevice=matches[0].Id;}else{Message(Loc.Pick("Adj meg egyértelmű eszköznevet vagy IP-címet.","Enter an unambiguous device name or IP address."));return;}BuildPage();},"InsightDeviceFilter");filter.Height=38;filter.VerticalAlignment=VerticalAlignment.Bottom;filter.Margin=new Thickness(0,0,0,10);Grid.SetColumn(filter,4);controls.Children.Add(filter);
        var chart=Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Mi történik a hálózatban?","What is happening on the network?"),19,bold:true),controls,
            Ui.Text(Loc.Pick($"STATIKUS FIXTURE • {bins[0].Start:yyyy-MM-dd HH:mm}–{bins[^1].End:HH:mm} • esemény / időablak",$"STATIC FIXTURE • {bins[0].Start:yyyy-MM-dd HH:mm}–{bins[^1].End:HH:mm} • events / interval"),12,"#B6C6DA"),BuildActivityChart(bins),
            Ui.Text(Loc.Pick("Forrás: a közös fixture domainnel rendelkező eseményei; fiókműveletek nélkül. Engine-ID nincs. Pillanatkép, nem élő adatfolyam.","Source: domain-bearing events from the shared fixture, excluding account actions. No Engine ID. Snapshot, not a live stream."),12,"#B6C6DA")));
        chart.Padding=new Thickness(14);page.Children.Add(chart);page.Children.Add(AnalystPanel());
    }
    FrameworkElement BuildActivityChart(IReadOnlyList<(DateTime Start,DateTime End,int Count)> bins)
    {
        int maximum=Math.Max(10,(int)Math.Ceiling(bins.Max(b=>b.Count)/10.0)*10);
        var grid=new Grid{Margin=new Thickness(0,8,0,8),Height=195};grid.ColumnDefinitions.Add(new(){Width=new GridLength(42)});for(int i=0;i<6;i++)grid.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});
        var scale=new Grid{Height=148,VerticalAlignment=VerticalAlignment.Top,Margin=new Thickness(0,20,0,0)};scale.Children.Add(Ui.Text(maximum.ToString(),11,"#B6C6DA"));var mid=Ui.Text((maximum/2).ToString(),11,"#B6C6DA");mid.VerticalAlignment=VerticalAlignment.Center;scale.Children.Add(mid);var zero=Ui.Text("0",11,"#B6C6DA");zero.VerticalAlignment=VerticalAlignment.Bottom;scale.Children.Add(zero);grid.Children.Add(scale);
        for(int i=0;i<bins.Count;i++)
        {
            var b=bins[i];var column=new Grid{Margin=new Thickness(4,0,4,0)};column.RowDefinitions.Add(new(){Height=new GridLength(20)});column.RowDefinitions.Add(new(){Height=new GridLength(148)});column.RowDefinitions.Add(new(){Height=new GridLength(27)});
            var value=Ui.Text(b.Count.ToString(),12,"#9AC5FF",true);value.TextAlignment=TextAlignment.Center;column.Children.Add(value);
            var bar=new Border{Height=b.Count/(double)maximum*142,Background=Ui.Brush("#9AC5FF"),CornerRadius=new CornerRadius(4,4,0,0),VerticalAlignment=VerticalAlignment.Bottom,Margin=new Thickness(8,0,8,0),Focusable=true,ToolTip=$"{b.Start:yyyy-MM-dd HH:mm}–{b.End:HH:mm}\n{b.Count} "+(EngineMode?Loc.Pick("esemény • API aggregátum","events • API aggregate"):Loc.Pick("esemény • statikus fixture","events • static fixture"))};
            column.ToolTip=bar.ToolTip;AutomationProperties.SetName(bar,(string)bar.ToolTip);AutomationProperties.SetAutomationId(bar,"ChartBar"+i);bar.GotKeyboardFocus+=(_,_)=>{bar.BorderBrush=Ui.Brush("#FFD58A");bar.BorderThickness=new Thickness(2);};bar.LostKeyboardFocus+=(_,_)=>bar.BorderThickness=new Thickness(0);Grid.SetRow(bar,1);column.Children.Add(bar);
            var label=Ui.Text(b.Start.ToString("HH:mm"),12,"#B6C6DA");label.TextAlignment=TextAlignment.Center;Grid.SetRow(label,2);column.Children.Add(label);Grid.SetColumn(column,i+1);grid.Children.Add(column);
        }
        AutomationProperties.SetName(grid,Loc.Pick("Eseményszám az időtengelyen; a nulla alul, a skála balra látható.","Event count over time; zero baseline at bottom, scale at left."));return grid;
    }
    Border AnalystPanel()
    {
        bool absent=Scenario is "Missing" or "EngineUnavailable" or "AiUnavailable" or "Stale";
        var header=new Grid();header.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});header.ColumnDefinitions.Add(new(){Width=new GridLength(44)});
        header.Children.Add(Ui.Text(AnalystName,19,"#9AC5FF",true));var core=new CoreVisual{Minimal=true,Width=40,Height=38};Grid.SetColumn(core,1);header.Children.Add(core);
        string title=Loc.Pick("Az eszközszintű érvényesülés nem igazolt","Device-level enforcement is not verified");
        var content=Ui.Stack(header,Ui.Text(Loc.Pick("BEÉPÍTETT DEMÓELEMZÉS • nincs élő AI-generáció","BUILT-IN DEMO ANALYSIS • no live AI generation"),11,"#74DCFF",true),Ui.Text(title,20,bold:true),
            Ui.Text(Loc.Pick("A konfigurált szabály és a naplózott esemény nem bizonyítja, hogy az eszköz tényleges DNS-forgalmára a kívánt szabály érvényesült.","A configured rule and a recorded event do not prove that the intended policy was enforced on the device's actual DNS traffic."),14,"#B6C6DA"));
        var metadata=new WrapPanel();foreach(var text in new[]{Loc.Pick("Bizonyosság: Ismeretlen","Confidence: Unknown"),Loc.Pick("Súlyosság: vizsgálandó, nem igazolt incidens","Severity: investigate, no confirmed incident"),Loc.Pick("Érintett forrás: közös fixture; Engine-ID nincs","Affected source: shared fixture; no Engine ID")})metadata.Children.Add(Ui.Badge(text));content.Children.Add(metadata);
        content.Children.Add(Ui.Text(absent?Loc.Pick("Aktuális bizonyíték nem áll rendelkezésre.","Current evidence is unavailable."):Loc.Pick($"Háttéradat: {Store.Events.Count} demóesemény. A fixture-ben nincs enforcementet igazoló adat.",$"Context: {Store.Events.Count} demo events. No data confirming enforcement is present in the fixture."),13,"#B6C6DA"));
        content.Children.Add(Ui.Text(Loc.Pick("Következő vizsgálat: eszközhöz és policyverzióhoz kötött alkalmazási visszaigazolás és DNS-útvonal ellenőrzése.","Next investigation: obtain device- and policy-version-bound acknowledgment and inspect the DNS path."),14));
        content.Children.Add(Actions(("Bizonyítékok",ShowAnalystEvidence,"AgentEvidence"),("Diagnosztika",()=>Navigate("Diagnosztika"),"AnalystDiagnostics")));
        var panel=Ui.Card(content);panel.BorderBrush=Ui.Brush("#3A7395");panel.Padding=new Thickness(16);return panel;
    }
    public void ShowAnalystEvidence()
    {if(EngineMode){ShowEngineEvidence();return;}
        SelectFinding("Primary");detailTitle.Text=Loc.Pick("Érvényesülési bizonyíték hiánya","Missing enforcement evidence");
        detailFinding.Text=Loc.Pick("Bizonyosság: Ismeretlen\nSúlyosság: további vizsgálat\nElemzés: előre megírt demonstrációs szöveg.","Confidence: Unknown\nSeverity: investigate\nAnalysis: predefined demonstration text.");
        detailEvidence.Text=Loc.Pick($"Forrás: közös demóesemények ({Store.Events.Count} sor).\nEngine-azonosító: nem áll rendelkezésre.\nEszközazonosítók: rendelkezésre állnak a fixture-eseményekben.\nAlkalmazási visszaigazolás: nincs.\nEnforcement-bizonyíték: nincs.\nEgy naplózott engedély/tiltás nem hálózati bizonyítás.",$"Source: shared demo events ({Store.Events.Count} rows).\nEngine identifier: unavailable.\nDevice identifiers: available in fixture events.\nApplication acknowledgment: absent.\nEnforcement evidence: absent.\nA logged allow/block is not network proof.");
        detailNext.Text=Loc.Pick("Vesd össze az eszköz DNS-útvonalát, a policyverziót és az Engine alkalmazási visszaigazolását. A demó nem hajt végre vizsgálatot.","Compare device DNS path, policy version and Engine acknowledgment. This demo performs no investigation.");
    }
    void DiagnosticsPage()
    {
        page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Upstream késleltetés – diagnosztikai észrevétel","Upstream latency – diagnostic observation"),21,bold:true),Ui.Text(Loc.Pick("Elsősorban teljesítmény- és rendelkezésreállási mutató, önmagában nem biztonsági incidens.","Primarily a performance and availability indicator; not a security incident by itself."),14,"#B6C6DA"),Ui.Text(Loc.Pick("A fixture-ben nincs resolverazonosító, Engine-ID, mért válaszidő, időablakhoz kötött összehasonlítás vagy eltérésérték. Mért késleltetés és felhasználói hatás nem állapítható meg.","The fixture has no resolver ID, Engine ID, measured latency, time-window comparison or deviation value. Measured latency and user impact cannot be determined.")),Actions(("Bizonyítékok",ShowAnalystEvidence,"DiagnosticEvidence")))));
        page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Engine-visszaigazolás: nincs"),Ui.Text("Érvényesülés: nem igazolt"),Ui.Text("Adatok frissessége: kizárólag beépített fixture.",14,"#B6C6DA"))));
    }
    public void ClearActivityFilter(string key)
    {
        switch(key){case "search":ActivitySearch="";break;case "device":ActivityDevice="";break;case "domain":ActivityDomain="";break;case "user":ActivityUser="";break;case "type":ActivityType="";break;case "scope":ActivityScope="";break;case "decision":ActivityDecision="";break;case "result":ActivityResult="";break;case "date":ActivityFrom=ActivityTo="";break;case "all":ActivitySearch=ActivityDevice=ActivityDomain=ActivityUser=ActivityType=ActivityScope=ActivityDecision=ActivityResult=ActivityFrom=ActivityTo="";break;}
    }
    void ActivityPage()
    {
        var search=Input(ActivitySearch,"ActivitySearch");search.Height=38;search.Margin=new Thickness(0,0,0,10);search.MinWidth=200;
        var basic=new Grid();basic.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});for(int i=0;i<3;i++)basic.ColumnDefinitions.Add(new(){Width=GridLength.Auto});basic.Children.Add(Field("Keresés",search));
        var searchActions=new (string,Action,string)[]{(Loc.Pick("Szűrők","Filters"),()=>{ActivityFiltersOpen=!ActivityFiltersOpen;BuildPage();AnimatePage();},"ToggleActivityFilters"),("Keresés",()=>{ActivitySearch=search.Text.Trim();BuildPage();},"ApplyActivity"),(Loc.Pick("Szűrők törlése","Clear filters"),()=>{ClearActivityFilter("all");BuildPage();},"ClearActivity")};
        for(int i=0;i<searchActions.Length;i++){var action=searchActions[i];var button=Ui.Button(action.Item1,action.Item2,action.Item3);button.Height=38;button.VerticalAlignment=VerticalAlignment.Bottom;button.Margin=new Thickness(8,0,0,10);Grid.SetColumn(button,i+1);basic.Children.Add(button);}page.Children.Add(basic);
        var periods=Actions((Loc.Pick("Minden fixture-esemény","All fixture events"),()=>{ActivityFrom=ActivityTo="";BuildPage();},"ActivityPeriodAll"),(Loc.Pick("Fixture napja: 2026-11-01","Fixture day: 2026-11-01"),()=>{ActivityFrom=ActivityTo="2026-11-01";BuildPage();},"ActivityPeriodDay"));page.Children.Add(periods);
        var chips=new WrapPanel();foreach(var (key,value) in new[]{("search",ActivitySearch),("device",ActivityDevice),("domain",ActivityDomain),("user",ActivityUser),("type",ActivityType),("scope",ActivityScope),("decision",ActivityDecision),("result",ActivityResult),("date",ActivityFrom.Length+ActivityTo.Length==0?"":ActivityFrom+"…"+ActivityTo)})if(value.Length>0){var chip=Ui.Button(value+" ×",()=>{ClearActivityFilter(key);BuildPage();},"RemoveFilter"+key);chip.Margin=new Thickness(0,0,7,7);chips.Children.Add(chip);}page.Children.Add(chips);
        if(ActivityFiltersOpen)
        {
            var fields=new[]{("Eszköz",ActivityDevice,"ActivityDevice"),("Domain",ActivityDomain,"ActivityDomain"),("Felhasználó",ActivityUser,"ActivityUser"),("Eseménytípus",ActivityType,"ActivityType"),("Hatókör",ActivityScope,"ActivityScope"),("Hozzáférési döntés",ActivityDecision,"ActivityDecision"),("Eredmény",ActivityResult,"ActivityResult"),("Dátumtól (yyyy-MM-dd)",ActivityFrom,"ActivityFrom"),("Dátumig (yyyy-MM-dd)",ActivityTo,"ActivityTo")};
            var inputs=fields.Select(f=>Input(f.Item2,f.Item3)).ToArray();var form=new WrapPanel();for(int i=0;i<fields.Length;i++){var field=Field(fields[i].Item1,inputs[i]);field.Width=190;form.Children.Add(field);}
            var controls=Ui.Stack(form,Actions(("Keresés",()=>{var v=inputs.Select(t=>t.Text.Trim()).ToArray();if(v[7]!=""&&!DateTime.TryParseExact(v[7],"yyyy-MM-dd",System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.None,out _)||v[8]!=""&&!DateTime.TryParseExact(v[8],"yyyy-MM-dd",System.Globalization.CultureInfo.InvariantCulture,System.Globalization.DateTimeStyles.None,out _)){Message(Loc.Pick("Érvénytelen dátum; yyyy-MM-dd szükséges.","Invalid date; use yyyy-MM-dd."));return;}ActivitySearch=search.Text.Trim();ActivityDevice=v[0];ActivityDomain=v[1];ActivityUser=v[2];ActivityType=v[3];ActivityScope=v[4];ActivityDecision=v[5];ActivityResult=v[6];ActivityFrom=v[7];ActivityTo=v[8];BuildPage();},"SearchAdvanced")));page.Children.Add(Ui.Card(controls));
        }
        var rows=FilterEvents();page.Children.Add(Ui.Text($"{rows.Count} / {Store.Events.Count} "+Loc.Pick("fixture-esemény • nincs élő auditforrás","fixture events • not an authoritative live audit source"),13,"#B6C6DA"));
        var table=Table(rows,("Időpont","Time",170),("Felhasználó","User",145),("Eszköz","Device",120),("Domain","Domain",170),("Eseménytípus","TypeText",150),("Hatókör","ScopeText",120),("Hozzáférési döntés","DecisionText",150),("Eredmény","ResultText",230));page.Children.Add(table);
        page.Children.Add(Actions(("Részletek",()=>{if(table.SelectedItem is DemoEvent e)Modal(Loc.T("Tevékenység"),Ui.Text($"{e.Time:O}\n{e.User}\n{e.Session}\n{e.Device} / {e.Domain}\n{e.TypeText} / {e.ScopeText} / {e.DecisionText}\n{e.ResultText}"));},"ActivityDetails")));
    }
}
