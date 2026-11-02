using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Automation;
using System.Windows.Threading;
using System.Text.Json;
using DesignPrototype.Engine;
namespace DesignPrototype;

public sealed partial class PrototypeWindow
{
    public EngineProjection EngineData{get;private set;}=new();public bool EngineMode{get;private set;}public bool EngineMock{get;private set;}
    public MockHttpsEngine? MockEngine{get;private set;}public EnginePoller? EnginePolling{get;private set;}public EngineReader? EngineTransport{get;private set;}
    public string EngineModeLabel=>ReleaseCandidate&&EngineTransport==null?Loc.Pick("UAT • NINCS KAPCSOLAT","UAT • NOT CONNECTED"):EngineMock?(ReleaseCandidate?"UAT • LOCAL HTTPS TEST":"MOCK ENGINE • HTTPS • READ-ONLY"):("ENGINE • "+(userSession?.Role??"NINCS MUNKAMENET"));
    readonly List<(TextBlock Text,Func<string> Value)> engineTexts=[];StackPanel? engineChart;string engineChartKey="";string engineDeviceSearch="";string? selectedEngineDevice;string? selectedEngineEvent;
    public int EngineRefreshes{get;private set;}public int EnginePageBuilds{get;private set;}public string EngineAppliedSearch=>ActivitySearch;public DataGrid? EngineGrid{get;private set;}
    readonly DispatcherTimer freshnessTimer=new(){Interval=TimeSpan.FromSeconds(1)};long sourceEpoch;bool closeAfterEngineStop;
    public async Task StartMockEngine(bool automatic=true,bool schedule=true)
    {
        await StopEngine();MockEngine=new(){AutoChange=automatic,ReleaseManagement=ReleaseCandidate};MockEngine.Start();EngineMock=true;
        await AttachEngine(new EngineReader(MockEngine.Origin,MockEngine.Certificate,()=>MockEngine?.Token),5,schedule);
    }
    public async Task StartLiveEngine(string configPath)
    {
        if(ReleaseCandidate)throw new InvalidOperationException("New LIVE connection is not authorized for RC preparation.");
        var config=LiveConfiguration.Load(configPath);await StopEngine();EngineMock=false;
        var credentials=new ReadOnlyCredential();await AttachEngine(new EngineReader(config.Origin,config.EnrolledCertificate,()=>credentials.Read(config.CredentialId)),config.PollSeconds);
    }
    async Task AttachEngine(EngineReader reader,int seconds,bool schedule=true)
    {
        EngineData=new();EngineMode=true;EngineTransport=reader;long epoch=++sourceEpoch;CloseModal();CloseDetails();
        EnginePolling=new(reader,snapshot=>Dispatcher.InvokeAsync(()=>{if(epoch!=sourceEpoch||!EngineMode)return;if(SessionState=="Active"&&(!snapshot.Get("/dns/status")!.Usable||snapshot.Reads.Values.Any(r=>r.Error==ReadError.Authentication))){QueueSessionFailure();return;}EngineData.Apply(snapshot);EngineRefreshes++;RefreshEngineBindings(true);WriteEngineReceipt();}).Task,TimeSpan.FromSeconds(seconds));
        if(!engineClosingHook){engineClosingHook=true;Closing+=async(_,args)=>{if(closeAfterEngineStop)return;args.Cancel=true;await StopEngine();closeAfterEngineStop=true;Dispatcher.BeginInvoke(()=>Close());};freshnessTimer.Tick+=(_,_)=>{if(EngineMode)RefreshEngineBindings();};}
        freshnessTimer.Start();scenarioButton.Content=EngineModeLabel;BuildPage();Adapt();if(schedule)EnginePolling.Start();else await EnginePolling.PollOnceAsync();
    }
    bool engineClosingHook;
    public async Task StopEngine()
    {
        sourceEpoch++;freshnessTimer.Stop();var poll=EnginePolling;EnginePolling=null;if(poll!=null)await poll.DisposeAsync();EngineTransport=null;
        var mock=MockEngine;MockEngine=null;if(mock!=null)await mock.DisposeAsync();EngineMode=false;engineTexts.Clear();engineChart=null;EngineGrid=null;
        InsightDevice="";selectedEngineDevice=null;selectedEngineEvent=null;engineDeviceSearch="";ClearActivityFilter("all");
    }
    internal async Task PauseEngineForMeasurement(){if(EnginePolling!=null)await EnginePolling.DisposeAsync();freshnessTimer.Stop();}
    public void CycleMockScenario()
    {
        if(MockEngine==null){Message(Loc.Pick("Élő módban nincs hibaszimuláció.","No fault simulation in live mode."));return;}
        var states=new[]{"Normal","DeviceGone","Disconnected","503","Missing","Stale","Empty","Normal"};int i=Array.IndexOf(states,MockEngine.Scenario);MockEngine.Scenario=states[(i+1)%states.Length];scenarioButton.Content=EngineModeLabel+" · "+MockEngine.Scenario;
    }
    void WriteEngineReceipt()
    {
        try{File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"engine-state.json"),JsonSerializer.Serialize(new{mode=EngineModeLabel,refreshes=EngineRefreshes,instance=EngineData.Instance,revision=EngineData.Revision,connected=EngineData.Connected,devices=EngineData.Devices.Count,events=EngineData.Events.Count,requests=EngineTransport?.Requests,networkProof=EngineData.NetworkProof.ToString(),policyProof=EngineData.PolicyProof.ToString(),view=CurrentView,outer=new[]{ActualWidth,ActualHeight},selected=selectedEngineDevice,search=ActivitySearch,scenario=MockEngine?.Scenario},new JsonSerializerOptions{WriteIndented=true}));}catch(IOException){}catch(UnauthorizedAccessException){}
    }
    TextBlock EngineText(Func<string> value,double size=14,string color="#B6C6DA",bool bold=false)
    {var text=Ui.Text(value(),size,color,bold);engineTexts.Add((text,value));return text;}
    static string Unknown=>Loc.Pick("Nem ismert","Unknown");
    static string ProofText(ProofState state)=>state switch{ProofState.Configured=>Loc.Pick("Konfigurálva","Configured"),ProofState.Applied=>Loc.Pick("Alkalmazás megfigyelve","Applied to observed requests"),ProofState.Verified=>Loc.Pick("Hálózaton igazolva","Verified network effect"),ProofState.Unavailable=>Loc.Pick("Nem elérhető","Unavailable"),_=>Loc.Pick("Nem igazolt","Unknown")};
    string GetField(string path,string field){var f=EngineData.Field(path,field);return (f.Value??Unknown)+(f.Freshness==DataState.Stale?Loc.Pick(" · elavult"," · stale"):"");}
    string ConnectionSummary()=>EnginePolling?.CircuitOpen==true?Loc.Pick("Nyolc sikertelen ciklus után a kapcsolat szünetel. Újracsatlakozás a Beállításoknál.","Connection paused after eight failed cycles. Resume in Settings."):EngineData.Connected?Loc.Pick("Az Engine adatforrás elérhető","Engine data source available"):Loc.Pick("Az adatforrás nem elérhető vagy nem friss","Data source unavailable or stale")+" · "+ErrorLabel(EngineData.ConnectionError);
    public static string ErrorLabel(ReadError error)=>error switch{ReadError.Authentication=>Loc.Pick("Hitelesítési hiba (401)","Authentication failed (401)"),ReadError.Forbidden=>Loc.Pick("Hozzáférés megtagadva (403)","Access forbidden (403)"),ReadError.Tls=>Loc.Pick("A tanúsítvány ellenőrzése sikertelen","Certificate validation failed"),ReadError.Timeout=>Loc.Pick("A lekérdezés időtúllépéssel megszakadt","Request timed out"),ReadError.Unreachable=>Loc.Pick("A kapcsolat megszakadt vagy nem elérhető","Connection lost or unreachable"),ReadError.InvalidJson or ReadError.Schema=>Loc.Pick("A válasz formátuma hiányos vagy hibás","Response is malformed or incomplete"),ReadError.Server=>Loc.Pick("Az Engine kiszolgáló hibát jelzett","Engine server error"),ReadError.None=>Unknown,_=>error.ToString()};
    void RefreshEngineBindings(bool refreshTables=false)
    {
        foreach(var (text,get) in engineTexts){var value=get();if(text.Text!=value)text.Text=value;}
        if(refreshTables&&EngineGrid!=null){var selected=EngineGrid.SelectedItem;CollectionViewSource.GetDefaultView(EngineGrid.ItemsSource)?.Refresh();if(selected!=null&&EngineGrid.Items.Contains(selected))EngineGrid.SelectedItem=selected;}
        RefreshEngineChart();UpdateEngineFooter();
    }
    void UpdateEngineFooter(){scenarioButton.Content=EngineModeLabel;DetailsButton.IsEnabled=EngineMode;AutomationProperties.SetName(scenarioButton,EngineModeLabel);scenarioButton.ToolTip=EngineMock?"F6: isolated mock scenario":"Live read-only; no fault simulation";status.Text=EngineModeLabel+" | "+(EngineData.Connected?Loc.Pick("friss API-adat","fresh API data"):Loc.Pick("elavult / nem elérhető","stale / unavailable"))+ $" | {ActualWidth:0} × {ActualHeight:0} DIP";}
    public bool BuildEnginePage()
    {
        EnginePageBuilds++;engineTexts.Clear();engineChart=null;EngineGrid=null;page.Children.Clear();CurrentTable=null;
        page.Children.Add(Actions(("Kijelentkezés",()=>SignOut(),"EngineSignOut")));page.Children.Add(Ui.Text("HOSTSGUARDIAN / "+EngineModeLabel,12,"#9AC5FF",true));page.Children.Add(Ui.Text(Loc.T(CurrentView),27,bold:true));
        if(CurrentView!="Domainek és policy") {
        if(ReleaseCandidate)page.Children.Add(Ui.Text(Loc.Pick("A részletes technikai vizsgálat elsődleges helye a Linux Engine. Itt a fontos állapotok és teendők láthatók.","Use the Linux Engine for detailed technical investigation. This view shows essential state and next steps."),12));
        page.Children.Add(EngineText(()=>ConnectionSummary()+" · "+Loc.Pick("Utolsó sikeres státuszfrissítés: ","Last successful status update: ")+(EngineData.LastSuccess?.ToLocalTime().ToString("HH:mm:ss")??Unknown)));
        page.Children.Add(Ui.Text(ReleaseCandidate&&EngineTransport==null?Loc.Pick("Nincs csatlakoztatott adatforrás. Az ismeretlen állapot nem jelent védelmet.","No connected data source. Unknown does not mean protected."):EngineMock?Loc.Pick("Izolált HTTPS mock • szintetikus adatok • nincs production kapcsolat.","Isolated HTTPS mock • synthetic data • no production connection."):Loc.Pick("Valódi Engine • szerveroldali szerepkör- és eszközkorlátozás.","Real Engine • server-enforced role and device scope."),12,"#74DCFF"));
        }
        switch(CurrentView)
        {
            case "Áttekintés":EngineOverview();break;
            case "Eszközök":EngineDevicesPage();break;
            case "Tevékenység":EngineActivityPage();break;
            case "Security Insights":EngineInsightsPage();IntegratedAnalystCard();break;
            case "Diagnosztika":EngineDiagnosticsPage();break;
            case "Domainek és policy":if(ReleaseCandidate){IntegratedRulesPage();break;}page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Policy – kizárólag visszaolvasás","Policy – readback only"),21,bold:true),EngineText(()=>"Revision: "+(EngineData.Revision?.ToString()??Unknown)+" · "+EngineData.PolicyProof),Ui.Text(Loc.Pick("A konfigurált szabály és az Engine döntése nem bizonyítja a hálózati hatást. A mentés és az alkalmazás le van tiltva.","A configured rule and an Engine decision do not prove network effect. Save and apply are disabled.")),EngineWarnings())));break;
            case "Beállítások":if(ReleaseCandidate)ReleaseSettingsPage();else EngineSettingsPage();break;
        }
        WriteEngineReceipt();return true;
    }
    Border EngineWarnings()=>Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Védelmi bizonyíték: nem igazolt","Protection evidence: not verified"),20,"#FFD58A",true),
        EngineText(()=>Loc.Pick("Bindingok: ","Bindings: ")+(EngineData.Fresh("/v2/bindings")?Json.A(EngineData.Value("/v2/bindings"),"observations").Length.ToString():Unknown)),
        EngineText(()=>Loc.Pick("IPv6 eszközszintű védelem: ","IPv6 device enforcement: ")+(EngineData.Fresh("/v2/capabilities")?Json.B(EngineData.Value("/v2/capabilities"),"ipv6DeviceEnforcement") is {} enabled?(enabled?Loc.Pick("Engine-képesség; hálózati hatás nem igazolt","Engine capability; network effect unverified"):Loc.Pick("Nem támogatott","Not supported")):Unknown:Unknown)),
        Ui.Text(Loc.Pick("A receiver állapota a jelenlegi HTTPS-szerződésből nem állapítható meg. A Gate 5 auditban UNAVAILABLE volt; ez történeti megfigyelés, nem mostani mérés.","Receiver state is not exposed by the current HTTPS contract. Gate 5 observed UNAVAILABLE; this is historical evidence, not a current measurement.")),
        Ui.Text(ReleaseCandidate?Loc.Pick("A meglévő hitelesített management-hozzáférés nem felhasználói RBAC. Az UAT csak olvas; nincs eszközspecifikus védettségi ígéret.","Existing authenticated management access is not user RBAC. UAT is read-only; device-specific protection is not promised."):Loc.Pick("A szerver ellenőrzi az aktuális munkamenetet és hatókört. A visszaolvasás önmagában nem igazolt hálózati védelem.","Engine user RBAC is missing. This client only reads; local demo login is not Engine authentication."),13,"#FFD58A")));
    void EngineOverview()
    {
        var hero=new Grid();hero.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});hero.ColumnDefinitions.Add(new(){Width=new GridLength(150)});
        hero.Children.Add(Ui.Stack(EngineText(ConnectionSummary,23,"#F2F6FC",true),Ui.Text(Loc.Pick("Megfigyelés, nem védettségi ígéret.","Observation, not a protection guarantee."),15),EngineText(()=>"DNS UDP: "+GetField("/dns/status","udpState")+" · TCP: "+GetField("/dns/status","tcpState")),EngineText(()=>"Upstream: "+GetField("/dns/status","lastUpstreamOutcome")),EngineText(()=>"Policy revision: "+(EngineData.Revision?.ToString()??Unknown)),EngineText(()=>Loc.Pick("Fogadott DNS-kérések: ","Received DNS queries: ")+(Json.N(Json.P(EngineData.Value("/v2/diagnostics"),"counters"),"received")?.ToString()??Unknown)+(EngineData.Fresh("/v2/diagnostics")?"":Loc.Pick(" · ELAVULT / NEM ELÉRHETŐ"," · STALE / UNAVAILABLE")))));var core=new CoreVisual{Height=150};Grid.SetColumn(core,1);hero.Children.Add(core);page.Children.Add(Ui.Card(hero));page.Children.Add(EngineWarnings());page.Children.Add(EngineAnalyst());
    }
    Border EngineAnalyst()=>Ui.Card(Ui.Stack(Ui.Text(AnalystName,20,"#9AC5FF",true),Ui.Text(Loc.Pick("DETERMINISZTIKUS ADATÖSSZEFOGLALÓ • nincs RAG/LLM-hívás","DETERMINISTIC DATA SUMMARY • no RAG/LLM call"),11,"#74DCFF",true),EngineText(()=>Loc.Pick("Szabálybizonyíték: ","Rule evidence: ")+ProofText(EngineData.PolicyProof)+" · "+Loc.Pick("Hálózati hatás: ","Network effect: ")+ProofText(EngineData.NetworkProof),18,"#FFD58A"),Ui.Text(Loc.Pick("Az alkalmazási megfigyelés csak a naplózott kérésekre érvényes, nem minden szabályra. Bizonyosság: nincs elegendő végponti bizonyíték. Következő vizsgálat: jóváhagyott kliens DNS-útja, friss binding és kérés/válasz korreláció.","Application evidence applies only to recorded requests, not all rules. Confidence: insufficient endpoint evidence. Next investigation: approved client DNS path, fresh binding and request/response correlation.")),Actions(("Bizonyítékok",ShowEngineEvidence,"EngineEvidence"))));
    public void ShowEngineEvidence()
    {
        SelectFinding("Engine");detailTitle.Text=Loc.Pick("Engine-bizonyítékok","Engine evidence");detailFinding.Text=ConnectionSummary();
        detailEvidence.Text=string.Join("\n",EngineReader.Paths.Select(p=>{var r=EngineData.Latest?.Get(p);return p+"\n"+(r==null?Unknown:r.Error+" · "+r.Freshness+" · received "+r.ReceivedAt.ToString("O")+" · observed "+(r.ObservedAt?.ToString("O")??Unknown));}));
        detailNext.Text=Loc.Pick("Configured ≠ Applied ≠ Verified. A megjelenített értékek Engine-adatok; a végponti hálózati hatás nincs bizonyítva.","Configured ≠ Applied ≠ Verified. Values are Engine data; endpoint network effect is not proven.");
    }
    DataGrid EngineTable(System.Collections.ObjectModel.ObservableCollection<EngineRow> rows,params(string Hu,string En,string Field,double Width)[] columns)
    {
        var grid=new DataGrid{ItemsSource=CollectionViewSource.GetDefaultView(rows),AutoGenerateColumns=false,IsReadOnly=true,CanUserAddRows=false,Height=Compact?270:330,EnableRowVirtualization=true,EnableColumnVirtualization=true,Margin=new Thickness(0,8,0,12)};
        foreach(var c in columns)grid.Columns.Add(new DataGridTextColumn{Header=Loc.Pick(c.Hu,c.En),Binding=new Binding("["+c.Field+"]"),MinWidth=c.Width,Width=c.Width,ElementStyle=(Style)Application.Current.FindResource("GridText")});
        AutomationProperties.SetAutomationId(grid,"EngineTable");EngineGrid=grid;CurrentTable=grid;return grid;
    }
    void EngineDevicesPage()
    {
        var search=Input(engineDeviceSearch,"EngineDeviceSearch");search.TextChanged+=(_,_)=>{engineDeviceSearch=search.Text;CollectionViewSource.GetDefaultView(EngineData.Devices).Refresh();};page.Children.Add(Field(Loc.Pick("Keresés név, IP vagy Engine-azonosító alapján","Search name, IP or Engine identity"),search));
        var view=CollectionViewSource.GetDefaultView(EngineData.Devices);view.Filter=x=>x is EngineRow r&&new[]{"Name","Id","Address"}.Any(k=>(r.Raw(k)??"").Contains(engineDeviceSearch,StringComparison.OrdinalIgnoreCase));
        var grid=EngineTable(EngineData.Devices,("Eszköz","Device","Name",170),("IP-címek","IP addresses","Address",165),("Identitásbizonyíték","Identity evidence","Identity",230),("Binding","Binding","Binding",190),("Utolsó megfigyelés","Last observation","Seen",210),("Jelenlét","Presence","Presence",250),("Engine ID","Engine ID","Id",290));grid.SelectedItem=EngineData.Devices.FirstOrDefault(x=>x.Key==selectedEngineDevice);grid.SelectionChanged+=(_,_)=>{if(grid.SelectedItem is EngineRow r)selectedEngineDevice=r.Key;};page.Children.Add(grid);
        page.Children.Add(Ui.Text(Loc.Pick("A lista automatikus frissítése nem hálózati discovery. A hiányzó sor rövid ideig megmarad, ismeretlen jelenléttel; a kliens nem alkot új eszközidentitást.","Automatic list refresh is not network discovery. Missing rows are temporarily retained with unknown presence; the client creates no device identity.")));
        page.Children.Add(Actions(("Részletek",()=>{if(grid.SelectedItem is EngineRow r)Modal(Loc.Pick("Engine-eszköz","Engine device"),Ui.Text(r["Id"]+"\n"+r["Source"]+"\n"+r["Presence"]));},"EngineDeviceDetails")));
    }
    bool EngineEventMatches(EngineRow r)
    {
        bool Contains(string field,string filter)=>filter.Length==0||(r.Raw(field)??"").Contains(filter,StringComparison.OrdinalIgnoreCase);
        bool date=true;if(DateTimeOffset.TryParse(r.Raw("Time"),out var t)){if(DateTime.TryParse(ActivityFrom,out var from))date&=t.Date>=from.Date;if(DateTime.TryParse(ActivityTo,out var to))date&=t.Date<=to.Date;}else if(ActivityFrom.Length+ActivityTo.Length>0)date=false;
        return date&&(ActivitySearch.Length==0||new[]{"Domain","Device","Decision","Result","Type","Reason"}.Any(f=>Contains(f,ActivitySearch)))&&Contains("Domain",ActivityDomain)&&Contains("Device",ActivityDevice)&&Contains("User",ActivityUser)&&Contains("Scope",ActivityScope)&&Contains("Type",ActivityType)&&Contains("Decision",ActivityDecision)&&Contains("Result",ActivityResult);
    }
    void EngineActivityPage()
    {
        var search=Input(ActivitySearch,"ActivitySearch");search.Height=38;search.Margin=new Thickness(0,0,0,10);search.MinWidth=150;
        var basic=new Grid();basic.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});for(int i=0;i<3;i++)basic.ColumnDefinitions.Add(new(){Width=GridLength.Auto});basic.Children.Add(Field("Keresés",search));
        var actions=new (string Text,Action Run,string Id)[]{(Loc.Pick("Szűrők","Filters"),()=>{ActivitySearch=search.Text;ActivityFiltersOpen=!ActivityFiltersOpen;BuildPage();},"ToggleActivityFilters"),(Loc.T("Keresés"),()=>{ActivitySearch=search.Text;BuildPage();},"ApplyActivity"),(Loc.Pick("Szűrők törlése","Clear filters"),()=>{ClearActivityFilter("all");BuildPage();},"ClearActivity")};
        for(int i=0;i<actions.Length;i++){var a=actions[i];var button=Ui.Button(a.Text,a.Run,a.Id);button.Height=38;button.Margin=new Thickness(8,0,0,10);button.VerticalAlignment=VerticalAlignment.Bottom;Grid.SetColumn(button,i+1);basic.Children.Add(button);}page.Children.Add(basic);
        var chips=new WrapPanel();foreach(var (key,value) in new[]{("search",ActivitySearch),("device",ActivityDevice),("domain",ActivityDomain),("user",ActivityUser),("type",ActivityType),("scope",ActivityScope),("decision",ActivityDecision),("result",ActivityResult),("date",ActivityFrom+ActivityTo)})if(value.Length>0){var chip=Ui.Button(value+" ×",()=>{ClearActivityFilter(key);BuildPage();},"RemoveFilter"+key);chip.Margin=new Thickness(0,0,7,7);chips.Children.Add(chip);}page.Children.Add(chips);
        if(ActivityFiltersOpen)
        {
            var fields=new[]{("Eszköz",ActivityDevice),("Domain",ActivityDomain),("Felhasználó",ActivityUser),("Eseménytípus",ActivityType),("Hatókör",ActivityScope),("Hozzáférési döntés",ActivityDecision),("Eredmény",ActivityResult),("Dátumtól (yyyy-MM-dd)",ActivityFrom),("Dátumig (yyyy-MM-dd)",ActivityTo)};var boxes=fields.Select((f,i)=>Input(f.Item2,"EngineFilter"+i)).ToArray();var form=new WrapPanel();for(int i=0;i<fields.Length;i++){var f=Field(fields[i].Item1,boxes[i]);f.Width=190;form.Children.Add(f);}page.Children.Add(Ui.Card(Ui.Stack(form,Actions(("Keresés",()=>{var a=boxes.Select(b=>b.Text.Trim()).ToArray();if(a[7]!=""&&!DateTime.TryParseExact(a[7],"yyyy-MM-dd",null,System.Globalization.DateTimeStyles.None,out _)||a[8]!=""&&!DateTime.TryParseExact(a[8],"yyyy-MM-dd",null,System.Globalization.DateTimeStyles.None,out _)){Message(Loc.Pick("Érvénytelen dátum.","Invalid date."));return;}ActivitySearch=search.Text;ActivityDevice=a[0];ActivityDomain=a[1];ActivityUser=a[2];ActivityType=a[3];ActivityScope=a[4];ActivityDecision=a[5];ActivityResult=a[6];ActivityFrom=a[7];ActivityTo=a[8];BuildPage();},"SearchAdvanced")))));
        }
        CollectionViewSource.GetDefaultView(EngineData.Events).Filter=x=>x is EngineRow r&&EngineEventMatches(r);
        var grid=EngineTable(EngineData.Events,("Időpont (forrás)","Time (source)","Time",215),("Domain","Domain","Domain",200),("Eszköz","Device","Device",190),("Döntés","Decision","Decision",110),("Eredmény","Result","Result",160),("Eseménytípus","Event type","Type",140),("Bizonyíték","Evidence","Proof",250));grid.SelectedItem=EngineData.Events.FirstOrDefault(x=>x.Key==selectedEngineEvent);grid.SelectionChanged+=(_,_)=>{if(grid.SelectedItem is EngineRow r)selectedEngineEvent=r.Key;};page.Children.Add(grid);
        page.Children.Add(EngineText(()=>Loc.Pick("Megtartott Engine-események: ","Retained Engine events: ")+EngineData.Events.Count+" · "+(EngineData.Fresh("/v2/dns-observations")?"API":"STALE / UNAVAILABLE")));
        page.Children.Add(Ui.Text(Loc.Pick("A régebbi Engine nem közöl válaszeredményt vagy felhasználót; ezek Nem ismert állapotban maradnak. A döntés nem bizonyított kliensoldali hatás.","Older Engine versions do not report response outcome or user; these remain Unknown. A decision is not verified client-side effect.")));
    }
    void EngineDiagnosticsPage()
    {
        page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Engine állapot és erőforrások","Engine status and resources"),21,bold:true),EngineText(()=>Loc.Pick("Diagnosztika forrása: ","Diagnostics source: ")+(EngineData.Fresh("/v2/diagnostics")?Loc.Pick("friss API-minta","fresh API sample"):Loc.Pick("ELAVULT / NEM ELÉRHETŐ – korábbi értékek","STALE / UNAVAILABLE – retained values")),13,"#FFD58A"),EngineText(()=>"Runtime: "+GetField("/dns/status","runtimeState")),EngineText(()=>"Upstream: "+GetField("/dns/status","lastUpstreamOutcome")),EngineText(()=>{var r=Json.P(EngineData.Value("/v2/diagnostics"),"resources");return "CPU: "+(Json.D(r,"cpuPercent")?.ToString("0.00")??Unknown)+"% · RAM: "+(Json.N(r,"workingSetBytes") is {} b?(b/1048576.0).ToString("0.0")+" MiB":Unknown);}),EngineText(()=>{var latency=Json.P(EngineData.Value("/v2/diagnostics"),"upstreamLatency");return "Upstream p95: "+(Json.D(latency,"p95Ms")?.ToString("0.00")??Unknown)+" ms · samples: "+(Json.N(latency,"samples")?.ToString()??Unknown);}),Ui.Text(Loc.Pick("A késleltetés diagnosztikai adat, önmagában nem biztonsági incidens.","Latency is diagnostic data, not a security incident by itself.")),Actions(("Bizonyítékok",ShowEngineEvidence,"EngineDiagnosticEvidence")))));page.Children.Add(EngineWarnings());
    }
    void EngineInsightsPage()
    {
        var overview=new WrapPanel();foreach(var item in new[]{(Loc.Pick("Policy állapot","Policy state"),(Func<string>)(()=>ProofText(EngineData.PolicyProof))),(Loc.Pick("Hálózati hatás","Network effect"),()=>ProofText(EngineData.NetworkProof)),(Loc.Pick("Események (API)","Events (API)"),()=>EngineData.Fresh("/v2/dns-observations")||EngineData.Fresh("/v2/operational-events?after=0")?EngineData.Events.Count.ToString():Unknown)}){var card=Ui.Card(Ui.Stack(Ui.Text(item.Item1,12,"#B6C6DA",true),EngineText(item.Item2,22,"#FFD58A",true)));card.Width=Compact?245:285;card.Margin=new Thickness(0,0,12,10);overview.Children.Add(card);}page.Children.Add(overview);
        var controls=new Grid();controls.ColumnDefinitions.Add(new(){Width=GridLength.Auto});controls.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});controls.ColumnDefinitions.Add(new(){Width=GridLength.Auto});
        var periods=Actions(new[]{6,12,24}.Select(h=>(h+Loc.Pick(" óra"," hours"),(Action)(()=>{InsightHours=h;engineChartKey="";RefreshEngineChart();}),"InsightPeriod"+h)).ToArray());foreach(Button b in periods.Children){b.Height=38;b.Margin=new Thickness(0,0,8,10);}controls.Children.Add(Field(Loc.Pick("Időszak","Period"),periods));
        var device=Input(InsightDevice,"InsightDeviceSearch");device.Height=38;device.Margin=new Thickness(16,0,8,10);device.MinWidth=150;var field=Field(Loc.Pick("Engine DeviceId (üres = összes)","Engine DeviceId (empty = all)"),device);Grid.SetColumn(field,1);controls.Children.Add(field);var filter=Ui.Button("Szűrés",()=>{InsightDevice=device.Text.Trim();engineChartKey="";RefreshEngineChart();},"InsightDeviceFilter");filter.Height=38;filter.Margin=new Thickness(0,0,0,10);filter.VerticalAlignment=VerticalAlignment.Bottom;Grid.SetColumn(filter,2);controls.Children.Add(filter);
        engineChart=new();page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Mi történik a hálózatban?","What is happening on the network?"),19,bold:true),controls,engineChart,Ui.Text(Loc.Pick("Forrás: /v3/activity, 5 perces nem osztályozott DNS-bucketek. A hiányzó időablak nincs nullával kitöltve. A szolgáltatások átfedő számai nem kerülnek összeadásra.","Source: /v3/activity, unclassified 5-minute DNS buckets. Missing intervals are not filled with zero. Overlapping service counts are not added."),12))));engineChartKey="";RefreshEngineChart();page.Children.Add(EngineAnalyst());
    }
    void RefreshEngineChart()
    {
        if(engineChart==null)return;var endpoint=EngineData.LastGood.GetValueOrDefault("/v3/activity");var key=(endpoint?.Value?.GetRawText()??"")+InsightHours+InsightDevice+EngineData.Fresh("/v3/activity");if(key==engineChartKey)return;engineChartKey=key;engineChart.Children.Clear();
        var data=Json.A(EngineData.Value("/v3/activity"),"buckets").GroupBy(b=>(Json.S(b,"deviceId"),Json.S(b,"serviceId"),Json.T(b,"windowStartUtc"))).Where(g=>g.Select(b=>b.GetRawText()).Distinct().Count()==1).Select(g=>g.First()).Where(b=>Json.P(b,"serviceId") is null or {ValueKind:JsonValueKind.Null}).Where(b=>InsightDevice==""||Json.S(b,"deviceId")==InsightDevice).Where(b=>Json.T(b,"windowStartUtc")>DateTimeOffset.UtcNow.AddHours(-InsightHours)).Where(b=>Json.N(b,"allowed")>=0&&Json.N(b,"blocked")>=0&&Json.N(b,"failed")>=0).GroupBy(b=>Json.T(b,"windowStartUtc")!.Value).OrderBy(g=>g.Key).TakeLast(6).Select(g=>(Start:g.Key.UtcDateTime,End:g.Key.AddMinutes(5).UtcDateTime,Count:(int)Math.Min(int.MaxValue,g.Sum(b=>(double)(Json.N(b,"allowed")??0)+(Json.N(b,"blocked")??0)+(Json.N(b,"failed")??0))))).ToArray();
        if(data.Length==0){engineChart.Children.Add(Ui.Text(Loc.Pick("Nincs megjeleníthető aggregátum – nem nulla forgalom.","No displayable aggregate – not zero traffic."),16,"#FFD58A"));return;}
        engineChart.Children.Add(Ui.Text((EngineData.Fresh("/v3/activity")?"API":"STALE / UNAVAILABLE")+" · UTC · "+data[0].Start.ToString("yyyy-MM-dd"),12));engineChart.Children.Add(BuildActivityChart(data));
    }
    void EngineSettingsPage()
    {
        if(EnginePolling?.CircuitOpen==true)page.Children.Add(Actions((Loc.Pick("Kapcsolat helyreállítása","Resume connection"),()=>EnginePolling?.Resume(),"ResumeEngineConnection")));
        page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Megjelenés és adatforrás","Appearance and data source"),21,bold:true),Actions(("Sötét",()=>ChangeTheme(false),"EngineDark"),("Világos",()=>ChangeTheme(true),"EngineLight"),("Magyar",()=>ChangeLanguage(false),"EngineHu"),("English",()=>ChangeLanguage(true),"EngineEn")),Ui.Text(Loc.Pick("Az Engine-kapcsolat nem írja felül a helyi felület beállításait. A LIVE mód külön Gate 6B jóváhagyást és explicit indítást igényel; soha nem indul automatikusan.","Engine connection does not overwrite local UI settings. LIVE mode requires separate Gate 6B approval and explicit launch; it never starts automatically.")),EngineText(()=>"Polling: "+EnginePolling?.Interval.TotalSeconds+" s · requests: "+EngineTransport?.Requests),Actions(("DEMO – fixture",async()=>{await StopEngine();CloseDetails();BuildPage();Adapt();scenarioButton.Content="DEMO • fixture";},"EngineDemoMode")))));
    }
}


