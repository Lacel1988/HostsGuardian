using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace DesignPrototype;

public static class Program
{
    [STAThread] public static void Main(string[] args)
    {
        var app=new Application{ShutdownMode=ShutdownMode.OnMainWindowClose};app.Resources.MergedDictionaries.Add((ResourceDictionary)Application.LoadComponent(new Uri("Styles.xaml",UriKind.Relative)));Theme.Initialize();
        var verification=args.Length==3&&(args[0]=="--verify-rbac"||args[0]=="--verify-block-list-restart")?args[2]:null;
        var window=new PrototypeWindow(verification==null){ReleaseCandidate=true,AutoStartup=false,SkipLogin=false};
        if(args.Length==2&&args[0]=="--isolated-demo")
        {
            using var fixture=JsonDocument.Parse(File.ReadAllBytes(args[1]));var root=fixture.RootElement;
            var config=root.GetProperty("configuration").Deserialize<DesignPrototype.Engine.LiveConfiguration>()!;
            if(!System.Net.IPAddress.IsLoopback(System.Net.IPAddress.Parse(new Uri(config.Origin).Host)))throw new InvalidOperationException("Isolated demo accepts loopback only");
            var connection=new LabConnection(config,root.GetProperty("credentialDirectory").GetString()!);
            window.ConnectionProvider=_=>Task.FromResult(connection);
            window.Title="HostsGuardian – IZOLÁLT Domain Block List demó";
        }
        if(verification!=null)window.Loaded+=async(_,_)=>{try{if(args[0]=="--verify-block-list-restart")await window.RunBlockListRestartCheck(args[1],verification);else await window.RunIntegratedChecks(args[1],verification);}catch(Exception ex){Directory.CreateDirectory(verification);File.WriteAllText(Path.Combine(verification,"failure.txt"),ex.GetType().Name+": "+ex.Message);Environment.ExitCode=1;}finally{window.Close();}};
        app.Run(window);
    }

}

public static class Ui
{
    public static SolidColorBrush Brush(string hex)=>Theme.Brush(hex);
    public static TextBlock Text(string value,double size=15,string color="#F2F6FC",bool bold=false)=>new(){Text=Loc.T(value),FontSize=size,Foreground=Brush(color),FontWeight=bold?FontWeights.SemiBold:FontWeights.Normal,LineHeight=size*1.4,Margin=new Thickness(0,0,0,6)};
    public static Button Button(string text,Action action,string id)
    {
        var b=new Button{Content=Loc.T(text)};AutomationProperties.SetName(b,Loc.T(text));AutomationProperties.SetAutomationId(b,id);b.Click+=(_,_)=>action();return b;
    }
    public static Border Card(UIElement child)=>new(){Background=Brush("#142238"),BorderBrush=Brush("#365571"),BorderThickness=new Thickness(1),CornerRadius=new CornerRadius(14),Padding=new Thickness(18),Margin=new Thickness(0,0,0,12),Child=child};
    public static StackPanel Stack(params UIElement[] elements){var p=new StackPanel();foreach(var e in elements)p.Children.Add(e);return p;}
    public static Border Badge(string text,string color="#9AC5FF")=>new(){HorizontalAlignment=HorizontalAlignment.Left,Background=Brush("#22344C"),CornerRadius=new CornerRadius(5),Padding=new Thickness(8,3,8,3),Margin=new Thickness(0,0,8,4),Child=Text(text,12,color,true)};
}

public sealed record WindowPreference(double Width,double Height,double Left,double Top,bool Maximized);

public sealed partial class PrototypeWindow:Window
{
    readonly bool savePlacement;
    readonly string preferences=Path.Combine(AppContext.BaseDirectory,"uat-window.json");
    public Grid Surface {get;}=new();
    readonly Grid body=new();
    readonly StackPanel navigation=new();
    readonly Dictionary<string,Button> navigationButtons=new();
    readonly Border navigationBorder;
    readonly ScrollViewer mainScroll=new(){VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled};
    readonly StackPanel page=new();
    readonly Border detailBorder;
    readonly ScrollViewer detailScroll=new(){VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
    readonly TextBlock headerTitle=Ui.Text("Áttekintés",18,bold:true);
    readonly TextBlock status=Ui.Text("",12,"#B6C6DA");
    readonly TextBlock detailTitle=Ui.Text("",21,bold:true);
    readonly TextBlock detailFinding=Ui.Text("",15,"#B6C6DA");
    readonly TextBlock detailEvidence=Ui.Text("",14,"#B6C6DA");
    readonly TextBlock detailNext=Ui.Text("",14);
    readonly Button scenarioButton;
    public Button DetailsButton {get;}
    public Button CloseButton {get;}
    public Button NavigationButton {get;}
    public string CurrentView {get;private set;}="Áttekintés";
    public string Scenario {get;private set;}="Fresh";
    public string Selected {get;private set;}="";
    public bool Compact=>Surface.ActualWidth<1100;
    bool panelRequested,drawerOpen,navigationOpen,previousDock;
    public bool Docked=>detailBorder.Visibility==Visibility.Visible&&Grid.GetColumn(detailBorder)==3;
    public bool DetailVisible=>detailBorder.Visibility==Visibility.Visible;
    public double[] Metrics=>new[]{body.ColumnDefinitions[0].ActualWidth,Surface.RowDefinitions[0].ActualHeight,detailBorder.ActualWidth,Surface.RowDefinitions[2].ActualHeight};
    public string[] ScenarioNames {get;}={"Fresh","Long","Missing","EngineUnavailable","AiUnavailable","Stale","Dense","Incident"};

    public PrototypeWindow(bool persist)
    {
        savePlacement=persist;
        Title="HostsGuardian • Security Core • IZOLÁLT GATE 6A";
        SizeToContent=SizeToContent.Manual;
        Width=1360;Height=850;MinWidth=900;MinHeight=760;
        FontFamily=new FontFamily("Segoe UI");FontSize=15;Background=Ui.Brush("#0C1422");Foreground=Ui.Brush("#F2F6FC");
        WindowStartupLocation=WindowStartupLocation.CenterScreen;UseLayoutRounding=true;SnapsToDevicePixels=true;TextOptions.SetTextFormattingMode(this,TextFormattingMode.Display);TextOptions.SetTextRenderingMode(this,TextRenderingMode.Grayscale);
        if(persist)RestorePlacement();
        Surface.Background=new RadialGradientBrush((Color)ColorConverter.ConvertFromString("#15314E"),(Color)ColorConverter.ConvertFromString("#080F1D")){Center=new Point(.80,.06),GradientOrigin=new Point(.80,.06),RadiusX=.9,RadiusY=.9};
        Surface.RowDefinitions.Add(new(){Height=new GridLength(60)});Surface.RowDefinitions.Add(new(){Height=new GridLength(1,GridUnitType.Star)});Surface.RowDefinitions.Add(new(){Height=new GridLength(32)});
        var header=new Grid{Margin=new Thickness(16,0,16,0)};
        foreach(var width in new[]{GridLength.Auto,new GridLength(1,GridUnitType.Star),GridLength.Auto,GridLength.Auto})header.ColumnDefinitions.Add(new(){Width=width});
        NavigationButton=Ui.Button("☰",ToggleNavigation,"NavigationToggle");NavigationButton.ToolTip="Navigáció megnyitása vagy bezárása";NavigationButton.Margin=new Thickness(0,0,14,0);NavigationButton.VerticalAlignment=VerticalAlignment.Center;header.Children.Add(NavigationButton);
        headerTitle.Margin=new Thickness(0);headerTitle.TextWrapping=TextWrapping.NoWrap;headerTitle.TextTrimming=TextTrimming.CharacterEllipsis;headerTitle.VerticalAlignment=VerticalAlignment.Center;Grid.SetColumn(headerTitle,1);header.Children.Add(headerTitle);
        scenarioButton=Ui.Button("DEMÓ · Alapállapot",NextScenario,"DemoScenario");scenarioButton.ToolTip="F6: következő demonstrációs állapot. Nincs élő kapcsolat.";scenarioButton.Margin=new Thickness(8,0,12,0);scenarioButton.VerticalAlignment=VerticalAlignment.Center;Grid.SetColumn(scenarioButton,2);header.Children.Add(scenarioButton);
        DetailsButton=Ui.Button("Részletek",ToggleDetails,"OpenDetails");DetailsButton.VerticalAlignment=VerticalAlignment.Center;Grid.SetColumn(DetailsButton,3);header.Children.Add(DetailsButton);Surface.Children.Add(header);
        body.ColumnDefinitions.Add(new(){Width=new GridLength(232)});body.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});body.ColumnDefinitions.Add(new(){Width=new GridLength(0)});body.ColumnDefinitions.Add(new(){Width=new GridLength(0)});Grid.SetRow(body,1);Surface.Children.Add(body);
        navigationBorder=new Border{Background=Ui.Brush("#101C2E"),Padding=new Thickness(12,20,12,12)};
        navigation.Children.Add(new CoreVisual{Width=60,Height=52,Minimal=true,HorizontalAlignment=HorizontalAlignment.Left});navigation.Children.Add(Ui.Text("HostsGuardian",20,"#E7F6FF",true));navigation.Children.Add(Ui.Text("CONTROL CENTER",12,"#B6C6DA"));
        var spacer=new Border{Height=22};navigation.Children.Add(spacer);
        foreach(var (name,glyph) in new[]{("Áttekintés","⌂"),("Eszközök","▣"),("Domainek és policy","≡"),("Tevékenység","◷"),("Security Insights","◇"),("Diagnosztika","⌁"),("Beállítások","⚙")})
        {
            var row=new StackPanel{Orientation=Orientation.Horizontal};var icon=Ui.Text(glyph,18,"#9AC5FF");icon.Width=26;icon.Margin=new Thickness(0);row.Children.Add(icon);var text=Ui.Text(name,14);text.Margin=new Thickness(8,0,0,0);text.VerticalAlignment=VerticalAlignment.Center;row.Children.Add(text);
            var b=Ui.Button(name,()=>Navigate(name),"Nav"+navigationButtons.Count);b.Style=(Style)Application.Current.FindResource("NavButton");b.Content=row;b.Margin=new Thickness(0,0,0,5);navigationButtons[name]=b;navigation.Children.Add(b);
        }
        navigationBorder.Child=new ScrollViewer{Content=navigation,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled};body.Children.Add(navigationBorder);
        mainScroll.Content=page;mainScroll.Margin=new Thickness(24,18,24,8);Grid.SetColumn(mainScroll,1);body.Children.Add(mainScroll);
        CloseButton=Ui.Button("← Vissza",CloseDetails,"CloseDetails");CloseButton.HorizontalAlignment=HorizontalAlignment.Left;CloseButton.Margin=new Thickness(0,0,0,18);
        var detail=Ui.Stack(CloseButton,Ui.Text("AI BIZTONSÁGI ELEMZŐ / BIZONYÍTÉKOK",12,"#9AC5FF",true),detailTitle,detailFinding,
            new Border{Height=12},Ui.Text("Bizonyíték és hatókör",15,bold:true),detailEvidence,new Border{Height=12},Ui.Text("Következő vizsgálat",15,bold:true),detailNext,
            new Border{Height=16},Ui.Text("Passzív diagnosztika • Nincs végrehajtó művelet",12,"#FFD58A"));
        detailScroll.Content=detail;detailBorder=new Border{Background=Ui.Brush("#172940"),BorderBrush=Ui.Brush("#6B88AF"),BorderThickness=new Thickness(1,0,0,0),Padding=new Thickness(20),Child=detailScroll,Visibility=Visibility.Collapsed};Panel.SetZIndex(detailBorder,20);body.Children.Add(detailBorder);
        status.Margin=new Thickness(0);status.TextWrapping=TextWrapping.NoWrap;status.TextTrimming=TextTrimming.CharacterEllipsis;
        var footer=new Border{Background=Ui.Brush("#101C2E"),Padding=new Thickness(16,5,16,0),Child=status};Grid.SetRow(footer,2);Surface.Children.Add(footer);Content=Surface;
        Surface.SizeChanged+=(_,_)=>Adapt();
        Loaded+=(_,_)=>{if(ReleaseCandidate){InitializeRelease();return;}Navigate(ActivationLab?"Beállítások":"Áttekintés");WriteStateReceipt();InitializeIdentity();InitializeExperience();};
        PreviewKeyDown+=async(_,e)=>
        {
            var key=e.Key==Key.System?e.SystemKey:e.Key;
            if(ReleaseCandidate){if(key==Key.Escape)CloseDetails();else if(key==Key.D&&Keyboard.Modifiers==ModifierKeys.Alt)ToggleDetails();else if(key==Key.F10)ToggleNavigation();else return;e.Handled=true;return;}
            if(key==Key.F9&&Keyboard.Modifiers==ModifierKeys.None){if(EngineMode&&EngineMock)await ShowGate6Scene(Gate6Scene%12+1);else ReviewNext();e.Handled=true;}
            if(key==Key.F8&&Keyboard.Modifiers==ModifierKeys.None){if(EngineMode)ShowEngineEvidence();else ShowDeveloper();e.Handled=true;}
            if(key==Key.F6){if(EngineMode){CycleMockScenario();e.Handled=true;return;}NextScenario();e.Handled=true;}
            if(key==Key.F2&&Keyboard.Modifiers==ModifierKeys.None){StartStartup(2.5);e.Handled=true;}
            if(key==Key.F3&&Keyboard.Modifiers==ModifierKeys.None){StartStartup(4);e.Handled=true;}
            if(key==Key.F4&&Keyboard.Modifiers==ModifierKeys.None){SetReducedMotion(!CoreVisual.ReducedMotion);e.Handled=true;}
            if(key==Key.F7&&Keyboard.Modifiers==ModifierKeys.None){AdvanceStartupPhase();e.Handled=true;}
            if(key==Key.F10&&Keyboard.Modifiers==ModifierKeys.None){ToggleNavigation();e.Handled=true;}
            if(Keyboard.Modifiers==ModifierKeys.Control&&key is Key.D1 or Key.D2 or Key.D3){SetScenario(key==Key.D1?"Fresh":key==Key.D2?"Dense":"Incident");e.Handled=true;}
            if(key==Key.D&&Keyboard.Modifiers==ModifierKeys.Alt){ToggleDetails();e.Handled=true;}
            if(key==Key.Escape&&StartupVisible){ExitStartup();e.Handled=true;return;}
            if(key==Key.Escape){if(DetailVisible)CloseDetails();else if(navigationOpen){navigationOpen=false;Adapt();NavigationButton.Focus();}e.Handled=true;}
        };
        Closing+=(_,_)=>{if(savePlacement)SavePlacement();};
    }

    void RestorePlacement()
    {
        var area=SystemParameters.WorkArea;
        try
        {
            if(File.Exists(preferences))
            {
                var p=JsonSerializer.Deserialize<WindowPreference>(File.ReadAllText(preferences));
                if(p!=null&&new[]{p.Width,p.Height,p.Left,p.Top}.All(double.IsFinite)&&p.Width>=900&&p.Height>=760&&p.Width<10000&&p.Height<10000)
                {
                    Width=Math.Min(p.Width,area.Width);Height=Math.Min(p.Height,area.Height);Left=Math.Clamp(p.Left,area.Left,Math.Max(area.Left,area.Right-Width));Top=Math.Clamp(p.Top,area.Top,Math.Max(area.Top,area.Bottom-Height));WindowStartupLocation=WindowStartupLocation.Manual;if(p.Maximized)WindowState=WindowState.Maximized;return;
                }
            }
        }catch(IOException){}catch(JsonException){}catch(UnauthorizedAccessException){}
        // Only initial placement is fitted to the available desktop, never a page transition.
        Width=Math.Max(MinWidth,Math.Min(1360,area.Width));Height=Math.Max(MinHeight,Math.Min(850,area.Height));
    }
    void SavePlacement()
    {
        var bounds=WindowState==WindowState.Normal?new Rect(Left,Top,ActualWidth,ActualHeight):RestoreBounds;
        try { File.WriteAllText(preferences,JsonSerializer.Serialize(new WindowPreference(bounds.Width,bounds.Height,bounds.Left,bounds.Top,WindowState==WindowState.Maximized))); }
        catch(IOException){}catch(UnauthorizedAccessException){}
    }
    string ScenarioLabel=>Scenario switch{"Long"=>"Hosszú magyar szöveg","Missing"=>"Hiányzó adat","EngineUnavailable"=>"Engine nem elérhető","AiUnavailable"=>"AI nem elérhető","Stale"=>"Elavult adat","Dense"=>"Sűrű demóadat","Incident"=>"Diagnosztikai incidens",_=>"Alapállapot"};
    string FindingTitle=>Scenario switch
    {
        "Incident"=>"Több diagnosztikai jelzés összefüggése további vizsgálatot igényel",
        "Long"=>"A névfeloldási válaszidők ingadozásának vizsgálatához további, időben összevethető upstream megfigyelések szükségesek",
        "Missing"=>"Nincs elegendő bizonyíték az értékeléshez",
        "EngineUnavailable"=>"Az Engine aktuális állapota nem ellenőrizhető",
        "AiUnavailable"=>"Az elemző jelenleg nem érhető el",
        "Stale"=>"A korábbi megállapítás elavult",
        _=>"Upstream késleltetés: további vizsgálat javasolt"
    };
    string Certainty=>Scenario is "Missing" or "EngineUnavailable" or "AiUnavailable" or "Stale"?"UNKNOWN":"INFERRED";
    string NextInvestigation=>Scenario=="Long"?"Hasonlítsd össze az azonos megfigyelési időszakhoz tartozó elsődleges és tartalék névfeloldó mintáit, és ellenőrizd, hogy elegendő sikeres mérés áll-e rendelkezésre a következtetéshez. Az időbeli együttjárás önmagában nem bizonyít ok-okozati kapcsolatot.":Scenario is "EngineUnavailable" or "Missing"?"Ellenőrizd az adatforrás rendelkezésre állását és az utolsó sikeres megfigyelés idejét.":"Vesd össze az upstream mintákat azonos megfigyelési időablakban.";
    public void NextScenario(){var i=Array.IndexOf(ScenarioNames,Scenario);SetScenario(ScenarioNames[(i+1)%ScenarioNames.Length]);}
    public void SetScenario(string scenario)
    {
        if(EngineMode){CycleMockScenario();return;}
        Scenario=scenario;scenarioButton.Content="DEMÓ · "+ScenarioLabel;AutomationProperties.SetName(scenarioButton,(string)scenarioButton.Content);BuildPage();
        if(DetailVisible)PopulateDetails();Adapt();WriteStateReceipt();
    }
    public void Navigate(string view)
    {
        if(CurrentView!=view){panelRequested=false;drawerOpen=false;Selected="";}
        CurrentView=view;headerTitle.Text=Loc.T(view);
        if(navigationOpen){navigationOpen=false;NavigationButton.Focus();}
        foreach(var (name,b) in navigationButtons)b.Tag=name==view?"selected":null;
        BuildPage();mainScroll.ScrollToTop();Adapt();AnimatePage();WriteStateReceipt();
    }
    public void ToggleNavigation(){navigationOpen=!navigationOpen;Adapt();if(navigationOpen){if(!CoreVisual.ReducedMotion){var move=new TranslateTransform();navigationBorder.RenderTransform=move;move.BeginAnimation(TranslateTransform.XProperty,new System.Windows.Media.Animation.DoubleAnimation(-20,0,TimeSpan.FromMilliseconds(160)));}Dispatcher.BeginInvoke(()=>navigationButtons[CurrentView].Focus(),DispatcherPriority.Input);}else NavigationButton.Focus();WriteStateReceipt();}
    public void SelectFinding(string title)
    {
        Selected=title;panelRequested=true;drawerOpen=Surface.ActualWidth<1320;PopulateDetails();if(Loc.English){detailTitle.Text=Selected=="Primary"?Loc.T(FindingTitle):Selected;detailFinding.Text="Severity: investigate / Confidence: Inferred or Unknown. Synthetic fixture, not live analysis.";detailEvidence.Text="Source: built-in fixture. Freshness: demonstration only. Scope: sample Engine observations; no verified device-level DNS protection.";detailNext.Text="Compare measurements from the same observation window.";}detailScroll.ScrollToTop();Adapt();AnimateElement(detailBorder);Dispatcher.BeginInvoke(()=>CloseButton.Focus(),DispatcherPriority.Input);WriteStateReceipt();
    }
    void PopulateDetails()
    {
        detailTitle.Text=Selected=="Primary"?FindingTitle:Selected;
        string level=Selected=="Primary"?Certainty:Selected.StartsWith("Lehetséges")?"HYPOTHESIS":"UNKNOWN";
        detailFinding.Text=$"Súlyosság: {(level=="INFERRED"?"figyelmeztetés":"információ")}\nBizonyosság: {Loc.T(level)}\nElemzés: szintetikus demó, nem élő eredmény.";
        detailEvidence.Text=Scenario is "Missing" or "EngineUnavailable"?"Aktuális bizonyíték: nem áll rendelkezésre.\nAz ismeretlen állapot nem tekinthető hibamentes vagy védett állapotnak.":"Forrás: beépített demonstrációs diagnosztikai összesítés.\nMegfigyelés: bemutatott 14:31–14:32.\nFrissesség: "+(Scenario=="Stale"?"ELAVULT":"kizárólag demó")+".\nHatókör: a bemutatott Engine-fixture; nem igazol minden eszközre érvényes DNS-védelmet.";
        detailNext.Text=NextInvestigation;
        if(Scenario=="Incident")detailEvidence.Text+="\n\nDIAGNOSZTIKAI ELEMZÉS · SZINTETIKUS SZÖVEG\nA fixture két egymástól elkülönített megfigyelési időszakban eltérő upstream válaszidőt szemléltet. Ez INFERRED megállapítás; nem támasztja alá támadás vagy eszközszintű megkerülés tényét.\n\nHYPOTHESIS: az elsődleges és tartalék resolver eltérő viselkedése hozzájárulhatott a mintázathoz. A feltételezést azonos időablakból származó méréssel kell vizsgálni.\n\nUNKNOWN: az eszközök tényleges névfeloldási útvonala, az esetleges DoH-használat és a teljes LAN-lefedettség. A hiányzó adat nem jelent hibamentességet.\n\nKorlát: a bemutató nem használ valódi Engine-adatot, nem hív LLM-et, és nem végez automatikus policy-módosítást. A szöveg előre megírt UX-fixture.";
    }
    public void ToggleDetails(){if(ReleaseCandidate&&!EngineMode)return;if(DetailVisible)CloseDetails();else if(EngineMode)ShowEngineEvidence();else if(CurrentView is "Áttekintés" or "Security Insights" or "Diagnosztika")ShowAnalystEvidence();}
    public void CloseDetails(){panelRequested=false;drawerOpen=false;Adapt();DetailsButton.Focus();WriteStateReceipt();}
    public void Adapt()
    {
        if(Surface.ActualWidth<1)return;
        var dock=panelRequested&&(Surface.ActualWidth>=1320||previousDock&&Surface.ActualWidth>=1280);
        if(previousDock&&!dock)drawerOpen=false;
        bool show=dock||drawerOpen;
        if(detailBorder.IsKeyboardFocusWithin&&!show)DetailsButton.Focus();
        if(navigationBorder.IsKeyboardFocusWithin&&Compact&&!navigationOpen)NavigationButton.Focus();
        body.ColumnDefinitions[0].Width=new GridLength(Compact?0:232);
        body.ColumnDefinitions[2].Width=new GridLength(dock?16:0);body.ColumnDefinitions[3].Width=new GridLength(dock?340:0);
        navigationBorder.Visibility=!Compact||navigationOpen?Visibility.Visible:Visibility.Collapsed;
        navigationBorder.Width=navigationOpen?232:double.NaN;navigationBorder.HorizontalAlignment=navigationOpen?HorizontalAlignment.Left:HorizontalAlignment.Stretch;Grid.SetColumnSpan(navigationBorder,navigationOpen?2:1);Panel.SetZIndex(navigationBorder,navigationOpen?25:0);
        Grid.SetColumn(detailBorder,dock?3:1);Grid.SetColumnSpan(detailBorder,dock?1:3);detailBorder.Visibility=show?Visibility.Visible:Visibility.Collapsed;detailBorder.Margin=dock?new Thickness(0):new Thickness(8);
        mainScroll.IsEnabled=!(show&&!dock)&&!navigationOpen;navigationBorder.IsEnabled=!(show&&!dock);KeyboardNavigation.SetTabNavigation(detailBorder,show&&!dock?KeyboardNavigationMode.Cycle:KeyboardNavigationMode.Continue);
        KeyboardNavigation.SetTabNavigation(navigationBorder,navigationOpen?KeyboardNavigationMode.Cycle:KeyboardNavigationMode.Continue);
        status.Text=$"DEMÓ • nem élő   |   {ActualWidth:0} × {ActualHeight:0} DIP ablak   |   {(Compact?"kompakt":"normál")}   |   {ScenarioLabel}";
        if(Loc.English)status.Text=$"DEMO • no live connection  |  {ActualWidth:0} × {ActualHeight:0} DIP  |  {(Compact?"compact":"normal")}";
        if(EngineMode)UpdateEngineFooter();else if(ReleaseCandidate)status.Text="UAT • NINCS KAPCSOLAT • UNKNOWN";
        previousDock=dock;
    }
    public void BuildPage()
    {
        if(!BackendSessionActive){if(loginOverlay==null&&IsLoaded)ShowLogin(false);return;}
        if(ReleaseCandidate&&!EngineMode){ReleaseOfflinePage();return;}
        if(EngineMode && BuildEnginePage())return;
        if(BuildExperiencePage())return;
        var focused=Keyboard.FocusedElement as DependencyObject;var id=page.IsKeyboardFocusWithin&&focused!=null?AutomationProperties.GetAutomationId(focused):"";
        page.Children.Clear();
        page.Children.Add(Ui.Text(CurrentView=="Security Insights"?"AI BIZTONSÁGI ELEMZŐ / SECURITY INSIGHTS":"HOSTSGUARDIAN / CONTROL CENTER",12,"#9AC5FF",true));
        if(BuildRichPage()){}
        else if(CurrentView=="Áttekintés")Overview();
        else if(CurrentView=="Security Insights")Insights();
        else if(CurrentView=="Eszközök")
        {
            page.Children.Add(Ui.Text("Eszközbizonyítékok",26,bold:true));
            foreach(var name in new[]{"Windows-PC","Nappali TV","Offline eszköz"})page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(name+" · demó",19,bold:true),Ui.Text("Jelenlét: szemléltető • Identitás: bizonytalan • DNS-lefedettség: UNKNOWN",14,"#B6C6DA"),Ui.Button("Bizonyítékok",()=>SelectFinding(name),"Device"+page.Children.Count))));
        }
        else if(CurrentView=="Diagnosztika")page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Engine-kapcsolat: nem elérhető · demó",23,bold:true),Ui.Text("Nem áll rendelkezésre aktuális Engine-bizonyíték. A kapcsolat, a policy alkalmazása és az eszközvédelem külön állapot.",15,"#B6C6DA"),Ui.Badge("UNKNOWN","#FFD58A"),Ui.Text("A prototípus nem végez hálózati lekérést.",13,"#B6C6DA"))));
        else if(CurrentView=="Domainek és policy")page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Domainek és policy",25,bold:true),Ui.Text("Megjelenítési példa • nincs szabályszerkesztés vagy küldés.",15,"#B6C6DA"),Ui.Text("example.invalid  |  Kívánt állapot: tiltás  |  Engine-visszaigazolás: nincs",14),Ui.Badge("NINCS VISSZAIGAZOLÁS","#FFD58A"))));
        else if(CurrentView=="Tevékenység")page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Diagnosztikai események · demó",25,bold:true),Ui.Text("14:32  •  INFERRED  •  Upstream minták vizsgálata\n14:31  •  UNKNOWN  •  Nincs elegendő eszközszintű bizonyíték",15,"#B6C6DA"))));
        else page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Ablak és megjelenítés",25,bold:true),Ui.Text("A külső ablak mérete navigáció és állapotváltás közben állandó. A kézzel választott méret, pozíció és maximalizálás a prototípus saját könyvtárában őrizhető meg.",15,"#B6C6DA"),Ui.Text("Alt+D: részletek · Escape: vissza · F6: következő demóállapot",14))));
        if(id.Length>0)Dispatcher.BeginInvoke(()=>Find(page,id)?.Focus(),DispatcherPriority.Input);
    }
    void Overview()
    {
        page.Children.Add(CoreHero());
        page.Children.Add(AgentSummary());
        var quick=new WrapPanel();foreach(var (name,id) in new[]{("Eszközök","QuickDevices"),("Domainek és policy","QuickPolicies"),("Diagnosztika","QuickDiagnostics")}){var b=Ui.Button(name+" →",()=>Navigate(name),id);b.Margin=new Thickness(0,0,10,8);quick.Children.Add(b);}page.Children.Add(quick);
        page.Children.Add(Ui.Text("Utolsó bemutatott megfigyelés: "+(Scenario is "Missing" or "EngineUnavailable"?"nem áll rendelkezésre":Scenario=="Stale"?"elavult":"14:32 · demó")+". A AI biztonsági elemző kizárólag értelmez és javasol.",12,"#B6C6DA"));
    }
    Border AgentSummary()=>AnalystPanel();
    void Insights()
    {
        page.Children.Add(Ui.Text("Diagnosztikai megállapítások",26,bold:true));page.Children.Add(Ui.Text("Passzív AI biztonsági elemző • A súlyosság és a bizonyosság külön értelmezendő.",14,"#B6C6DA"));
        var rows=new[]{(Certainty,FindingTitle,"Javasolt vizsgálat és bizonyítékok", "Primary"),("HYPOTHESIS","Lehetséges resolver-eltérés","Összehasonlító minta szükséges; nem igazolt hiba.","Lehetséges resolver-eltérés"),("UNKNOWN","Eszközszintű lefedettség","Nem áll rendelkezésre elegendő bizonyíték.","Eszközszintű lefedettség")};
        foreach(var (level,title,note,key) in rows)
        {
            var row=new Grid();row.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});row.ColumnDefinitions.Add(new(){Width=GridLength.Auto});
            var text=Ui.Stack(Ui.Text(level+"  ·  "+(level=="INFERRED"?"FIGYELMEZTETÉS":"INFORMÁCIÓ"),12,"#9AC5FF",true),Ui.Text(title,18,bold:true),Ui.Text(note,13,"#B6C6DA"));text.Margin=new Thickness(0,0,14,0);row.Children.Add(text);
            var button=Ui.Button("Részletek",()=>SelectFinding(key),"Finding"+level);button.VerticalAlignment=VerticalAlignment.Center;Grid.SetColumn(button,1);row.Children.Add(button);page.Children.Add(Ui.Card(row));
        }
        var disabled=Ui.Button("Új elemzés · demóban nem elérhető",()=>{},"DisabledAnalysis");disabled.IsEnabled=false;disabled.HorizontalAlignment=HorizontalAlignment.Left;page.Children.Add(disabled);page.Children.Add(Ui.Text("Az elemző nem módosít policyt és nem indít beavatkozást.",12,"#B6C6DA"));
    }
    public static UIElement? Find(DependencyObject root,string id){if(root is UIElement e&&AutomationProperties.GetAutomationId(root)==id)return e;for(int i=0;i<VisualTreeHelper.GetChildrenCount(root);i++){var found=Find(VisualTreeHelper.GetChild(root,i),id);if(found!=null)return found;}return null;}
    public object Receipt()=>new { outerWidth=ActualWidth,outerHeight=ActualHeight,left=Left,top=Top,state=WindowState.ToString(),clientWidth=Surface.ActualWidth,clientHeight=Surface.ActualHeight,view=CurrentView,scenario=Scenario,compact=Compact,panel=Docked?"docked":DetailVisible?"drawer":"closed",selected=Selected,metrics=Metrics,dpi=VisualTreeHelper.GetDpi(this).DpiScaleX,density=Scenario=="Dense",reducedMotion=CoreVisual.ReducedMotion,insightHours=InsightHours,insightDevice=InsightDevice,activityFiltersOpen=ActivityFiltersOpen,settingsCategory=SettingsTab,sessionNotice=SessionNotice,pickerSelection=PickerSelection.ToArray(),analyst=AnalystName,reviewStep=ReviewStep,theme=Theme.Light?"Light":"Dark",language=Loc.English?"en":"hu",session=SessionState,role=Account.Role,policyCount=Store.Policies.Count,startupPhase=startupPreviewPhase,menuOpen=navigationOpen,rowCount=CurrentTable?.Items.Count??0,mainViewportWidth=MainViewportWidth };
    void WriteStateReceipt(){if(IsLoaded)Dispatcher.BeginInvoke(()=>{try{File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"runtime-state.json"),JsonSerializer.Serialize(Receipt(),new JsonSerializerOptions{WriteIndented=true}));}catch(IOException){}catch(UnauthorizedAccessException){}},DispatcherPriority.ApplicationIdle);}
}

public static class Verification
{
    static async Task Flush(){await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);await Task.Delay(80);}
    public static async Task Run(PrototypeWindow w,string output)
    {
        Directory.CreateDirectory(output);var checks=new List<string>();var states=new List<object>();await Flush();
        var initial=(w.ActualWidth,w.ActualHeight,w.WindowState);
        void Check(bool test,string name){if(!test)throw new InvalidOperationException(name);checks.Add(name);}
        void Stable(string label){Check(Math.Abs(w.ActualWidth-initial.ActualWidth)<.1&&Math.Abs(w.ActualHeight-initial.ActualHeight)<.1&&w.WindowState==initial.WindowState,"Stable outer window: "+label);states.Add(w.Receipt());}
        foreach(var view in new[]{"Áttekintés","Eszközök","Domainek és policy","Tevékenység","Security Insights","Diagnosztika","Beállítások"}){w.Navigate(view);await Flush();Stable(view);}
        w.Navigate("Áttekintés");await Flush();foreach(var scenario in w.ScenarioNames){w.SetScenario(scenario);await Flush();Stable(scenario);}
        w.SetScenario("Fresh");w.SelectFinding("Primary");await Flush();Stable("open evidence");Check(w.DetailVisible,"Evidence opens inside window");Check(w.CloseButton.IsKeyboardFocused,"Explicit evidence open moves focus into details");
        w.CloseDetails();await Flush();Stable("close evidence");Check(w.DetailsButton.IsKeyboardFocused,"Closing evidence restores trigger focus");
        w.ToggleDetails();await Flush();Stable("reopen evidence");Check(w.Selected=="Primary","Selection preserved across close and reopen");
        if(w.Docked)Check(Math.Abs(w.Metrics[2]-340)<1,"Docked details measure 340 DIP");
        w.CloseDetails();w.Navigate("Security Insights");await Flush();Stable("insights after evidence");
        Check(Math.Abs(w.Metrics[1]-60)<1&&Math.Abs(w.Metrics[3]-32)<1,"Header 60 and footer 32 DIP");
        Check(Math.Abs(w.Metrics[0]-(w.Compact?0:232))<1,"Navigation geometry for current mode");
        Check(w.SizeToContent==SizeToContent.Manual,"Window SizeToContent stays Manual");
        File.WriteAllText(Path.Combine(output,"stability.json"),JsonSerializer.Serialize(new{passed=checks,initialOuter=new[]{initial.ActualWidth,initial.ActualHeight},states,limits="Fixed initial window size throughout. No screenshots are generated by this verifier; requested pictures are native window captures."},new JsonSerializerOptions{WriteIndented=true}));
    }
}





