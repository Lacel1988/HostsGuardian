using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
namespace DesignPrototype;

public sealed partial class PrototypeWindow
{
    public DemoStore Store {get;}=new();
    public DemoAccount Account {get;private set;}=new(){Name="observer.demo"};
    public bool SkipLogin {get;set;}
    public string SessionState {get;private set;}="SignedOut";
    public string SettingsTab {get;private set;}="Megjelenés";
    Border? loginOverlay;Border? editorOverlay;
    string? expandedDevice;DemoPolicy? draft;string? editingId;
    readonly DispatcherTimer sessionTimer=new(){Interval=TimeSpan.FromSeconds(5)};
    DateTime lastInput=DateTime.Now,sessionStart=DateTime.Now;
    int idleMinutes=5,sessionMinutes=60;
    bool animations=true;
    public string PolicySearch="",PolicyFilter="Összes";
    public string ActivitySearch="",ActivityDevice="",ActivityDomain="",ActivityUser="",ActivityType="",ActivityScope="",ActivityDecision="",ActivityResult="",ActivityFrom="",ActivityTo="";
    public string LastMessage {get;private set;}="";
    public double? LoginShieldProgress=>loginOverlay==null?null:Descendants(loginOverlay).OfType<ShieldVisual>().FirstOrDefault()?.UnlockProgress;
    public double LoginScrollableHeight=>loginOverlay==null?0:Descendants(loginOverlay).OfType<ScrollViewer>().Select(s=>s.ScrollableHeight).DefaultIfEmpty(0).Max();
    string profile="Kiegyensúlyozott";
    readonly Dictionary<string,bool> noticePreferences=new();
    int retentionHours=72,retentionMB=50;
    readonly string demoPreferences=Path.Combine(AppContext.BaseDirectory,"uat-ui-preferences.json");
    public bool MotionEnabled=>animations&&SystemParameters.ClientAreaAnimation&&!CoreVisual.ReducedMotion;
    void InitializeExperience()
    {
        try{if(savePlacement&&File.Exists(demoPreferences)){var p=JsonSerializer.Deserialize<DemoPreferences>(File.ReadAllText(demoPreferences));if(p!=null){Theme.Apply(p.Light);Loc.English=p.English;animations=p.Animations;}}}catch(Exception e)when(e is IOException or JsonException or UnauthorizedAccessException){}
        CoreVisual.ReducedMotion=!animations||!SystemParameters.ClientAreaAnimation;
        ApplyTheme();
        ShowLogin(false);
        PreviewMouseDown+=(_,_)=>lastInput=DateTime.Now;PreviewKeyDown+=(_,_)=>lastInput=DateTime.Now;
        sessionTimer.Tick+=(_,_)=>EvaluateSession(SessionClock());
        sessionTimer.Start();Closed+=(_,_)=>sessionTimer.Stop();
        bool wasCompact=Compact;Surface.SizeChanged+=(_,_)=>{if(wasCompact!=Compact){wasCompact=Compact;if(loginOverlay!=null)ShowLogin(SessionState=="Locked");}};
        PreviewKeyDown+=(_,e)=>{if(e.Key==Key.Escape&&editorOverlay!=null){CloseModal();e.Handled=true;}};
        SystemParameters.StaticPropertyChanged+=OnSystemMotionChanged;Closed+=(_,_)=>SystemParameters.StaticPropertyChanged-=OnSystemMotionChanged;
    }
    void OnSystemMotionChanged(object? sender,System.ComponentModel.PropertyChangedEventArgs e){if(e.PropertyName==nameof(SystemParameters.ClientAreaAnimation))SetReducedMotion(!animations||!SystemParameters.ClientAreaAnimation);}
    record DemoPreferences(bool Light,bool English,bool Animations);
    void SaveDemoPreferences(){try{File.WriteAllText(demoPreferences,JsonSerializer.Serialize(new DemoPreferences(Theme.Light,Loc.English,animations)));}catch(Exception e)when(e is IOException or UnauthorizedAccessException){LastMessage=e.Message;}}
    void ApplyTheme()
    {
        Surface.Background=new RadialGradientBrush(Ui.Brush("#15314E").Color,Ui.Brush("#080F1D").Color){Center=new Point(.8,.06),GradientOrigin=new Point(.8,.06),RadiusX=.9,RadiusY=.9};
        if(startupOverlay!=null)startupOverlay.Background=new RadialGradientBrush(Ui.Brush("#15314E").Color,Ui.Brush("#080F1D").Color);
        foreach(var c in Descendants(Surface).OfType<CoreVisual>())c.InvalidateVisual();
    }
    public void ChangeTheme(bool light){Theme.Apply(light);ApplyTheme();SaveDemoPreferences();if(SessionState=="Active")BuildPage();else ShowLogin(SessionState=="Locked");WriteStateReceipt();}
    public void ChangeLanguage(bool english){Loc.English=english;RefreshLanguage();SaveDemoPreferences();WriteStateReceipt();}
    void RefreshLanguage()
    {
        foreach(var (name,b) in navigationButtons){if(b.Content is StackPanel row&&row.Children[1] is TextBlock t)t.Text=Loc.T(name);AutomationProperties.SetName(b,Loc.T(name));}
        headerTitle.Text=Loc.T(CurrentView);DetailsButton.Content=Loc.T("Részletek");CloseButton.Content=Loc.T("← Vissza");
        scenarioButton.Content=EngineMode?EngineModeLabel:Loc.Pick("UAT • NINCS KAPCSOLAT","UAT • NOT CONNECTED");
        NavigationButton.ToolTip=Loc.Pick("Navigáció megnyitása vagy bezárása","Open or close navigation");
        if(detailScroll.Content is StackPanel detail&&detail.Children[1] is TextBlock label)label.Text=AnalystName+" / "+Loc.T("Bizonyítékok");
        if(SessionState=="Active")BuildPage();else ShowLogin(SessionState=="Locked");
    }
    void AnimatePage()
    {
        page.BeginAnimation(OpacityProperty,null);page.Opacity=1;
        var move=new TranslateTransform();page.RenderTransform=move;
        if(!MotionEnabled)return;
        page.BeginAnimation(OpacityProperty,new DoubleAnimation(.15,1,TimeSpan.FromMilliseconds(300)),HandoffBehavior.SnapshotAndReplace);
        move.BeginAnimation(TranslateTransform.YProperty,new DoubleAnimation(9,0,TimeSpan.FromMilliseconds(300)){EasingFunction=new CubicEase{EasingMode=EasingMode.EaseInOut}},HandoffBehavior.SnapshotAndReplace);
        int i=0;foreach(FrameworkElement child in page.Children.OfType<Border>().Take(4))child.BeginAnimation(OpacityProperty,new DoubleAnimation(.4,1,TimeSpan.FromMilliseconds(240)){BeginTime=TimeSpan.FromMilliseconds(i++*18)},HandoffBehavior.SnapshotAndReplace);
    }
    public bool DemoLogin(string name,string password){LastMessage="Valódi Engine-hitelesítés szükséges.";return false;}
    async Task RemoveAcceptedLogin(Border accepted)
    {
        accepted.IsHitTestVisible=false;
        await Task.Delay(1100);
        if(loginOverlay==accepted&&SessionState=="Active"){Surface.Children.Remove(accepted);loginOverlay=null;StartStartup(AutoStartupDuration);}
    }
    public void SignOut(string reason="SignedOut"){_=EndEngineSession("Kijelentkeztél. Kérlek, jelentkezz be újra.");}
    public void ShowLogin(bool locked)
    {
        ExitStartup();if(editorOverlay!=null){Surface.Children.Remove(editorOverlay);editorOverlay=null;}
        if(loginOverlay!=null)Surface.Children.Remove(loginOverlay);
        if(locked)SessionState="Locked";else if(SessionState=="Active")SessionState="SignedOut";
        body.Visibility=Visibility.Hidden;page.Children.Clear();panelRequested=drawerOpen=navigationOpen=false;Adapt();
        var form=new StackPanel{MaxWidth=420,Width=Math.Min(420,Math.Max(260,Surface.ActualWidth-64)),HorizontalAlignment=HorizontalAlignment.Center,Margin=new Thickness(24),VerticalAlignment=VerticalAlignment.Center};
        form.Children.Add(Ui.Text("HOSTSGUARDIAN",26,bold:true));form.Children.Add(Ui.Text(locked?Loc.Pick("Zárolt munkamenet","Locked session"):Loc.Pick("Bejelentkezés","Sign in"),22,bold:true));
        form.Children.Add(Ui.Text("Biztonságos bejelentkezés a beállított Linux Engine-re.",14,"#B6C6DA"));
        if(SessionNotice.Length>0)form.Children.Add(Ui.Text(SessionNotice,13,"#FFD58A"));
        form.Children.Add(Ui.Text("Felhasználónév",13));var name=Input("admin","LoginName");name.IsReadOnly=false;form.Children.Add(name);
        form.Children.Add(Ui.Text("Jelszó",13));var password=new PasswordBox{Margin=new Thickness(0,0,0,12)};AutomationProperties.SetAutomationId(password,"LoginPassword");form.Children.Add(password);
        form.Children.Add(Ui.Text(Loc.Pick("Engine-oldali jogosultságok • lejáró munkamenet.","Engine-side authorization • expiring session."),12,"#B6C6DA"));
        var error=Ui.Text("",14,"#FFD58A");form.Children.Add(error);
        Button? submit=null;submit=Ui.Button(locked?"Feloldás":"Bejelentkezés",async()=>await LoginToEngine(name.Text,password.Password,password,error,submit),"LoginSubmit");submit.IsDefault=true;form.Children.Add(submit);
        var options=Actions(("Sötét",()=>ChangeTheme(false),"LoginDark"),("Világos",()=>ChangeTheme(true),"LoginLight"),(Loc.English?"Magyar":"English",()=>ChangeLanguage(!Loc.English),"LoginLanguage"));form.Children.Add(options);form.Children.Add(Actions(("Engine-kapcsolat",ConfigureRemoteConnection,"ConfigureRemote"),("Jelszó visszaállítása",ResetPasswordForm,"ResetPassword")));
        var grid=new Grid();grid.ColumnDefinitions.Add(new(){Width=new GridLength(Compact?0:1,GridUnitType.Star)});grid.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});
        var art=Ui.Stack(new ShieldVisual{Height=310,Margin=new Thickness(20)},Ui.Text(Loc.Pick("A hozzáférés bizalmi határa.","The trust boundary of access."),22,"#9AC5FF",true));art.VerticalAlignment=VerticalAlignment.Center;art.Margin=new Thickness(40);if(Compact)art.Visibility=Visibility.Collapsed;grid.Children.Add(art);
        if(Compact)form.Children.Insert(1,new ShieldVisual{Height=130,HorizontalAlignment=HorizontalAlignment.Center,Width=150,Margin=new Thickness(0,8,0,12)});
        var scroll=new ScrollViewer{Content=form,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};Grid.SetColumn(scroll,1);grid.Children.Add(scroll);
        loginOverlay=new Border{Background=Ui.Brush("#0C1422"),Child=grid};Grid.SetRowSpan(loginOverlay,3);Panel.SetZIndex(loginOverlay,150);Surface.Children.Add(loginOverlay);KeyboardNavigation.SetTabNavigation(loginOverlay,KeyboardNavigationMode.Cycle);Dispatcher.BeginInvoke(()=>name.Focus(),DispatcherPriority.Input);WriteStateReceipt();
    }
    public bool BuildExperiencePage()
    {
        if(SessionState!="Active"&&IsLoaded)return false;
        page.Children.Clear();CurrentTable=null;
        var top=new Grid();top.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});top.ColumnDefinitions.Add(new(){Width=GridLength.Auto});
        top.Children.Add(Ui.Text("HOSTSGUARDIAN  /  "+Loc.Pick("SZINTETIKUS DEMÓ","SYNTHETIC DEMO"),12,"#9AC5FF",true));
        var session=Actions(("Zárolás",()=>ShowLogin(true),"Lock"),("Kijelentkezés",()=>SignOut(),"SignOut"));Grid.SetColumn(session,1);top.Children.Add(session);page.Children.Add(top);
        page.Children.Add(Ui.Text(Loc.T(CurrentView),27,bold:true));
        page.Children.Add(Ui.Text(Account.Name+" • "+Loc.T(Account.Role)+" • "+Loc.T("Biztonságos bejelentkezés a beállított Linux Engine-re."),12,"#B6C6DA"));
        switch(CurrentView)
        {
            case "Áttekintés":page.Children.Add(CoreHero());page.Children.Add(AgentSummary());page.Children.Add(Ui.Text(Loc.Pick("Konfigurált, alkalmazott és igazolt állapot külön kezelve.","Configured, applied and verified states remain separate."),14,"#B6C6DA"));break;
            case "Eszközök":DevicesPage();break;
            case "Domainek és policy":PoliciesPage();break;
            case "Tevékenység":ActivityPage();break;
            case "Security Insights":InsightsPage();break;
            case "Diagnosztika":DiagnosticsPage();break;
            case "Beállítások":SettingsPage();break;
        }
        WriteStateReceipt();return true;
    }
    static WrapPanel Actions(params (string Text,Action Action,string Id)[] actions)
    {var panel=new WrapPanel();foreach(var a in actions){var b=Ui.Button(a.Text,a.Action,a.Id);b.Margin=new Thickness(0,4,8,6);b.VerticalAlignment=VerticalAlignment.Bottom;panel.Children.Add(b);}return panel;}
    static TextBox Input(string value,string id){var t=new TextBox{Text=value,Margin=new Thickness(0,0,10,10),MinWidth=150};AutomationProperties.SetAutomationId(t,id);return t;}
    static FrameworkElement Field(string label,UIElement input){return Ui.Stack(Ui.Text(label,13,"#B6C6DA"),input);}
    static CheckBox Check(string label,bool value,Action<bool> changed,string id)
    {var c=new CheckBox{Content=Loc.T(label),IsChecked=value};AutomationProperties.SetAutomationId(c,id);c.Checked+=(_,_)=>changed(true);c.Unchecked+=(_,_)=>changed(false);return c;}
    DataGrid Table<T>(IEnumerable<T> rows,params (string Header,string Property,double Width)[] columns)
    {
        var grid=new DataGrid{ItemsSource=rows.ToList(),AutoGenerateColumns=false,Height=Compact?230:310,Margin=new Thickness(0,8,0,12)};
        foreach(var c in columns)grid.Columns.Add(new DataGridTextColumn{Header=Loc.T(c.Header),Binding=new Binding(c.Property){StringFormat=c.Property=="Time"?"yyyy-MM-dd HH:mm:ss":null},MinWidth=c.Width,Width=new DataGridLength(c.Width,DataGridLengthUnitType.Pixel),ElementStyle=(Style)Application.Current.FindResource("GridText")});
        if(grid.Items.Count>0)grid.SelectedIndex=0;AutomationProperties.SetAutomationId(grid,"ExperienceTable");CurrentTable=grid;return grid;
    }
    void DevicesPage()
    {
        var rows=Store.Devices.Select(d=>new{d.Id,d.Name,d.Address,d.Identity,d.LastSeen,Counts=$"{Store.ForDevice(d.Id).Count(p=>!p.Global)} / {Store.ForDevice(d.Id).Count(p=>p.Global)}",d.Enforcement}).ToList();
        page.Children.Add(Ui.Text(Loc.Pick("180 eszköz • azonosítás és érvényesülés külön bizonyíték","180 devices • identity and enforcement are separate evidence"),14,"#B6C6DA"));
        var table=Table(rows,("Név","Name",210),("IP-címek","Address",170),("Azonosítás","Identity",155),("Utolsó megfigyelés","LastSeen",170),("Hozzárendelt / Örökölt","Counts",140),("Érvényesülés","Enforcement",140));page.Children.Add(table);
        void Expand(){if(table.SelectedIndex>=0)ExpandDevice(rows[table.SelectedIndex].Id);}
        table.MouseDoubleClick+=(_,_)=>Expand();table.PreviewKeyDown+=(_,e)=>{if(e.Key==Key.Enter){Expand();e.Handled=true;}};
        page.Children.Add(Actions(("Eszköz lenyitása",Expand,"ExpandDevice")));
        if(expandedDevice!=null)
        {
            var d=Store.Devices.First(x=>x.Id==expandedDevice);var content=Ui.Stack(Ui.Text(d.Name+" / "+d.Id,21,bold:true),Ui.Text(Loc.Pick("Demóóra: ","Demo clock: ")+Store.Clock.ToString("yyyy-MM-dd HH:mm"),13,"#B6C6DA"),Ui.Text("Érvényesülés: nem igazolt",14,"#B6C6DA"));
            foreach(var p in Store.ForDevice(d.Id))
            {
                bool? decision=Store.Decision(d.Id,p.Target);string label=Loc.T(decision==null?"Nem meghatározható":decision.Value?"Engedélyezett":"Tiltott");
                var decisionText=Ui.Text((decision==null?"":"● ")+label,17,decision==null?"#B6C6DA":decision.Value?"#8CE0BD":"#FFB4B4",true);
                content.Children.Add(Ui.Card(Ui.Stack(Ui.Text(p.Name+" / "+p.Target,18,bold:true),decisionText,Ui.Text(p.Id+" • "+p.Scope+" • "+p.ScheduleText,13,"#B6C6DA"),Ui.Text(p.Scheduled&&!p.ActiveAt(Store.Clock)?Loc.Pick("Következő időszak: ","Next interval: ")+p.Start+"–"+p.End:Store.Policies.Any(g=>g.Global&&g.Block&&g.Target==p.Target&&g.ActiveAt(Store.Clock))?"A globális tiltás elsőbbséget élvez.":"Nincs aktív tiltás",13,"#B6C6DA"),Actions(("Részletek",()=>ShowPolicyDetails(p),"DevicePolicy"+p.Id),("Szerkesztés",()=>{Navigate("Domainek és policy");OpenPolicy(p.Id);},"EditDevice"+p.Id)))));
            }
            page.Children.Add(Ui.Card(content));
        }
    }
    public void ExpandDevice(string id){expandedDevice=id;BuildPage();AnimatePage();Dispatcher.BeginInvoke(()=>mainScroll.ScrollToBottom(),DispatcherPriority.Loaded);}
    public List<DemoPolicy> FilterPolicies()=>Store.Policies.Where(p=>(p.Name+" "+p.Target+" "+p.Id).Contains(PolicySearch,StringComparison.OrdinalIgnoreCase)).Where(p=>PolicyFilter switch{"Globális"=>p.Global,"Egyéni"=>!p.Global,"Időzített"=>p.Scheduled,_=>true}).ToList();
    void PoliciesPage()
    {
        var search=Input(PolicySearch,"PolicySearch");var controls=Actions(("+ Új szabály",()=>OpenPolicy(null),"NewPolicy"),("Keresés",()=>{PolicySearch=search.Text;BuildPage();},"SearchPolicies"));controls.Children.Insert(0,search);page.Children.Add(controls);
        page.Children.Add(Actions(new[]{"Összes","Globális","Egyéni","Időzített"}.Select(s=>(s,(Action)(()=>{PolicyFilter=s;BuildPage();}),"PolicyFilter"+s)).ToArray()));
        var list=FilterPolicies();var table=Table(list,("Név","Name",200),("Domain vagy csoport","Target",180),("Művelet","ActionText",120),("Hatókör","Scope",180),("Időzítés","ScheduleText",200),("Konfiguráció","Config",160),("Verzió","Version",80));page.Children.Add(table);
        DemoPolicy? SelectedPolicy()=>table.SelectedItem as DemoPolicy;
        page.Children.Add(Actions(("Részletek",()=>{if(SelectedPolicy() is {} p)ShowPolicyDetails(p);},"PolicyDetails"),("Szerkesztés",()=>{if(SelectedPolicy() is {} p)OpenPolicy(p.Id);},"EditPolicy"),("Aktiválás / inaktiválás",()=>{if(SelectedPolicy() is {} p){if(!Store.CanManage(Account)){Message(Loc.T("A módosításhoz Kezelő vagy Adminisztrátor demófiók szükséges."));return;}var copy=p.Copy();copy.Enabled=!copy.Enabled;ShowImpact(copy,p.Id);}},"TogglePolicy")));
        page.Children.Add(Ui.Text("Engine-visszaigazolás: nincs",14,"#B6C6DA"));page.Children.Add(Ui.Text("Érvényesülés: nem igazolt",14,"#B6C6DA"));
    }
    void ShowPolicyDetails(DemoPolicy p)=>Modal(Loc.T("Szabályok")+" / "+p.Id,Ui.Stack(Ui.Text(p.Name,23,bold:true),Ui.Text(p.Target+" • "+p.ActionText+" • "+p.Scope),Ui.Text(p.ScheduleText+" • "+Loc.T("Értesítés (perc)")+": "+p.Notice),Ui.Text($"{p.Creator} → {p.Modifier}\n{p.Created:yyyy-MM-dd HH:mm} → {p.Modified:yyyy-MM-dd HH:mm}\nv{p.Version} / {p.Config}"),Ui.Text("Engine-visszaigazolás: nincs"),Ui.Text("Érvényesülés: nem igazolt"),Ui.Text(Loc.Pick("A domaincsoport lefedettsége nem bizonyított.","Domain-group coverage is not verified."),14,"#B6C6DA")));
    public void OpenPolicyV23(string? id)
    {
        if(!Store.CanManage(Account)){Message(Loc.T("A módosításhoz Kezelő vagy Adminisztrátor demófiók szükséges."));return;}
        if(Account.Role=="Kezelő"&&id!=null&&Store.Policies.Any(p=>p.Id==id&&p.DeviceId!="device-1")){Message(Loc.Pick("A Kezelő demóhatásköre: device-1.","Operator demo scope: device-1."));return;}
        editingId=id;draft=id==null?new DemoPolicy{Name="Új demószabály",Target="example.invalid",DeviceId=Account.Role=="Kezelő"?"device-1":"",Creator=Account.Name}:Store.Policies.Single(p=>p.Id==id).Copy();
        TextBox name=Input(draft.Name,"PolicyName"),target=Input(draft.Target,"PolicyTarget"),device=Input(draft.DeviceId,"PolicyDevice"),days=Input(draft.Days,"PolicyDays"),start=Input(draft.Start,"PolicyStart"),end=Input(draft.End,"PolicyEnd"),notice=Input(draft.Notice.ToString(),"PolicyNotice");
        var content=Ui.Stack(Field("Név",name),Field("Domain vagy csoport",target),Check("Tiltás",draft.Block,v=>draft.Block=v,"PolicyBlock"),Field(Loc.Pick("Eszközazonosító; üres = globális","Device ID; empty = global"),device),Check("Időzített",draft.Scheduled,v=>draft.Scheduled=v,"PolicyScheduled"));
        var times=new WrapPanel();foreach(var x in new[]{Field("Napok (0=vasárnap)",days),Field("Kezdés (HH:mm)",start),Field("Befejezés (HH:mm)",end),Field("Értesítés (perc)",notice)})times.Children.Add(x);content.Children.Add(times);
        var error=Ui.Text("",14,"#FFD58A");content.Children.Add(error);
        content.Children.Add(Actions(("Hatáselőnézet",()=>{
            draft.Name=name.Text.Trim();draft.Target=target.Text.Trim();draft.DeviceId=device.Text.Trim();draft.Days=days.Text.Trim();draft.Start=start.Text.Trim();draft.End=end.Text.Trim();
            if(draft.Name.Length==0||draft.Target.Length==0||draft.DeviceId!=""&&!Store.Devices.Any(d=>d.Id==draft.DeviceId)||!int.TryParse(notice.Text,out int n)||n<0||n>1440||draft.Scheduled&&(!ValidTime(draft.Start)||!ValidTime(draft.End)||draft.Start==draft.End||draft.Days.Split(',').Any(d=>!int.TryParse(d,out var day)||day<0||day>6))){error.Text=Loc.Pick("Ellenőrizd a nevet, célt, eszközt, napokat és az időket.","Check name, target, device, days and times.");return;}draft.Notice=n;ShowImpact(draft,editingId);
        },"PreviewPolicy")));
        Modal(Loc.T("Szerkesztés"),content);
    }
    static bool ValidTime(string s)=>TimeSpan.TryParseExact(s,@"hh\:mm",System.Globalization.CultureInfo.InvariantCulture,out _);
    public void ShowImpact(DemoPolicy policy,string? existing)
    {
        var affected=Store.Devices.Where(d=>policy.AppliesTo(d.Id)).ToList();
        var content=Ui.Stack(Ui.Text(policy.Name,22,bold:true),Ui.Text(policy.Target+" / "+policy.ActionText+" / "+policy.ScheduleText),Ui.Text(Loc.Pick($"Tervezett hatókör: {affected.Count} demóeszköz. Ismert azonosítás: {affected.Count(d=>d.Certain)}; bizonytalan: {affected.Count(d=>!d.Certain)}.",$"Planned scope: {affected.Count} demo devices. Verified identity: {affected.Count(d=>d.Certain)}; uncertain: {affected.Count(d=>!d.Certain)}.")),Ui.Text(Loc.Pick("Várható konfigurációs hatás, nem hálózati bizonyíték. A globális tiltást egyéni engedély nem írja felül.","Expected configuration effect, not network evidence. Device allow does not override global deny.")),Ui.Text("Engine-visszaigazolás: nincs"),Ui.Text("Érvényesülés: nem igazolt"));
        content.Children.Add(Actions(("Mentés a demóba",()=>{if(SavePolicy(policy,existing)){CloseModal();Navigate("Domainek és policy");}else Message(LastMessage);},"ConfirmPolicy")));
        Modal(Loc.T("Hatáselőnézet"),content);
    }
    public bool SavePolicy(DemoPolicy p,string? id)
    {
        if(!EnsureSession()||!Store.CanManage(Account)||(Account.Role=="Kezelő"&&(p.Global||p.Targets.Any(x=>x!="device-1")||(id!=null&&Store.Policies.Any(x=>x.Id==id&&(x.Global||x.Targets.Any(d=>d!="device-1"))))))){LastMessage="Permission denied / demo scope: device-1";Store.Audit(Account.Name,p.Id,"Jogosultság","Elutasítva / demó");return false;}
        if(Store.ValidatePolicy(p) is string error){LastMessage=error;return false;}
        Store.Audit(Account.Name,p.Id,"Kezdeményezés","Fixture");Store.Audit(Account.Name,p.Id,"Jogosultság","Elfogadva / demó");
        var copy=p.Copy();copy.Modifier=Account.Name;copy.Modified=DateTime.Now;
        if(id!=null){int index=Store.Policies.FindIndex(x=>x.Id==id);if(index<0)return false;copy.Id=id;copy.Version=Store.Policies[index].Version+1;Store.Policies[index]=copy;}else Store.Policies.Add(copy);
        Store.Audit(Account.Name,copy.Id,"Konfiguráció","Elfogadva / demó; Engine: nincs visszaigazolás");return true;
    }
    void Modal(string title,UIElement content)
    {
        if(editorOverlay!=null)Surface.Children.Remove(editorOverlay);
        var card=Ui.Card(Ui.Stack(Ui.Text(title,23,bold:true),content,Actions(("Mégse",CloseModal,"CloseModal"))));card.MaxWidth=840;card.Margin=new Thickness(Compact?12:40);card.VerticalAlignment=VerticalAlignment.Center;
        var scroll=new ScrollViewer{Content=card,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};editorOverlay=new Border{Background=Ui.Brush("#0C1422"),Child=scroll};Grid.SetRowSpan(editorOverlay,3);Panel.SetZIndex(editorOverlay,80);Surface.Children.Add(editorOverlay);KeyboardNavigation.SetTabNavigation(editorOverlay,KeyboardNavigationMode.Cycle);
        AnimateElement(card);Dispatcher.BeginInvoke(()=>card.MoveFocus(new TraversalRequest(FocusNavigationDirection.First)),DispatcherPriority.Input);
    }
    void AnimateElement(FrameworkElement e){if(!MotionEnabled)return;var t=new TranslateTransform(12,0);e.RenderTransform=t;t.BeginAnimation(TranslateTransform.XProperty,new DoubleAnimation(0,TimeSpan.FromMilliseconds(190)));e.BeginAnimation(OpacityProperty,new DoubleAnimation(.3,1,TimeSpan.FromMilliseconds(190)));}
    public void CloseModal(){if(editorOverlay!=null){Surface.Children.Remove(editorOverlay);editorOverlay=null;}NavigationButton.Focus();}
    public void Message(string text){LastMessage=text;Modal(Loc.Pick("Tájékoztatás","Information"),Ui.Text(text));}
    public List<DemoEvent> FilterEvents()
    {
        bool Match(string value,string query)=>query.Length==0||value.Contains(query,StringComparison.OrdinalIgnoreCase);
        DateTime.TryParse(ActivityFrom,out var from);DateTime.TryParse(ActivityTo,out var to);
        return Store.Events.Where(e=>Match($"{e.Time} {e.User} {e.Device} {e.Domain} {e.Type} {e.TypeText} {e.Result} {e.ResultText}",ActivitySearch)&&Match(e.Device,ActivityDevice)&&Match(e.Domain,ActivityDomain)&&Match(e.User,ActivityUser)&&Match(e.Type+" "+e.TypeText,ActivityType)&&Match(e.Scope+" "+e.ScopeText,ActivityScope)&&Match(e.Decision+" "+e.DecisionText,ActivityDecision)&&Match(e.Result+" "+e.ResultText,ActivityResult)&&(from==default||e.Time>=from.Date)&&(to==default||e.Time<to.Date.AddDays(1))).ToList();
    }
    void ActivityPageV23()
    {
        var fields=new[]{("Szabad szöveg",ActivitySearch,"ActivitySearch"),("Dátumtól (yyyy-MM-dd)",ActivityFrom,"ActivityFrom"),("Dátumig (yyyy-MM-dd)",ActivityTo,"ActivityTo"),("Eszköz",ActivityDevice,"ActivityDevice"),("Domain",ActivityDomain,"ActivityDomain"),("Felhasználó",ActivityUser,"ActivityUser"),("Eseménytípus",ActivityType,"ActivityType"),("Hatókör",ActivityScope,"ActivityScope"),("Művelet",ActivityDecision,"ActivityDecision"),("Eredmény",ActivityResult,"ActivityResult")};
        var inputs=fields.Select(f=>Input(f.Item2,f.Item3)).ToArray();var form=new WrapPanel();for(int i=0;i<fields.Length;i++){var field=Field(fields[i].Item1,inputs[i]);field.Width=Compact?190:210;form.Children.Add(field);}page.Children.Add(form);
        page.Children.Add(Actions(("Alkalmaz",()=>{var v=inputs.Select(t=>t.Text.Trim()).ToArray();ActivitySearch=v[0];ActivityFrom=v[1];ActivityTo=v[2];ActivityDevice=v[3];ActivityDomain=v[4];ActivityUser=v[5];ActivityType=v[6];ActivityScope=v[7];ActivityDecision=v[8];ActivityResult=v[9];if(v[1]!=""&&!DateTime.TryParse(v[1],out _)||v[2]!=""&&!DateTime.TryParse(v[2],out _)){Message(Loc.Pick("Érvénytelen dátum.","Invalid date."));return;}BuildPage();},"ApplyActivity"),("Törlés / alaphelyzet",()=>{ActivitySearch=ActivityFrom=ActivityTo=ActivityDevice=ActivityDomain=ActivityUser=ActivityType=ActivityScope=ActivityDecision=ActivityResult="";BuildPage();},"ClearActivity")));
        var rows=FilterEvents();page.Children.Add(Ui.Text($"{rows.Count} / {Store.Events.Count} "+Loc.Pick("fixture-esemény","fixture events"),13,"#B6C6DA"));
        var table=Table(rows,("Időpont","Time",170),("Felhasználó","User",150),("Eszköz","Device",130),("Domain","Domain",170),("Eseménytípus","TypeText",140),("Hatókör","ScopeText",130),("Művelet","DecisionText",125),("Eredmény","ResultText",230));page.Children.Add(table);
        page.Children.Add(Actions(("Részletek",()=>{if(table.SelectedItem is DemoEvent e)Modal(Loc.T("Tevékenység"),Ui.Text($"{e.Time:O}\n{e.User}\n{e.Session}\n{e.Device} / {e.Domain}\n{e.TypeText} / {e.ScopeText} / {e.DecisionText}\n{e.ResultText}"));},"ActivityDetails")));
    }
    void InsightsPageV23()
    {
        var end=Store.Clock.Date.AddHours(17);var bins=Enumerable.Range(0,6).Select(i=>{var begin=end.AddHours(i-6);return (Hour:begin,Count:Store.Events.Count(e=>e.Time>=begin&&e.Time<begin.AddHours(1)));}).ToArray();
        page.Children.Add(Ui.Text("Biztonsági áttekintés",24,bold:true));page.Children.Add(Ui.Text("A demó nem igazol tényleges védelmet.",15,"#FFD58A"));
        var cards=new WrapPanel();foreach(var (title,value) in new[]{("Aktív jelzések","3 / fixture"),("Védelmi lefedettség",Loc.T("Nem igazolt")),("Kiemelt kockázatok",Loc.Pick("2 vizsgálati irány","2 investigation paths"))}){var c=Ui.Card(Ui.Stack(Ui.Text(title,14,"#B6C6DA"),Ui.Text(value,23,bold:true)));c.Width=Compact?195:250;c.Margin=new Thickness(0,0,12,12);cards.Children.Add(c);}page.Children.Add(cards);
        page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Hálózati aktivitás",19,bold:true),Ui.Text(Loc.Pick("Utolsó 6 órás fixture • esemény / óra • nem élő DNS-mérés","Last 6 fixture hours • events / hour • not live DNS measurement"),13,"#B6C6DA"),new TrendVisual{Height=105,Values=bins.Select(b=>b.Count).ToArray()},Ui.Text(string.Join("  •  ",bins.Select(b=>$"{b.Hour:HH:mm}  {b.Count}")),12,"#B6C6DA"))));
        page.Children.Add(AgentSummary());
        page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Loc.T("Bizonyosság")+" ≠ "+Loc.T("Súlyosság"),18,bold:true),Ui.Text(Loc.Pick("Bizonyított tény: a fixture 600 eseményt tartalmaz. Következtetés: eltérő upstream mintázat. Hipotézis: resolver-eltérés. Ismeretlen: eszközszintű enforcement. Egyik sem igazol megerősített támadást.","Verified fact: the fixture contains 600 events. Inference: differing upstream patterns. Hypothesis: resolver variance. Unknown: device-level enforcement. None confirms an attack."),14,"#B6C6DA"),Actions(("Diagnosztika",()=>Navigate("Diagnosztika"),"InsightsDiagnostics")))));
    }
    void DiagnosticsPageV23()
    {
        page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Engine-kapcsolat: nincs élő adat","Engine connection: no live data"),23,bold:true),Ui.Text("Engine-visszaigazolás: nincs"),Ui.Text("Érvényesülés: nem igazolt"),Ui.Text("Adatok frissessége: kizárólag beépített fixture.",14,"#B6C6DA"))));
        foreach(var title in new[]{Loc.Pick("Upstream válaszidő ingadozása","Upstream response-time variance"),Loc.Pick("Policy-visszaigazolás hiánya","Missing policy acknowledgment"),Loc.Pick("Eszközszintű DNS-útvonal ismeretlen","Unknown device-level DNS path")})page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(title,19,bold:true),Ui.Text(Loc.Pick("Bizonyosság: Következtetett / Ismeretlen. Súlyosság: vizsgálandó. Nincs élő AI-elemzés.","Confidence: Inferred / Unknown. Severity: investigate. No live AI analysis."),14,"#B6C6DA"),Actions(("Bizonyítékok",()=>SelectFinding(title),"Diagnostic"+title)))));
    }
    void SettingsPage()
    {
        page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Loc.Pick("Adatforrás: DEMO","Data source: DEMO"),20,bold:true),Actions(("HTTPS mock Engine",async()=>await StartMockEngine(),"StartMockEngine")),Ui.Text(Loc.Pick("A mock helyi, szintetikus HTTPS-adatforrás. LIVE kapcsolódás csak külön Gate 6B jóváhagyás után.","Mock is a local synthetic HTTPS data source. LIVE connection requires separate Gate 6B approval.")))));
        var tabs=new List<string>{"Biztonság és hozzáférés","Védelmi profil","Nyelv","Megjelenés","Értesítések"};if(Store.CanAdmin(Account))tabs.AddRange(new[]{"Naplómegőrzés","Felhasználók és jogosultságok"});
        if(!tabs.Contains(SettingsTab))SettingsTab=tabs[0];
        var settingsGrid=new Grid();settingsGrid.ColumnDefinitions.Add(new(){Width=new GridLength(Compact?178:210)});settingsGrid.ColumnDefinitions.Add(new(){Width=new GridLength(16)});settingsGrid.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});
        var categories=new StackPanel();foreach(var tab in tabs){var button=Ui.Button(tab,()=>{SettingsTab=tab;BuildPage();AnimatePage();},"Settings"+tabs.IndexOf(tab));button.Style=(Style)Application.Current.FindResource("NavButton");button.HorizontalContentAlignment=HorizontalAlignment.Left;button.Content=Ui.Text(tab,13);button.Tag=tab==SettingsTab?"selected":null;button.Margin=new Thickness(0,0,0,5);categories.Children.Add(button);}var rail=Ui.Card(categories);rail.Padding=new Thickness(8);rail.VerticalAlignment=VerticalAlignment.Top;settingsGrid.Children.Add(rail);
        var content=Ui.Stack(Ui.Text(SettingsTab,21,bold:true));
        switch(SettingsTab)
        {
            case "Megjelenés":content.Children.Add(Actions(("Sötét",()=>ChangeTheme(false),"ThemeDark"),("Világos",()=>ChangeTheme(true),"ThemeLight")));content.Children.Add(Ui.Text("Security Core "+(Theme.Light?"Light":"Dark"),18));content.Children.Add(Check("Finom felületi animációk engedélyezése",animations&&!CoreVisual.ReducedMotion,v=>{animations=v;SetReducedMotion(!v||!SystemParameters.ClientAreaAnimation);SaveDemoPreferences();},"Animations"));content.Children.Add(Ui.Text(Loc.Pick("Az operációs rendszer csökkentett mozgását tiszteletben tartjuk.","The operating system reduced-motion preference is respected."),14,"#B6C6DA"));break;
            case "Nyelv":content.Children.Add(Actions(("Magyar",()=>ChangeLanguage(false),"LanguageHu"),("English",()=>ChangeLanguage(true),"LanguageEn"),("Rendszernyelv követése",()=>ChangeLanguage(System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName!="hu"),"LanguageSystem")));content.Children.Add(Ui.Text(Loc.Pick("A szabad szöveges fixture-nevek eredeti nyelven maradhatnak.","Free-text fixture names may retain their original language."),14,"#B6C6DA"));break;
            case "Biztonság és hozzáférés":
                content.Children.Add(Ui.Text(Loc.Pick("Módosítások védelme: fixture-szerepkör ellenőrzés. Nem valódi biztonsági határ.","Change protection: fixture-role checks. Not a real security boundary.")));
                TextBox idle=Input(idleMinutes.ToString(),"IdleMinutes"),expiry=Input(sessionMinutes.ToString(),"SessionMinutes");content.Children.Add(Field(Loc.Pick("Zárolás inaktivitás után (perc)","Lock after inactivity (minutes)"),idle));content.Children.Add(Field(Loc.Pick("Demómunkamenet lejárata (perc)","Demo session expiry (minutes)"),expiry));
                content.Children.Add(Actions(("Alkalmaz",()=>{if(int.TryParse(idle.Text,out var i)&&i>=1&&i<=60&&int.TryParse(expiry.Text,out var x)&&x>=1&&x<=480){idleMinutes=i;sessionMinutes=x;Message(Loc.Pick("Demóbeállítás elmentve a memóriába.","Demo setting saved in memory."));}else Message(Loc.Pick("Érvénytelen időtartam.","Invalid duration."));},"ApplySession"),("Zárolás",()=>ShowLogin(true),"SecurityLock")));
                content.Children.Add(Ui.Text(Loc.Pick("Kritikus műveletek újrahitelesítése: későbbi Engine-szerződés. A prototípus nem küld ilyen műveletet.","Critical-operation reauthentication: future Engine contract. This prototype sends no such operation."),14,"#B6C6DA"));break;
            case "Védelmi profil":content.Children.Add(Actions(new[]{"Alap","Kiegyensúlyozott","Szigorú"}.Select(t=>(t,(Action)(()=>{profile=t;BuildPage();}),"Profile"+t)).ToArray()));content.Children.Add(Ui.Text(Loc.T(profile),21));content.Children.Add(Ui.Text(Loc.Pick("Alap: kevés célzott szabály. Kiegyensúlyozott: általános kiindulás. Szigorú: több korlátozás lehet. Pontos policyhatás még nincs definiálva; nem garantál nagyobb tényleges védelmet.","Basic: a few targeted rules. Balanced: general starting point. Strict: potentially more restrictions. Exact policy effects are not defined; greater actual protection is not guaranteed.")));break;
            case "Értesítések":foreach(var title in new[]{"General","Security","Schedule"}){string label=title switch{"General"=>Loc.Pick("Általános értesítések","General notifications"),"Security"=>Loc.Pick("Biztonsági események","Security events"),_=>Loc.Pick("Közelgő szabályidőzítés","Upcoming rule schedule")};content.Children.Add(Check(label,noticePreferences.GetValueOrDefault(title,true),v=>noticePreferences[title]=v,"Notice"+title));}content.Children.Add(Ui.Text(Loc.Pick("Csak helyi UI-demó. Nincs értesítési csatorna. A konkrét előjelzési idő a szabályban található.","Local UI demo only. No notification channel. Per-policy advance notice is configured in the policy."),14,"#B6C6DA"));break;
            case "Naplómegőrzés":TextBox retention=Input(retentionHours.ToString(),"RetentionHours"),limit=Input(retentionMB.ToString(),"RetentionMiB");content.Children.Add(Field(Loc.Pick("Működési megőrzés (48–168 óra)","Operational retention (48–168 hours)"),retention));content.Children.Add(Field(Loc.Pick("Kiinduló méretkorlát (MB)","Initial size limit (MB)"),limit));content.Children.Add(Ui.Text(Loc.Pick("Tárolóhasználat: ismeretlen. Külön auditmegőrzés szükséges; ezt működési takarítás nem törölheti.","Storage usage: unknown. Audit retention must be separate and immune to operational cleanup.")));content.Children.Add(Actions(("Alkalmaz",()=>{if(int.TryParse(retention.Text,out int hours)&&hours>=48&&hours<=168&&int.TryParse(limit.Text,out int mb)&&mb>=1){retentionHours=hours;retentionMB=mb;Message(Loc.Pick("Tervezési érték memóriába mentve; nincs Engine-tárolás módosítás.","Planning value saved in memory; no Engine storage change."));}else Message(Loc.Pick("Érvénytelen megőrzési érték.","Invalid retention value."));},"RetentionApply")));break;
            case "Felhasználók és jogosultságok":UsersPanel(content);break;
        }
        var settingCard=Ui.Card(content);Grid.SetColumn(settingCard,2);settingsGrid.Children.Add(settingCard);page.Children.Add(settingsGrid);
    }
    void UsersPanelV23(StackPanel content)
    {
        if(!Store.CanAdmin(Account))return;
        var table=Table(Store.Accounts,("Felhasználó","Name",200),("Szerepkör","RoleText",180),("Állapot","State",130));content.Children.Add(table);
        content.Children.Add(Actions(("Új felhasználó",()=>UserEditor(null),"NewUser"),("Szerepkör módosítása",()=>{if(table.SelectedItem is DemoAccount a)UserEditor(a);},"EditUser"),("Hozzáférés visszavonása",()=>{if(table.SelectedItem is DemoAccount a){var error=Store.ChangeRole(Account,a,a.Role,false);if(error!=null)Message(error);else if(a==Account)SignOut("Revoked");else BuildPage();}},"RevokeUser"),("Munkamenet visszavonása",()=>{if(table.SelectedItem is DemoAccount a){Store.Audit(Account.Name,a.Name,"Munkamenet","Visszavonva / demó");if(a==Account)SignOut("Revoked");else Message(Loc.Pick("Demómunkamenet visszavonása naplózva.","Demo session revocation recorded."));}},"RevokeSession")));
        content.Children.Add(Ui.Text(Loc.Pick("Nincs nyilvános regisztráció vagy élő aktiválási titok. Az új fiók csak ebben a futásban létezik; a nyilvános demo-only jelszóval próbálható.","No public registration or live activation secret. New accounts exist only in this run and use the public demo-only password."),14,"#B6C6DA"));
    }
    void UserEditorV23(DemoAccount? account)
    {
        if(!Store.CanAdmin(Account))return;var name=Input(account?.Name??"new.demo","UserName");string role=account?.Role??"Megfigyelő";name.IsReadOnly=account!=null;
        var label=Ui.Text(Loc.T(role));var content=Ui.Stack(Field("Felhasználó",name),label,Actions(new[]{"Megfigyelő","Kezelő","Adminisztrátor"}.Select(r=>(r,(Action)(()=>{role=r;label.Text=Loc.T(r);}),"UserRole"+r)).ToArray()));
        content.Children.Add(Actions(("Mentés a demóba",()=>{if(!Store.CanAdmin(Account))return;if(account==null){if(name.Text.Trim().Length<3||Store.Accounts.Any(a=>a.Name==name.Text.Trim())){Message(Loc.Pick("A név üres vagy már foglalt.","Name is empty or already used."));return;}Store.Accounts.Add(new(){Name=name.Text.Trim(),Role=role});Store.Audit(Account.Name,name.Text,"Felhasználó","Létrehozva / demó");}else{var error=Store.ChangeRole(Account,account,role,true);if(error!=null){Message(error);return;}}CloseModal();BuildPage();},"SaveUser")));Modal(Loc.T("Felhasználók és jogosultságok"),content);
    }
    public void ShowDeveloper()
    {
        if(SessionState!="Active")return;
        var content=Ui.Stack(Ui.Text(Loc.Pick("IZOLÁLT FEJLESZTŐI DEMÓ • nem jogosultságkiosztás","ISOLATED DEVELOPER DEMO • not permission assignment"),14,"#FFD58A"),Actions(("Core Activation 2,5 s",()=>{CloseModal();StartStartup(2.5);},"Dev25"),("Core Activation 4 s",()=>{CloseModal();StartStartup(4);},"Dev4"),("Fázisbemutató",()=>{CloseModal();AdvanceStartupPhase();},"DevPhase"),("Engine unavailable",()=>{CloseModal();SetScenario("EngineUnavailable");},"DevUnavailable"),("15:00",()=>{Store.Clock=new(2026,11,1,15,0,0);CloseModal();BuildPage();},"Clock15"),("17:00",()=>{Store.Clock=new(2026,11,1,17,0,0);CloseModal();BuildPage();},"Clock17"),("Session expiry",()=>SignOut("Expired"),"DevExpire")));
        content.Children.Add(Ui.Text(Loc.Pick("Szerepkör kipróbálása: jelentkezz ki és lépj be a másik rögzített demófiókkal. A login nem oszt szerepkört.","To test another role, sign out and use its fixed demo account. Login does not assign roles."),14,"#B6C6DA"));content.Children.Add(Actions((Loc.Pick("Első admin – koncepció","First admin – concept"),ShowBootstrapConcept,"BootstrapConcept"),(Loc.Pick("Első belépés – koncepció","First sign-in – concept"),ShowActivationConcept,"ActivationConcept"),(Loc.Pick("Automatikus zárolás demóóra","Auto-lock demo clock"),()=>{CloseModal();AdvanceSessionClockForTest(TimeSpan.FromMinutes(6));},"LabAutoLock")));Modal("Developer / fixture lab",content);
    }
}

public sealed class ShieldVisual:FrameworkElement
{
    public static readonly DependencyProperty UnlockProgressProperty=DependencyProperty.Register(nameof(UnlockProgress),typeof(double),typeof(ShieldVisual),new FrameworkPropertyMetadata(0.0,FrameworkPropertyMetadataOptions.AffectsRender));
    public double UnlockProgress {get=>(double)GetValue(UnlockProgressProperty);set=>SetValue(UnlockProgressProperty,value);}
    public void Unlock(){if(CoreVisual.ReducedMotion)UnlockProgress=1;else BeginAnimation(UnlockProgressProperty,new DoubleAnimation(0,1,TimeSpan.FromMilliseconds(650)){EasingFunction=new CubicEase{EasingMode=EasingMode.EaseOut}});}
    readonly DispatcherTimer timer=new(){Interval=TimeSpan.FromMilliseconds(125)};
    double phase;
    public static long Ticks;
    public ShieldVisual()
    {
        IsHitTestVisible=false;
        timer.Tick+=(_,_)=>{if(!IsVisible||CoreVisual.ReducedMotion||!SystemParameters.ClientAreaAnimation){timer.Stop();InvalidateVisual();return;}phase+=.125;Ticks++;InvalidateVisual();};
        Loaded+=(_,_)=>{if(!CoreVisual.ReducedMotion&&SystemParameters.ClientAreaAnimation)timer.Start();};Unloaded+=(_,_)=>timer.Stop();
        IsVisibleChanged+=(_,_)=>{if(IsVisible&&!CoreVisual.ReducedMotion&&SystemParameters.ClientAreaAnimation)timer.Start();else timer.Stop();};
    }
    public void RefreshMotion(){if(IsLoaded&&IsVisible&&!CoreVisual.ReducedMotion&&SystemParameters.ClientAreaAnimation)timer.Start();else timer.Stop();InvalidateVisual();}
    protected override void OnRender(DrawingContext dc)
    {
        double scale=Math.Min(ActualWidth/340,ActualHeight/340);if(scale<=0)return;dc.PushTransform(new TranslateTransform((ActualWidth-340*scale)/2,0));dc.PushTransform(new ScaleTransform(scale,scale));
        var geometry=Geometry.Parse("M 170,24 C 218,60 260,76 298,78 C 300,188 265,264 170,316 C 75,264 40,188 42,78 C 80,76 122,60 170,24 Z");
        dc.DrawGeometry(new LinearGradientBrush(Ui.Brush("#142238").Color,Ui.Brush("#203D60").Color,70),new Pen(Ui.Brush("#74DCFF"),3),geometry);
        dc.PushClip(geometry);var random=new Random(22);var points=Enumerable.Range(0,40).Select(_=>new Point(40+random.NextDouble()*260,30+random.NextDouble()*290)).ToArray();
        foreach(var a in points){foreach(var b in points.Where(b=>(b-a).Length<65))dc.DrawLine(new Pen(Ui.Brush("#365571"),.8),a,b);dc.PushOpacity(CoreVisual.ReducedMotion?1:.6+.4*(.5+.5*Math.Sin(phase*.9+a.Y*.025)));dc.DrawEllipse(Ui.Brush("#9AC5FF"),null,a,2.2,2.2);dc.Pop();}dc.Pop();
        // One rigid U-shaped shackle: yaw around the retained leg's vertical axis.
        // Project the same geometry through depth; never move its control points independently.
        double open=UnlockProgress,lift=12*Math.Clamp(open/.2,0,1),yaw=Math.Clamp((open-.15)/.85,0,1)*Math.PI*.75;
        Point ProjectShackle(Point p){double d=p.X-138,z=d*Math.Sin(yaw),perspective=400/(400+z);return new Point(138+d*Math.Cos(yaw)*perspective,155+(p.Y-155-lift)*perspective);}
        var shacklePoints=new List<Point>{new(138,155),new(138,133)};
        for(int i=1;i<=32;i++){double t=i/32.0,u=1-t;shacklePoints.Add(new Point(u*u*u*138+3*u*u*t*138+3*u*t*t*202+t*t*t*202,u*u*u*133+3*u*u*t*87+3*u*t*t*87+t*t*t*133));}shacklePoints.Add(new Point(202,155));
        var lockPath=new StreamGeometry();using(var shape=lockPath.Open()){shape.BeginFigure(ProjectShackle(shacklePoints[0]),false,false);foreach(var p in shacklePoints.Skip(1))shape.LineTo(ProjectShackle(p),true,false);}
        var shacklePen=new Pen(Ui.Brush("#74DCFF"),9){StartLineCap=PenLineCap.Round,EndLineCap=PenLineCap.Round};dc.DrawLine(shacklePen,new Point(138,155),ProjectShackle(new Point(138,155)));dc.DrawGeometry(null,shacklePen,lockPath);
        dc.DrawRoundedRectangle(Ui.Brush("#9AC5FF"),null,new Rect(125,150,90,75),7,7);dc.DrawEllipse(Ui.Brush("#142238"),null,new Point(170,178),7,7);dc.DrawLine(new Pen(Ui.Brush("#142238"),5),new Point(170,180),new Point(170,201));
        dc.DrawEllipse(null,new Pen(Ui.Brush("#86A8D3"),1),new Point(170,326),140,10);
        double angle=CoreVisual.ReducedMotion?0:phase*.24;for(int i=0;i<3;i++){double a=angle+i*Math.PI*2/3;dc.DrawEllipse(Ui.Brush("#74DCFF"),null,new Point(170+140*Math.Cos(a),326+10*Math.Sin(a)),3.2,1.8);}dc.Pop();dc.Pop();
    }
}
public sealed class TrendVisual:FrameworkElement
{
    public int[] Values {get;set;}=new[]{0,0,0,0,0,0};
    protected override void OnRender(DrawingContext dc)
    {
        var values=Values;for(int i=0;i<6;i++){double x=i*ActualWidth/6,h=values[i]/(double)Math.Max(1,values.Max())*(ActualHeight-22);dc.DrawRoundedRectangle(Ui.Brush("#9AC5FF"),null,new Rect(x+8,ActualHeight-h-12,Math.Max(4,ActualWidth/6-20),h),3,3);}dc.DrawLine(new Pen(Ui.Brush("#86A8D3"),1),new Point(0,ActualHeight-10),new Point(ActualWidth,ActualHeight-10));
    }
}


