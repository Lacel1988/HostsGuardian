using System.Windows;
using System.Windows.Media;
using System.Globalization;
namespace DesignPrototype;

public static class Theme
{
    public static bool Light {get;private set;}
    static readonly Dictionary<string,SolidColorBrush> brushes=new();
    sealed class ColorToken:System.ComponentModel.INotifyPropertyChanged
    {
        Color color; public Color Color {get=>color;set{color=value;PropertyChanged?.Invoke(this,new(nameof(Color)));}}
        public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    }
    static readonly Dictionary<string,ColorToken> tokens=new();
    public static void Initialize()=>Apply(false);
    public static void Apply(bool light)
    {
        Light=light;
        var dict=(ResourceDictionary)Application.LoadComponent(new Uri(light?"ThemeLight.xaml":"ThemeDark.xaml",UriKind.Relative));
        var oldBrushes=brushes.ToDictionary(x=>x.Key,x=>x.Value);
        foreach(string key in dict.Keys)
        {
            var value=((SolidColorBrush)dict[key]).Color;
            var brush=new SolidColorBrush(value);brush.Freeze();brushes[key]=brush;
            Application.Current.Resources[key]=brushes[key];
        }
        void Rebind(DependencyObject obj)
        {
            var locals=obj.GetLocalValueEnumerator();var replacements=new List<(DependencyProperty,string)>();
            while(locals.MoveNext()){var entry=locals.Current;if(entry.Value is SolidColorBrush b){var key=oldBrushes.FirstOrDefault(x=>ReferenceEquals(x.Value,b)).Key;if(key!=null)replacements.Add((entry.Property,key));}}
            foreach(var (property,key) in replacements)obj.SetValue(property,brushes[key]);
            for(int i=0;i<System.Windows.Media.VisualTreeHelper.GetChildrenCount(obj);i++)Rebind(System.Windows.Media.VisualTreeHelper.GetChild(obj,i));
        }
        foreach(Window w in Application.Current.Windows)Rebind(w);
        foreach(var (key,hex) in new[]{("Text","#F2F6FC"),("Muted","#B6C6DA"),("Accent","#9AC5FF")})
            if(Application.Current.Resources[key] is SolidColorBrush b&&!b.IsFrozen)b.Color=Brush(hex).Color;
    }
    public static SolidColorBrush Brush(string hex)
    {
        string key="C"+hex.TrimStart('#').ToUpperInvariant();
        return brushes.TryGetValue(key,out var b)?b:new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
    }
}
public static class Loc
{
    public static bool English;
    public static readonly Dictionary<string,string> Strings=new()
    {
        ["FIGYELMEZTETÉS"]="WARNING",["INFORMÁCIÓ"]="INFORMATION",["Érvényesülés"]="Enforcement",["Szerepkör"]="Role",["Állapot"]="State",["Hozzárendelt / Örökölt"]="Assigned / Inherited",["Konfiguráció"]="Configuration",
        ["Áttekintés"]="Overview",["Eszközök"]="Devices",["Domainek és policy"]="Domains & policy",["Tevékenység"]="Activity",["Diagnosztika"]="Diagnostics",["Beállítások"]="Settings",
        ["Részletek"]="Details",["← Vissza"]="← Back",["Bizonyítékok"]="Evidence",["Bejelentkezés"]="Sign in",["Felhasználónév"]="Username",["Jelszó"]="Password",["Kijelentkezés"]="Sign out",["Zárolás"]="Lock",["Feloldás"]="Unlock",
        ["Biztonság és hozzáférés"]="Security & access",["Védelmi profil"]="Protection profile",["Nyelv"]="Language",["Megjelenés"]="Appearance",["Értesítések"]="Notifications",["Naplómegőrzés"]="Log retention",["Felhasználók és jogosultságok"]="Users & permissions",
        ["Sötét"]="Dark",["Világos"]="Light",["Magyar"]="Hungarian",["Rendszernyelv követése"]="Follow system language",["Finom felületi animációk engedélyezése"]="Enable subtle interface animations",
        ["+ Új szabály"]="+ New rule",["Keresés"]="Search",["Szűrés"]="Filter",["Összes"]="All",["Globális"]="Global",["Egyéni"]="Device-specific",["Időzített"]="Scheduled",["Engedélyezett"]="Allowed",["Tiltott"]="Blocked",["Nem meghatározható"]="Undetermined",["Következtetett"]="Inferred",["Bizonyított tény"]="Verified fact",["Hipotézis"]="Hypothesis",["Ismeretlen"]="Unknown",
        ["Szerkesztés"]="Edit",["Hatáselőnézet"]="Impact preview",["Mentés a demóba"]="Save to demo",["Mégse"]="Cancel",["Aktiválás / inaktiválás"]="Activate / deactivate",["Név"]="Name",["Domain vagy csoport"]="Domain or group",["Művelet"]="Action",["Hatókör"]="Scope",["Napok (0=vasárnap)"]="Days (0=Sunday)",["Kezdés (HH:mm)"]="Start (HH:mm)",["Befejezés (HH:mm)"]="End (HH:mm)",["Értesítés (perc)"]="Notification (minutes)",["Tiltás"]="Block",["Engedélyezés"]="Allow",["Állandó"]="Permanent",["Időzítés"]="Schedule",
        ["Aktív jelzések"]="Active findings",["Védelmi lefedettség"]="Protection coverage",["Kiemelt kockázatok"]="Key risks",["Hálózati aktivitás"]="Network activity",["Nem igazolt"]="Not verified",["Szintetikus demó • nincs élő kapcsolat"]="Synthetic demo • no live connection",
        ["Eszköz lenyitása"]="Expand device",["Szabályok"]="Policies",["Örökölt"]="Inherited",["Hozzárendelt"]="Assigned",["Hozzáférési döntés"]="Access decision",["Engine-visszaigazolás: nincs"]="Engine acknowledgment: none",["Érvényesülés: nem igazolt"]="Enforcement: not verified",
        ["Kezelő"]="Operator",["Megfigyelő"]="Observer",["Adminisztrátor"]="Administrator",["Új felhasználó"]="New user",["Szerepkör módosítása"]="Change role",["Hozzáférés visszavonása"]="Revoke access",["Munkamenet visszavonása"]="Revoke session",["Aktív"]="Active",["Inaktív"]="Inactive",
        ["Dátumtól (yyyy-MM-dd)"]="From date (yyyy-MM-dd)",["Dátumig (yyyy-MM-dd)"]="To date (yyyy-MM-dd)",["Eszköz"]="Device",["Domain"]="Domain",["Felhasználó"]="User",["Eseménytípus"]="Event type",["Eredmény"]="Result",["Szabad szöveg"]="Free text",["Alkalmaz"]="Apply",["Törlés / alaphelyzet"]="Clear filters",
        ["Alap"]="Basic",["Kiegyensúlyozott"]="Balanced",["Szigorú"]="Strict",["Demó hitelesítés"]="Demo authentication",["Kizárólag fixture-adatok; nem valódi védelem."]="Fixture data only; no real protection.",
        ["A módosításhoz Kezelő vagy Adminisztrátor demófiók szükséges."]="An Operator or Administrator demo account is required to modify policies.",
        ["Hibás demófiók vagy demójelszó."]="Invalid demo account or demo password.",
        ["Biztonsági áttekintés"]="Security overview",["A demó nem igazol tényleges védelmet."]="The demo does not verify actual protection.",
        ["Utolsó megfigyelés"]="Last observation",["Azonosítás"]="Identification",["IP-címek"]="IP addresses",["Verzió"]="Version",["Időpont"]="Timestamp",["Célpont"]="Target",["Típus"]="Type",["Bizonyosság"]="Confidence",["Súlyosság"]="Severity",
        ["Adatok frissessége: kizárólag beépített fixture."]="Freshness: built-in fixture only.", ["Következő vizsgálat: azonos időablak méréseinek összevetése."]="Next investigation: compare measurements from the same time window.",
        ["Minden nap 16:00–19:00"]="Every day 16:00–19:00",["Következő tiltás: 16:00–19:00"]="Next block: 16:00–19:00",["Nincs aktív tiltás"]="No active block",["A globális tiltás elsőbbséget élvez."]="Global deny takes precedence.",
        ["Bizonyítékok és korlátok"]="Evidence and limitations",["Összes megállapítás →"]="All findings →",["Felület megnyitása"]="Open interface",
        ["Átlátható rendszerfelügyelet."]="Transparent system oversight.", ["Az eszközszintű DNS-lefedettség nincs igazolva."]="Device-level DNS coverage is not verified.",
        ["A bemutatott Engine-fixture szűrése aktív"]="The sample Engine fixture shows active filtering",["Upstream késleltetés: további vizsgálat javasolt"]="Upstream latency: further investigation recommended"
    };
    static Loc(){foreach(var (hu,en) in new[]{("Megfigyelés","Observation"),("Konfiguráció","Configuration"),("Fixture / nem igazolt","Fixture / not verified"),("AI BIZTONSÁGI ELEMZŐ / BIZONYÍTÉKOK","AI SECURITY ANALYST / EVIDENCE"),("Hozzáférési döntés","Access decision"),("Eseménytípus","Event type"),("Kiválasztás","Select")})Strings[hu]=en;}
    public static string T(string s)=>English&&Strings.TryGetValue(s,out var e)?e:s switch{"INFERRED"=>English?"Inferred":"Következtetett","UNKNOWN"=>English?"Unknown":"Ismeretlen","HYPOTHESIS"=>English?"Hypothesis":"Hipotézis",_=>s};
    public static string Pick(string hu,string en)=>English?en:hu;
}
public sealed class DemoPolicy
{
    public string Id {get;set;}=Guid.NewGuid().ToString("N")[..8];
    public string Name {get;set;}=""; public string Target {get;set;}="";
    public bool Block {get;set;}=true; public string DeviceId {get;set;}="";
    public string[] DeviceIds {get;set;}=Array.Empty<string>();
    public IReadOnlyList<string> Targets=>DeviceIds.Length>0?DeviceIds:DeviceId.Length>0?new[]{DeviceId}:Array.Empty<string>();
    public bool Global=>Targets.Count==0;
    public bool AppliesTo(string id)=>Global||Targets.Contains(id);
    public bool Enabled {get;set;}=true; public bool Scheduled {get;set;}
    public string Days {get;set;}="0,1,2,3,4,5,6"; public string Start {get;set;}="16:00";public string End {get;set;}="19:00";
    public int Notice {get;set;}=10;public int Version {get;set;}=1;
    public string Creator {get;set;}="admin.demo";public string Modifier {get;set;}="admin.demo";
    public DateTime Created {get;set;}=new(2026,11,1,10,0,0);public DateTime Modified {get;set;}=new(2026,11,1,10,0,0);
    public string Scope=>Global?Loc.T("Globális"):Targets.Count+" "+Loc.Pick("kiválasztott eszköz","selected devices");
    public string ActionText=>Loc.T(Block?"Tiltás":"Engedélyezés");
    public string ScheduleText=>Scheduled?$"{Days} / {Start}–{End}":Loc.T("Állandó");
    public string Config=>Loc.T(Enabled?"Aktív":"Inaktív")+" / "+Loc.Pick("csak demó","demo only");
    public DemoPolicy Copy(){var copy=(DemoPolicy)MemberwiseClone();copy.DeviceIds=DeviceIds.ToArray();return copy;}
    public string? ScheduleError()
    {
        if(!Scheduled)return null;
        if(!TimeSpan.TryParseExact(Start,@"hh\:mm",CultureInfo.InvariantCulture,out var start)||!TimeSpan.TryParseExact(End,@"hh\:mm",CultureInfo.InvariantCulture,out var end)||start==end)return "Érvénytelen időablak / Invalid time interval";
        if(!DaySelection.TryParse(Days,out _))return "Érvénytelen napok: 0–6, pl. 1-3,5. Fordított tartomány nem engedélyezett. / Invalid days: 0–6, e.g. 1-3,5; reversed ranges are not allowed.";
        return null;
    }
    public bool ActiveAt(DateTime clock)
    {
        if(!Enabled)return false;if(!Scheduled)return true;if(ScheduleError()!=null)return false;
        if(!TimeSpan.TryParseExact(Start,@"hh\:mm",CultureInfo.InvariantCulture,out var start)||!TimeSpan.TryParseExact(End,@"hh\:mm",CultureInfo.InvariantCulture,out var end))return false;
        DaySelection.TryParse(Days,out var days);
        if(start<end)return days.Contains((int)clock.DayOfWeek)&&clock.TimeOfDay>=start&&clock.TimeOfDay<end;
        return clock.TimeOfDay>=start?days.Contains((int)clock.DayOfWeek):clock.TimeOfDay<end&&days.Contains((int)clock.AddDays(-1).DayOfWeek);
    }
}
public sealed record DemoDevice(string Id,string Name,string Address,bool Certain)
{
    public string Identity=>Loc.T(Certain?"Bizonyított tény":"Következtetett");
    public string LastSeen=>"2026-11-01 15:30 / fixture";
    public string Enforcement=>Loc.T("Nem igazolt");
}
public sealed class DemoAccount
{
    public int SessionEpoch {get;set;}
    public string Name {get;set;}="";public string Role {get;set;}="Megfigyelő";public bool Active {get;set;}=true;
    public string RoleText=>Loc.T(Role);public string State=>Loc.T(Active?"Aktív":"Inaktív");
}
public sealed record DemoEvent(DateTime Time,string User,string Device,string Domain,string Type,string Scope,string Decision,string Result,string Session)
{
    public string TypeText=>Loc.T(Type);public string ScopeText=>Loc.T(Scope);public string DecisionText=>Loc.T(Decision);public string ResultText=>Loc.T(Result);
}
public sealed partial class DemoStore
{
    public DateTime Clock {get;set;}=new(2026,11,1,17,0,0);
    public List<DemoDevice> Devices {get;}=Enumerable.Range(1,180).Select(i=>new DemoDevice("device-"+i,i==1?"FixtureAlpha készüléke":"Demó eszköz "+i,i%2==0?$"2001:db8::{i:x}":$"192.0.2.{i}",i%3!=0)).ToList();
    public List<DemoAccount> Accounts {get;}=new(){new(){Name="admin.demo",Role="Adminisztrátor"},new(){Name="operator.demo",Role="Kezelő"},new(){Name="observer.demo",Role="Megfigyelő"}};
    public List<DemoPolicy> Policies {get;}=new(){new(){Id="POL-YT-001",Name="FixtureAlpha – YouTube",Target="YouTube",DeviceId="device-1",Scheduled=true},new(){Id="POL-GLOBAL",Name="Globális mintatiltás",Target="example.invalid"},new(){Id="POL-ALLOW",Name="Eszközspecifikus engedély",Target="example.invalid",DeviceId="device-1",Block=false},new(){Id="POL-DOCS",Name="Dokumentáció",Target="docs.example.invalid",Block=false}};
    public List<DemoEvent> Events {get;}=Enumerable.Range(0,600).Select(i=>new DemoEvent(new DateTime(2026,11,1,17,0,0).AddMinutes(-i),i%2==0?"operator.demo":"admin.demo","device-"+(i%180+1),i%2==0?"example.invalid":"YouTube",i%3==0?"Konfiguráció":"Megfigyelés",i%2==0?"Globális":"Egyéni",i%3==0?"Tiltott":"Engedélyezett","Fixture / nem igazolt","demo-session-"+(i%4))).ToList();
    public IEnumerable<DemoPolicy> ForDevice(string id)=>Policies.Where(p=>p.AppliesTo(id));
    public bool? Decision(string device,string target)
    {
        if(!Devices.Any(d=>d.Id==device)||string.IsNullOrWhiteSpace(target))return null;
        var active=ForDevice(device).Where(p=>p.Target==target&&p.ActiveAt(Clock)).ToList();
        if(active.Any(p=>p.Block))return false;
        return true; // Fixture baseline allow; not an Engine verdict.
    }
    public void Audit(string user,string target,string type,string result)=>Events.Insert(0,new(DateTime.Now,user,target,"",type,"Egyéni","",result,"demo-session"));
    public bool CanManage(DemoAccount account)=>Accounts.Contains(account)&&account.Active&&account.Role is "Kezelő" or "Adminisztrátor";
    public bool CanAdmin(DemoAccount account)=>Accounts.Contains(account)&&account.Active&&account.Role=="Adminisztrátor";
    public string? ChangeRole(DemoAccount actor,DemoAccount target,string role,bool active)
    {
        Audit(actor.Name,target.Name,"Jogosultság kezdeményezés","Fixture");
        if(!Roles.Contains(role)||!Accounts.Contains(target))return "Érvénytelen szerepkör vagy fiók / Invalid role or account";
        if(!CanAdmin(actor)){Audit(actor.Name,target.Name,"Jogosultság","Elutasítva / demó");return "Adminisztrátori demójogosultság szükséges.";}
        if(target.Role=="Adminisztrátor"&&target.Active&&(role!="Adminisztrátor"||!active)&&Accounts.Count(a=>a.Active&&a.Role=="Adminisztrátor")==1)return "Az utolsó aktív adminisztrátor nem fokozható le és nem vonható vissza.";
        target.Role=role;target.Active=active;Audit(actor.Name,target.Name,"Jogosultság",active?"Elfogadva / demó":"Visszavonva / demó");return null;
    }
}
