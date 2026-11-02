using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
namespace DesignPrototype;

public static class DaySelection
{
    public static bool TryParse(string input,out HashSet<int> days)
    {
        days=new();if(string.IsNullOrWhiteSpace(input))return false;
        foreach(var segment in input.Replace('–','-').Split(','))
        {
            var parts=segment.Trim().Split('-',StringSplitOptions.TrimEntries);
            if(parts.Length==1){if(!int.TryParse(parts[0],out int value)||value<0||value>6)return false;days.Add(value);}
            else if(parts.Length==2){if(!int.TryParse(parts[0],out int start)||!int.TryParse(parts[1],out int end)||start<0||end>6||start>end)return false;for(int day=start;day<=end;day++)days.Add(day);}
            else return false;
        }
        return days.Count>0;
    }
}

public sealed partial class DemoStore
{
    public IEnumerable<DemoEvent> NetworkEvents=>Events.Where(e=>e.Domain.Length>0);
    public static readonly HashSet<string> Roles=new(){"Megfigyelő","Kezelő","Adminisztrátor"};
    public string? CreateAccount(DemoAccount actor,string name,string role,out DemoAccount? created)
    {
        created=null;
        if(!CanAdmin(actor))return "Adminisztrátori demójogosultság szükséges / Administrator demo role required";
        name=name.Trim();
        if(name.Length<3||name.Any(c=>!char.IsLetterOrDigit(c)&&c is not '.' and not '-' and not '_'))return "Hiányzó vagy érvénytelen felhasználónév / Missing or invalid username";
        if(!Roles.Contains(role))return "Érvénytelen szerepkör / Invalid role";
        if(Accounts.Any(a=>a.Name.Equals(name,StringComparison.OrdinalIgnoreCase)))return "A felhasználónév már foglalt / Duplicate username";
        created=new(){Name=name,Role=role};Accounts.Add(created);Audit(actor.Name,name,"Felhasználó létrehozása","Elfogadva / demó");return null;
    }
    public string? RevokeSessions(DemoAccount actor,DemoAccount target)
    {
        if(!CanAdmin(actor)||!Accounts.Contains(target))return "Jogosultság megtagadva / Permission denied";
        target.SessionEpoch++;Audit(actor.Name,target.Name,"Munkamenet visszavonása","Elfogadva / demó");return null;
    }
    public string? RemoveAccount(DemoAccount actor,DemoAccount target)
    {
        if(!CanAdmin(actor))return "Jogosultság megtagadva / Permission denied";
        var error=ChangeRole(actor,target,target.Role,false);if(error!=null)return error;
        target.SessionEpoch++;Accounts.Remove(target);Audit(actor.Name,target.Name,"Fiók törlése","Elfogadva / demó");return null;
    }
    public string? ValidatePolicy(DemoPolicy p)
    {
        if(string.IsNullOrWhiteSpace(p.Name)||string.IsNullOrWhiteSpace(p.Target))return "Hiányzó szabálynév vagy cél / Missing policy name or target";
        if(p.Targets.Any(id=>!Devices.Any(d=>d.Id==id)))return "Ismeretlen eszköz / Unknown device";
        if(p.Notice<0||p.Notice>1440)return "Érvénytelen értesítési idő / Invalid notification time";
        return p.ScheduleError();
    }
}

public sealed partial class PrototypeWindow
{
    int currentSessionEpoch=0;
    public Func<DateTime> SessionClock {get;set;}=()=>DateTime.Now;
    public string SessionNotice {get;private set;}="";
    public void EvaluateSession(DateTime now)
    {
        if(SessionState!="Active")return;
        if(!Account.Active||!Store.Accounts.Contains(Account)||Account.SessionEpoch!=currentSessionEpoch){SessionNotice=Loc.Pick("A demómunkamenetet visszavonták.","The demo session has been revoked.");SignOut("Revoked");return;}
        if((now-sessionStart).TotalMinutes>=sessionMinutes){SessionNotice=Loc.Pick("A demómunkamenet lejárt.","The demo session has expired.");SignOut("Expired");return;}
        if((now-lastInput).TotalMinutes>=idleMinutes){SessionNotice=Loc.Pick("Automatikus zárolás inaktivitás miatt.","Automatically locked after inactivity.");ShowLogin(true);}
    }
    public bool EnsureSession(){EvaluateSession(SessionClock());return SessionState=="Active";}
    public void AdvanceSessionClockForTest(TimeSpan elapsed){var now=DateTime.Now;SessionClock=()=>now+elapsed;}
    public void ResetSessionClock(){SessionClock=()=>DateTime.Now;}
    public void SelectSettingsCategory(string category){SettingsTab=category;Navigate("Beállítások");}
    void UsersPanel(StackPanel content)
    {
        if(!Store.CanAdmin(Account))return;
        var table=Table(Store.Accounts,("Felhasználó","Name",180),("Szerepkör","RoleText",145),("Állapot","State",100));content.Children.Add(table);
        content.Children.Add(Actions(("Új felhasználó",()=>UserEditor(null),"NewUser"),("Szerepkör módosítása",()=>{if(table.SelectedItem is DemoAccount a)UserEditor(a);},"EditUser"),
            ("Hozzáférés visszavonása",()=>{if(!EnsureSession())return;if(table.SelectedItem is DemoAccount a){var error=Store.ChangeRole(Account,a,a.Role,false);if(error!=null)Message(error);else{EvaluateSession(SessionClock());if(SessionState=="Active")BuildPage();}}},"RevokeUser"),
            ("Munkamenet visszavonása",()=>{if(!EnsureSession())return;if(table.SelectedItem is DemoAccount a){var error=Store.RevokeSessions(Account,a);if(error!=null)Message(error);else{EvaluateSession(SessionClock());if(SessionState=="Active")Message(Loc.Pick("A meglévő demómunkamenetek érvénytelenítve; új bejelentkezés engedélyezett.","Existing demo sessions invalidated; a new login is allowed."));}}},"RevokeSession"),
            (Loc.Pick("Fiók törlése a demóból","Remove demo account"),()=>{if(!EnsureSession())return;if(table.SelectedItem is DemoAccount a){var error=Store.RemoveAccount(Account,a);if(error!=null)Message(error);else{EvaluateSession(SessionClock());if(SessionState=="Active")BuildPage();}}},"DeleteDemoAccount")));
        content.Children.Add(Ui.Text(Loc.Pick("Csak memóriabeli fiókok. Nyilvános demójelszó: demo-only; nincs valódi aktiválás. A meglévő munkamenet visszavonása a fiókot nem törli.","In-memory accounts only. Public demo password: demo-only; no real activation. Revoking sessions does not delete the account."),13,"#B6C6DA"));
    }
    public void UserEditor(DemoAccount? account)
    {
        if(!EnsureSession()||!Store.CanAdmin(Account)){Message(Loc.Pick("Jogosultság megtagadva: adminisztrátori demófiók szükséges.","Permission denied: administrator demo account required."));return;}
        var name=Input(account?.Name??"new.demo","UserName");name.IsReadOnly=account!=null;string role=account?.Role??"Megfigyelő";
        var selected=Ui.Text(Loc.T(role),17,"#9AC5FF",true);var error=Ui.Text("",14,"#FFD58A");
        var content=Ui.Stack(Field("Felhasználó",name),selected,Actions(DemoStore.Roles.Select(r=>(r,(Action)(()=>{role=r;selected.Text=Loc.T(r);}),"UserRole"+r)).ToArray()),error);
        content.Children.Add(Actions(("Mentés a demóba",()=>
        {
            if(!EnsureSession())return;
            string? failure=account==null?Store.CreateAccount(Account,name.Text,role,out _):Store.ChangeRole(Account,account,role,true);
            if(failure!=null){error.Text=failure;return;}
            CloseModal();SettingsTab="Felhasználók és jogosultságok";BuildPage();
        },"SaveUser")));
        content.Children.Add(Ui.Text(Loc.Pick("Demó: az új fiók azonnal kipróbálható a demo-only jelszóval, csak ebben a futásban. A későbbi egyszer használatos aktiválás külön koncepció.","Demo: new accounts can sign in with demo-only during this run. Future one-time activation is a separate concept."),13,"#B6C6DA"));
        Modal(account==null?Loc.T("Új felhasználó"):Loc.T("Szerepkör módosítása"),content);
    }
    public void ShowBootstrapConcept()
    {
        Modal(Loc.Pick("Első adminisztrátor – KIZÁRÓLAG KONCEPCIÓ","First administrator – CONCEPT ONLY"),Ui.Stack(
            Ui.Text(Loc.Pick("1. Helyi, jogosult Engine-telepítő indítja a bootstrapot.\n2. Az első admin egyszer hozható létre.\n3. Az Engine tartós lezárást rögzít; újraindítás nem nyitja újra.\n4. Helyreállítás külön helyi jogosultsággal, ellenőrzött recovery-eljárással és auditnyommal.","1. An authorized local Engine installer starts bootstrap.\n2. The first administrator is created once.\n3. Engine persists closure; restarting cannot reopen it.\n4. Recovery requires separate local authorization, a verified recovery procedure and an audit trail.")),
            Ui.Text(Loc.Pick("Nincs bootstrap-végrehajtás, új admin vagy recovery-fájlmódosítás.","No bootstrap execution, new real administrator or recovery-file change."),14,"#FFD58A")));
    }
    public void ShowActivationConcept()
    {
        Modal(Loc.Pick("Első belépés – KIZÁRÓLAG KONCEPCIÓ","First sign-in – CONCEPT ONLY"),Ui.Stack(Ui.Text(Loc.Pick("Admin létrehozza a fiókot → rövid életű, egyszer használatos helyi aktiválás → saját jelszó beállítása → szerveroldali aktiválás és audit. Nem kötelező e-mail vagy felhő.","Admin creates account → short-lived, single-use local activation → personal password setup → server-side activation and audit. Email or cloud is not mandatory.")),Ui.Text(Loc.Pick("Ez a képernyő nem ad ki aktiváló titkot és nem kér valódi jelszót.","This screen issues no activation secret and asks for no real password."),14,"#FFD58A")));
    }
}
