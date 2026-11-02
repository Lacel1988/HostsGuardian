using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace DesignPrototype;

public sealed record DemoRow(string Name,string Address,string State,string Evidence,string Detail);

public sealed partial class PrototypeWindow
{
    public DataGrid? CurrentTable {get;private set;}
    public bool NavigationOverlayOpen=>navigationOpen;
    public double MainViewportWidth=>mainScroll.ActualWidth;
    public bool NavigationOwnsFocus=>navigationBorder.IsKeyboardFocusWithin;
    Border CoreHero()
    {
        var grid=new Grid();grid.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});grid.ColumnDefinitions.Add(new(){Width=new GridLength(Compact?140:265)});
        bool unknown=Scenario is "Missing" or "Stale" or "EngineUnavailable";
        string state=Scenario=="EngineUnavailable"?"Az Engine aktuális állapota nem érhető el":unknown?"Nincs elegendő friss állapotadat":"A bemutatott Engine-fixture szűrése aktív";
        var copy=Ui.Stack(Ui.Text("SECURITY CORE  /  INTELLIGENS RENDSZERMAG",12,"#74DCFF",true),Ui.Text("Átlátható rendszerfelügyelet.",Compact?22:28,bold:true),Ui.Text(state,15,"#B6C6DA"),Ui.Badge(unknown?"UNKNOWN • NEM ÉLŐ ADAT":"VERIFIED • KIZÁRÓLAG DEMÓ",unknown?"#FFD58A":"#8CE0BD"),Ui.Text("Az eszközszintű DNS-lefedettség nincs igazolva.",13,"#FFD58A"));copy.VerticalAlignment=VerticalAlignment.Center;copy.Margin=new Thickness(4,0,12,0);grid.Children.Add(copy);
        var core=new CoreVisual{Height=Compact?138:205};Grid.SetColumn(core,1);grid.Children.Add(core);
        var b=Ui.Card(grid);b.Background=Ui.Brush("#142238");b.BorderBrush=Ui.Brush("#3A7395");return b;
    }
    Border DecorateAgent(Border original)
    {
        var child=original.Child;original.Child=null;
        var grid=new Grid();grid.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});grid.ColumnDefinitions.Add(new(){Width=new GridLength(54)});grid.Children.Add(child);
        var motif=new CoreVisual{Minimal=true,Width=48,Height=50,VerticalAlignment=VerticalAlignment.Top,RenderTransformOrigin=new Point(.5,.5),RenderTransform=new ScaleTransform(1,1)};Grid.SetColumn(motif,1);grid.Children.Add(motif);original.Child=grid;
        void React(bool active){if(CoreVisual.ReducedMotion)return;var transform=(ScaleTransform)motif.RenderTransform;transform.BeginAnimation(ScaleTransform.ScaleXProperty,new DoubleAnimation(active?1.07:1,TimeSpan.FromMilliseconds(160)));transform.BeginAnimation(ScaleTransform.ScaleYProperty,new DoubleAnimation(active?1.07:1,TimeSpan.FromMilliseconds(160)));}
        original.MouseEnter+=(_,_)=>React(true);original.MouseLeave+=(_,_)=>React(false);original.IsKeyboardFocusWithinChanged+=(_,_)=>React(original.IsKeyboardFocusWithin);return original;
    }
    bool BuildRichPage()
    {
        CurrentTable=null;
        if(CurrentView is "Áttekintés" or "Security Insights")return false;
        page.Children.Add(Ui.Text(CurrentView,28,bold:true));
        page.Children.Add(Ui.Text("SECURITY CORE  /  "+(Scenario=="Dense"?"SŰRŰ DEMÓADAT":Scenario=="Incident"?"DIAGNOSZTIKAI INCIDENS":"DEMONSTRÁCIÓ"),12,"#74DCFF",true));
        if(CurrentView=="Beállítások")
        {
            var controls=new WrapPanel();
            foreach(var (text,action,id) in new (string,Action,string)[]{("Core Activation · 2,5 s",()=>StartStartup(2.5),"Startup25"),("Core Activation · 4 s",()=>StartStartup(4),"Startup40"),("Indítási fázisok bemutatása",AdvanceStartupPhase,"StartupPhases"),(CoreVisual.ReducedMotion?"Mozgás engedélyezése":"Csökkentett mozgás",()=>SetReducedMotion(!CoreVisual.ReducedMotion),"ReduceMotion")})
            {var b=Ui.Button(text,action,id);b.Margin=new Thickness(0,0,10,8);controls.Children.Add(b);}
            page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Megjelenés és mozgás",21,bold:true),Ui.Text("Rétegzett, natív WPF-felületek. A dekoratív idővonal nem mér tényleges betöltést.",14,"#B6C6DA"),controls,Ui.Text(CoreVisual.ReducedMotion?"Csökkentett mozgás: aktív. A Core statikus; nincs várakoztatás az animációra.":"Finom mozgás: engedélyezett. A Core csak a látható nézetben frissül.",14,"#74DCFF"))));
            page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Stabil alkalmazáskeret",20,bold:true),Ui.Text("1360×850 DIP alapméret · 720×440 DIP minimum · 232 DIP navigáció · 60/32 DIP sávok. A részletek az ablakon belül nyílnak meg.",14,"#B6C6DA"),Ui.Text("A prototípus saját elhelyezési preferenciát használ. Nincs production konfiguráció, credential vagy szolgáltatásvezérlés.",14,"#B6C6DA"))));return true;
        }
        if(CurrentView=="Diagnosztika")
        {
            page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(Scenario=="Incident"?"Több vizsgálandó jelzés · incidensfixture":"Engine-állapot: nincs élő adat",23,bold:true),Ui.Badge("UNKNOWN • NEM ÉLŐ DIAGNOSZTIKA","#FFD58A"),Ui.Text("A kapcsolati állapot, a policy visszaigazolása és a teljes DNS-lefedettség külön bizonyíték. A bemutatott figyelmeztetések nem valós támadások.",15,"#B6C6DA"))));
            foreach(var (name,level) in new[]{("Upstream válaszidő ingadozása","INFERRED"),("Policy-adat frissessége nem igazolható","UNKNOWN"),("Lehetséges resolver-eltérés","HYPOTHESIS")})page.Children.Add(Ui.Card(Ui.Stack(Ui.Text(level+"  /  FIGYELMEZTETÉS",12,"#FFD58A",true),Ui.Text(name,18,bold:true),Ui.Button("Bizonyítékok és korlátok",()=>SelectFinding(name),"Diagnostic"+level))));return true;
        }
        int count=Scenario=="Dense"?(CurrentView=="Tevékenység"?600:CurrentView=="Eszközök"?180:140):Scenario=="Incident"?36:6;
        var rows=Enumerable.Range(1,count).Select(i=>new DemoRow(
            CurrentView=="Domainek és policy"?$"alrendszer-{i:000}.rendkivul-hosszu-diagnosztikai-pelda.example.invalid":CurrentView=="Tevékenység"?$"14:{i%60:00}:{i*7%60:00} · Diagnosztikai esemény {i:000}":$"{(i%3==0?"Tárgyaló – megfigyelt munkaállomás":"Demó eszköz") } {i:000}",
            i%2==0?$"2001:db8:{i:x4}:abcd:1234:5678:90ab:{i:x4}":$"192.0.2.{i%250+1}",
            i%7==0?"Vizsgálandó":i%5==0?"Nincs friss adat":"Megfigyelt · demó",
            i%7==0?"HYPOTHESIS":i%5==0?"UNKNOWN":"INFERRED",
            $"Szintetikus {i}. megfigyelés. A hosszú magyar diagnosztikai szöveg a megjelenítés vizsgálatát szolgálja; nem igazol személyt, eszközt, DNS-védelmet vagy valós AI-elemzést. Az időbeli mintázat önmagában nem bizonyítja a feltételezett okot.")).ToArray();
        page.Children.Add(Ui.Text($"{count} demonstrációs sor · IPv4/IPv6 példacímek · csak olvasható, virtualizált táblázat",14,"#B6C6DA"));
        var grid=new DataGrid{ItemsSource=rows,AutoGenerateColumns=false,Height=Compact?290:340,Margin=new Thickness(0,8,0,12)};AutomationProperties.SetAutomationId(grid,"DemoDataGrid");AutomationProperties.SetName(grid,CurrentView+" demonstrációs táblázat");
        foreach(var (title,property,width,min) in new[]{(CurrentView=="Domainek és policy"?"DOMAIN / SZÁNDÉK":"NÉV / ESEMÉNY","Name",2.2,210.0),("IP-CÍM / FORRÁS","Address",1.8,190.0),("ÁLLAPOT","State",1.2,145.0),("BIZONYOSSÁG","Evidence",1.0,135.0)})
        {var column=new DataGridTextColumn{Header=title,Binding=new Binding(property),Width=new DataGridLength(width,DataGridLengthUnitType.Star),MinWidth=min,ElementStyle=(Style)Application.Current.FindResource("GridText")};grid.Columns.Add(column);}
        grid.SelectedIndex=0;CurrentTable=grid;
        void Open(){if(grid.SelectedItem is DemoRow row){SelectFinding(row.Name);detailFinding.Text="Súlyosság: információ / demó\nBizonyosság: "+row.Evidence;detailEvidence.Text=row.Detail+"\nCím: "+row.Address+"\nFrissesség: kizárólag beépített fixture.";}}
        grid.MouseDoubleClick+=(_,_)=>Open();grid.PreviewKeyDown+=(_,e)=>{if(e.Key==Key.Enter){Open();e.Handled=true;}};
        page.Children.Add(grid);var open=Ui.Button("Kijelölt sor bizonyítékai →",Open,"OpenSelectedRow");open.HorizontalAlignment=HorizontalAlignment.Left;page.Children.Add(open);
        page.Children.Add(Ui.Text("A hosszú cellák ellipszissel rövidülnek; a teljes név, cím és szöveg a kijelölt sor bizonyítéknézetében olvasható. Nincs policyküldés vagy automatikus beavatkozás.",13,"#B6C6DA"));return true;
    }
}

