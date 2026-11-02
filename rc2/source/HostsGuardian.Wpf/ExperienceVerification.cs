using System.IO;
using System.Text.Json;
using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
namespace DesignPrototype;
public static class ExperienceVerification
{
    static async Task Flush(){await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);await Task.Delay(260);}
    public static async Task Run(PrototypeWindow w,string output)
    {
        Directory.CreateDirectory(output);var passed=new List<string>();var receipts=new List<object>();
        void Check(bool ok,string name){if(!ok)throw new Exception(name);passed.Add(name);}
        await Flush();var size=(w.ActualWidth,w.ActualHeight);w.SetReducedMotion(true);
        Check(w.DemoLogin("admin.demo","wrong")==false,"Invalid demo login rejected");
        Check(w.DemoLogin("admin.demo","demo-only"),"Fixed account authenticates with synthetic credential");await Flush();
        foreach(bool light in new[]{false,true}){w.SignOut();w.ChangeTheme(light);await Flush();Check(w.LoginScrollableHeight<1,"Login fits without vertical scroll, theme "+light);w.DemoLogin("admin.demo","demo-only");}
        foreach(bool light in new[]{false,true})
        {
            w.ChangeTheme(light);await Flush();Check(Theme.Light==light,"Theme switch "+light);
            foreach(var view in new[]{"Áttekintés","Eszközök","Domainek és policy","Tevékenység","Security Insights","Diagnosztika","Beállítások"})
            {w.Navigate(view);await Flush();Check(w.ActualWidth==size.ActualWidth&&w.ActualHeight==size.ActualHeight,"Stable "+view+" theme "+light);receipts.Add(w.Receipt());}
        }
        w.ChangeLanguage(true);await Flush();Check(Loc.T("Beállítások")=="Settings","English localization");w.ChangeLanguage(false);Check(Loc.T("INFERRED")=="Következtetett","Hungarian confidence label");
        var store=w.Store;Check(store.Policies.Select(p=>p.Id).Distinct().Count()==store.Policies.Count,"Unique central policy IDs");
        Check(store.ForDevice("device-1").Count()==4,"Device inherits global and assigned policies");
        Check(store.Decision("device-1","example.invalid")==false,"Global deny defeats individual allow");
        store.Clock=new(2026,11,1,15,0,0);Check(store.Decision("device-1","YouTube")==true,"Scheduled deny inactive before interval");
        store.Clock=new(2026,11,1,17,0,0);Check(store.Decision("device-1","YouTube")==false,"Scheduled deny active in interval");
        store.Clock=new(2026,11,1,19,0,0);Check(store.Decision("device-1","YouTube")==true,"Schedule end exclusive");
        Check(store.Decision("missing","YouTube")==null,"Unknown decision has no allow signal");
        var original=store.Policies[0];var edited=original.Copy();edited.End="20:00";
        Check(w.SavePolicy(edited,original.Id),"Admin saves fixture policy");Check(store.ForDevice("device-1").Single(p=>p.Id==original.Id).End=="20:00","Device and editor share modified policy");
        Check(store.Policies.Single(p=>p.Id==original.Id).Version==2,"Fixture version incremented");
        var added=new DemoPolicy{Name="Test fixture",Target="test.invalid",DeviceId="device-2"};Check(w.SavePolicy(added,null),"New policy created in fixture");Check(store.ForDevice("device-2").Any(p=>p.Id==added.Id),"New policy reflected on target device");
        w.PolicySearch="test.invalid";Check(w.FilterPolicies().Count==1,"Policy text search");w.PolicySearch="";w.PolicyFilter="Időzített";Check(w.FilterPolicies().All(p=>p.Scheduled),"Scheduled policy filter");w.PolicyFilter="Összes";
        w.ActivitySearch="YouTube";Check(w.FilterEvents().Count>0&&w.FilterEvents().All(e=>e.Domain=="YouTube"),"Activity free-text search");w.ActivitySearch="";w.ActivityDevice="device-180";Check(w.FilterEvents().All(e=>e.Device=="device-180"),"Activity device filter");w.ActivityDevice="";
        w.ActivityFrom="2026-11-02";Check(w.FilterEvents().Count==0,"Activity date filter");w.ActivityFrom="";
        w.Navigate("Eszközök");await Flush();Check(w.CurrentTable?.EnableRowVirtualization==true&&w.CurrentTable.Items.Count==180,"Dense device table virtualized");w.ExpandDevice("device-1");await Flush();Check(w.ActualWidth==size.ActualWidth,"Expand device preserves frame");
        w.Navigate("Tevékenység");await Flush();Check(w.CurrentTable!.Items.Count>=600&&w.CurrentTable.EnableRowVirtualization,"Dense activity table virtualized");
        w.Navigate("Diagnosztika");w.SelectFinding("upstream");await Flush();w.Navigate("Eszközök");await Flush();Check(!w.DetailVisible&&w.Selected=="","Cross-page diagnostic context cleared");
        if(w.Compact){double width=w.MainViewportWidth;w.ToggleNavigation();await Flush();Check(w.NavigationOverlayOpen&&w.NavigationOwnsFocus,"Compact overlay focus");Check(width==w.MainViewportWidth,"Compact overlay does not squeeze");w.Navigate("Áttekintés");await Flush();Check(!w.NavigationOverlayOpen,"Navigation selection closes overlay");}
        var admin=store.Accounts[0];Check(store.ChangeRole(admin,admin,"Megfigyelő",true)!=null,"Last active admin demotion denied");Check(store.ChangeRole(admin,admin,"Adminisztrátor",false)!=null,"Last active admin revocation denied");
        w.ShowLogin(true);Check(w.SessionState=="Locked","Manual lock state");Check(!w.DemoLogin("operator.demo","demo-only"),"Locked session rejects another account");Check(w.DemoLogin("admin.demo","demo-only"),"Locked account unlocks");
        w.SignOut();Check(w.SessionState!="Active","Signout removes active session");Check(w.DemoLogin("observer.demo","demo-only"),"Observer fixed demo account");Check(!store.CanManage(w.Account)&&!store.CanAdmin(w.Account),"Observer has no modify/admin capabilities");Check(!w.SavePolicy(new DemoPolicy(),null),"Mutation handler rejects observer");
        w.SignOut();Check(w.DemoLogin("operator.demo","demo-only"),"Operator fixed demo account");Check(store.CanManage(w.Account)&&!store.CanAdmin(w.Account),"Operator modifies but cannot administer");
        w.SignOut();w.DemoLogin("admin.demo","demo-only");w.ExitStartup();w.SetReducedMotion(true);w.Navigate("Áttekintés");await Flush();long ticks=CoreVisual.TickCount;await Task.Delay(1500);Check(CoreVisual.TickCount==ticks,"Reduced motion stops Core timer");
        w.SetReducedMotion(false);w.Navigate("Áttekintés");await Flush();var process=Process.GetCurrentProcess();var cpu=process.TotalProcessorTime;var clock=Stopwatch.StartNew();long memory=process.WorkingSet64;
        var latency=new List<double>();for(int i=0;i<30;i++){var t=Stopwatch.StartNew();w.Navigate(i%2==0?"Eszközök":"Áttekintés");await Flush();latency.Add(t.Elapsed.TotalMilliseconds);await Task.Delay(500);}
        process.Refresh();Check(w.ActualWidth==size.ActualWidth&&w.ActualHeight==size.ActualHeight,"Rapid repeated transitions preserve frame");
        File.WriteAllText(Path.Combine(output,"experience.json"),JsonSerializer.Serialize(new{passed,states=receipts,performance=new{wallSeconds=clock.Elapsed.TotalSeconds,cpuSeconds=(process.TotalProcessorTime-cpu).TotalSeconds,cpuOneCorePercent=(process.TotalProcessorTime-cpu).TotalSeconds/clock.Elapsed.TotalSeconds*100,startWorkingSetMiB=memory/1048576.0,endWorkingSetMiB=process.WorkingSet64/1048576.0,meanNavigationIncluding260msWait=latency.Average(),maxNavigationIncluding260msWait=latency.Max()},dpi=System.Windows.Media.VisualTreeHelper.GetDpi(w).DpiScaleX,limits="Short repeated-transition run, not leak proof or long-duration soak. Native screenshots separate. No production/Engine calls."},new JsonSerializerOptions{WriteIndented=true}));
    }
}
