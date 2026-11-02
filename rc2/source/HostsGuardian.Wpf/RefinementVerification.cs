using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
namespace DesignPrototype;
public static class RefinementVerification
{
    record Result(string Category,string Goal,string Expected,string Actual,string Status,string Evidence);
    static IEnumerable<DependencyObject> Tree(DependencyObject root){yield return root;for(int i=0;i<VisualTreeHelper.GetChildrenCount(root);i++)foreach(var child in Tree(VisualTreeHelper.GetChild(root,i)))yield return child;}
    static async Task Flush(int ms=80){await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);await Task.Delay(ms);}
    static void Click(PrototypeWindow w,string id){var button=PrototypeWindow.Find(w.Surface,id) as Button??throw new Exception("Button not found: "+id);button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));}
    static TextBox Text(PrototypeWindow w,string id)=>(TextBox)(PrototypeWindow.Find(w.Surface,id)??throw new Exception("Input not found: "+id));
    public static async Task Run(PrototypeWindow w,string output)
    {
        Directory.CreateDirectory(output);var rows=new List<Result>();var states=new List<object>();
        string evidence=Path.GetFullPath(Path.Combine(output,"matrix.json"));
        void Check(string category,string goal,string expected,bool actual,string? observed=null)=>rows.Add(new(category,goal,expected,observed??actual.ToString(),actual?"PASS":"FAIL",evidence));
        void NotTested(string category,string goal,string expected,string reason)=>rows.Add(new(category,goal,expected,reason,"NOT TESTED",evidence));
        await Flush();var original=(w.ActualWidth,w.ActualHeight);w.SetReducedMotion(true);w.ResetSessionClock();w.SignOut();
        foreach(var (name,password,label) in new[]{("wrong.demo","demo-only","Nonexistent account"),("admin.demo","wrong","Wrong password"),("","demo-only","Empty username")})Check("Account negative",label,"Login rejected",!w.DemoLogin(name,password));
        Check("Account","Fixed demo administrator","Successful synthetic authentication",w.DemoLogin("admin.demo","demo-only"));
        var store=w.Store;var admin=store.Accounts[0];
        w.SelectSettingsCategory("Felhasználók és jogosultságok");await Flush();Click(w,"NewUser");await Flush();Text(w,"UserName").Text="qa.lifecycle";Click(w,"UserRoleKezelő");Click(w,"SaveUser");await Flush();
        var created=store.Accounts.SingleOrDefault(a=>a.Name=="qa.lifecycle");Check("Account UI","Create account through actual UI handlers","New Operator in shared store",created?.Role=="Kezelő");
        w.SignOut();Check("Account UI","New account signs in","New account authenticates using public demo-only",w.DemoLogin("qa.lifecycle","demo-only"));
        var scoped=new DemoPolicy{Name="Scoped test",Target="test.invalid",DeviceIds=new[]{"device-1"}};
        Check("Role","Operator own scope","device-1 save succeeds",w.SavePolicy(scoped,null));
        Check("Role","Operator other scope","device-2 save rejected",!w.SavePolicy(new(){Name="Other",Target="test.invalid",DeviceIds=new[]{"device-2"}},null));
        Check("Role","Operator global scope","Global save rejected",!w.SavePolicy(new(){Name="Global",Target="test.invalid"},null));
        Check("Role","Non-admin creation","Cannot create administrator",store.CreateAccount(w.Account,"forged.admin","Adminisztrátor",out _)!=null);
        Check("Account negative","Duplicate username","Case-insensitive duplicate rejected",store.CreateAccount(admin,"QA.LIFECYCLE","Megfigyelő",out _)!=null);
        Check("Account negative","Missing required username","Creation rejected",store.CreateAccount(admin,"","Megfigyelő",out _)!=null);
        Check("Account negative","Invalid role","Creation rejected",store.CreateAccount(admin,"invalid.role","SuperUser",out _)!=null);
        Check("Account negative","Invalid role mutation","Existing account unchanged",store.ChangeRole(admin,created!,"SuperUser",true)!=null&&created!.Role=="Kezelő");
        store.ChangeRole(admin,created!,"Megfigyelő",true);w.BuildPage();Check("Role lifecycle","Operator to observer","Same session cannot save",!w.SavePolicy(scoped,null));
        store.ChangeRole(admin,created!,"Kezelő",true);Check("Role lifecycle","Observer to operator","Same account can save scoped policy",w.SavePolicy(scoped,null));
        w.SelectSettingsCategory("Felhasználók és jogosultságok");await Flush();Check("Role UI","Non-admin settings","User administration absent",PrototypeWindow.Find(w.Surface,"NewUser")==null);
        var isolated=new DemoStore();var only=isolated.Accounts[0];
        Check("Administrator protection","Last admin deletion","Rejected; account remains",isolated.RemoveAccount(only,only)!=null&&isolated.Accounts.Contains(only));
        Check("Administrator protection","Last admin demotion","Rejected; role unchanged",isolated.ChangeRole(only,only,"Megfigyelő",true)!=null&&only.Role=="Adminisztrátor");
        Check("Administrator protection","Last admin revocation","Rejected; remains active",isolated.ChangeRole(only,only,"Adminisztrátor",false)!=null&&only.Active);
        isolated.CreateAccount(only,"second.admin","Adminisztrátor",out var second);Check("Administrator protection","Self-demotion with another admin","Allowed and privileges immediately lost",isolated.ChangeRole(only,only,"Megfigyelő",true)==null&&!isolated.CanAdmin(only)&&isolated.CanAdmin(second!));
        store.ChangeRole(admin,created!,created!.Role,false);w.SignOut();Check("Account negative","Inactive account login","Rejected",!w.DemoLogin("qa.lifecycle","demo-only"));store.ChangeRole(admin,created,created.Role,true);w.DemoLogin("qa.lifecycle","demo-only");
        store.RevokeSessions(admin,created);Check("Session","Revoked session mutation","Rejected and session becomes Revoked",!w.SavePolicy(scoped,null)&&w.SessionState=="Revoked");
        Check("Session","New session after revocation","New authentication is possible for active account",w.DemoLogin("qa.lifecycle","demo-only"));
        w.ShowLogin(true);Check("Session","Manual lock","Locked state",w.SessionState=="Locked");Check("Session","Wrong unlock password","Locked and shackle closed",!w.DemoLogin("qa.lifecycle","wrong")&&w.SessionState=="Locked"&&w.LoginShieldProgress==0);
        Check("Session","Unlock own account","Active after correct synthetic password",w.DemoLogin("qa.lifecycle","demo-only")&&w.SessionState=="Active");
        w.AdvanceSessionClockForTest(TimeSpan.FromMinutes(61));w.EvaluateSession(w.SessionClock());Check("Session","Session expiry","Expired; protected mutation rejected",w.SessionState=="Expired"&&!w.SavePolicy(scoped,null));w.ResetSessionClock();w.DemoLogin("admin.demo","demo-only");
        w.AdvanceSessionClockForTest(TimeSpan.FromMinutes(6));await Task.Delay(5300);await Flush();Check("Session timer","Automatic idle lock through real DispatcherTimer","Locked after timer tick with injected +6 minute demo clock",w.SessionState=="Locked",w.SessionState+"; "+w.SessionNotice);w.ResetSessionClock();w.DemoLogin("admin.demo","demo-only");
        w.SignOut();Check("Session","Signout clears contextual content","No active session and no selected finding",w.SessionState!="Active"&&w.Selected=="");w.DemoLogin("admin.demo","demo-only");
        var policy=store.Policies.First(p=>p.Id=="POL-YT-001");
        Check("Policy","Global deny over individual allow","Denied for same target",store.Decision("device-1","example.invalid")==false);
        Check("Policy","Inheritance","Same central policy ID visible on device",store.ForDevice("device-1").Any(p=>p.Id=="POL-GLOBAL"));
        var edit=policy.Copy();edit.End="20:00";int version=policy.Version;w.SavePolicy(edit,policy.Id);Check("Policy","Version and central identity","Version +1 and device view reflects edit",store.Policies.Single(p=>p.Id==policy.Id).Version==version+1&&store.ForDevice("device-1").Single(p=>p.Id==policy.Id).End=="20:00");
        var multi=new DemoPolicy{Name="Two devices",Target="multi.invalid",Block=true,DeviceIds=new[]{"device-1","device-3"}};Check("Policy","Multi-device rule","Single policy applies to both selected IDs",w.SavePolicy(multi,null)&&store.ForDevice("device-1").Any(p=>p.Id==multi.Id)&&store.ForDevice("device-3").Any(p=>p.Id==multi.Id));
        multi=store.Policies.Single(p=>p.Id==multi.Id).Copy();multi.Enabled=false;w.SavePolicy(multi,multi.Id);Check("Policy","Inactive policy","Does not deny access",store.Decision("device-1","multi.invalid")==true);
        var schedule=new DemoPolicy{Name="Schedule",Target="time.invalid",Scheduled=true,Days="1,2,3,4,5",Start="16:00",End="19:00"};
        foreach(var (clock,active,label) in new[]{(new DateTime(2026,11,2,15,59,59),false,"Before start"),(new DateTime(2026,11,2,16,0,0),true,"Exact start inclusive"),(new DateTime(2026,11,2,18,59,59),true,"Within interval"),(new DateTime(2026,11,2,19,0,0),false,"Exact end exclusive"),(new DateTime(2026,11,1,17,0,0),false,"Weekend excluded")})Check("Schedule",label,active.ToString(),schedule.ActiveAt(clock)==active);
        schedule.Start="22:00";schedule.End="02:00";schedule.Days="1";
        Check("Schedule","Overnight start day","Monday 23:00 active",schedule.ActiveAt(new(2026,11,2,23,0,0)));
        Check("Schedule","Overnight next day","Tuesday 01:00 inherits Monday start",schedule.ActiveAt(new(2026,11,3,1,0,0)));
        Check("Schedule","Overnight exact end","Tuesday 02:00 inactive",!schedule.ActiveAt(new(2026,11,3,2,0,0)));
        schedule.Days="";Check("Schedule negative","Empty days","Validation rejects and evaluation returns false",schedule.ScheduleError()!=null&&!schedule.ActiveAt(new(2026,11,2,23,0,0)));
        schedule.Days="1";schedule.Start=schedule.End="16:00";Check("Schedule negative","Empty time interval","Validation rejects",store.ValidatePolicy(schedule)!=null);
        schedule.Start="27:00";Check("Schedule negative","Invalid clock format","Validation rejects",store.ValidatePolicy(schedule)!=null);
        Check("Day selection","Inclusive day range","0-2 expands to Sunday, Monday, Tuesday",DaySelection.TryParse("0-2",out var range)&&range.SetEquals(new[]{0,1,2}));
        Check("Day selection","Mixed list and range","1-3,5 expands to four distinct days",DaySelection.TryParse("1-3,5",out range)&&range.SetEquals(new[]{1,2,3,5}));
        Check("Day selection","Whitespace and duplicates","Repeated days deduplicated",DaySelection.TryParse(" 1 - 3 , 2, 5 ",out range)&&range.SetEquals(new[]{1,2,3,5}));
        foreach(string invalid in new[]{"3-1","0-7","1,,2","-1","1-2-3"})Check("Day selection negative",invalid,"Invalid day expression rejected",!DaySelection.TryParse(invalid,out _));
        schedule.Start="16:00";schedule.End="19:00";schedule.Days="1-3";Check("Schedule","Range used by actual evaluator","Monday and Wednesday active; Thursday inactive",schedule.ActiveAt(new(2026,11,2,17,0,0))&&schedule.ActiveAt(new(2026,11,4,17,0,0))&&!schedule.ActiveAt(new(2026,11,5,17,0,0)));
        NotTested("Schedule","Timezone conversion","Policy bound to named timezone","Model is a naive fixture DateTime; no timezone support");NotTested("Schedule","DST overlap / missing local hour","Deterministic real-time interpretation","No timezone/DST model; explicitly unsupported");
        w.PolicySearch="YouTube";Check("Policy search","Text search","Matching central policy found",w.FilterPolicies().Any(p=>p.Id==policy.Id));w.PolicySearch="";
        w.OpenPolicy("POL-YT-001");await Flush();Text(w,"DevicePickerSearch").Text="FixtureAlpha";await Flush();var picker=PrototypeWindow.Find(w.Surface,"DevicePickerGrid") as DataGrid;
        Check("Picker UI","Search shared device names","Exactly one matching model row",picker?.Items.Count==1&&w.SearchPicker("FixtureAlpha").Single().Id=="device-1");
        Text(w,"DevicePickerSearch").Text="192.0.2.3";await Flush();Check("Picker UI","Search IP address","Existing model device found",w.SearchPicker("192.0.2.3").Any(d=>d.Id=="device-3"));
        ((PrototypeWindow.DeviceChoice)picker!.Items.Cast<object>().First(x=>x is PrototypeWindow.DeviceChoice c&&c.Address=="192.0.2.3")).Selected=true;
        Check("Picker UI","Selection uses shared IDs","Selected ID stored without typing it",w.PickerSelection.Contains("device-3"));
        Check("Picker UI","No technical ID input","Manual PolicyDevice textbox absent in open editor",PrototypeWindow.Find(w.Surface,"PolicyDevice")==null&&PrototypeWindow.Find(w.Surface,"DevicePickerGrid")!=null);
        Click(w,"PreviewPolicy");await Flush();Click(w,"ConfirmPolicy");await Flush();Check("Picker UI","UI save of selected scope","One central rule visible on both devices",store.Policies.Single(p=>p.Id=="POL-YT-001").Targets.Contains("device-3"));
        w.CloseModal();
        w.ActivitySearch="YouTube";w.ActivityUser="admin.demo";w.ActivityType="Megfigyelés";var filtered=w.FilterEvents();Check("Activity","Combined search, user and event type","Nonempty results all satisfy predicates",filtered.Count>0&&filtered.All(e=>e.Domain=="YouTube"&&e.User=="admin.demo"&&e.Type=="Megfigyelés"));
        w.ActivityDevice="device-180";Check("Activity","Device filter","All results match device",w.FilterEvents().All(e=>e.Device=="device-180"));w.ClearActivityFilter("all");
        w.ActivitySearch="no-such-fixture-value";Check("Activity","Empty results","Zero rows",w.FilterEvents().Count==0);w.ClearActivityFilter("search");Check("Activity","Single chip removal","Search cleared",w.ActivitySearch=="");
        w.ActivityFrom=w.ActivityTo="2026-11-01";Check("Activity","Date boundaries","Only selected fixture date",w.FilterEvents().All(e=>e.Time.Date==new DateTime(2026,11,1)));
        w.ActivityFrom="2026-11-02";w.ActivityTo="";Check("Activity","Future date","No historical fixture rows",w.FilterEvents().Count==0);w.ClearActivityFilter("all");Check("Activity","Clear all filters","All shared rows restored",w.FilterEvents().Count==store.Events.Count);
        w.Navigate("Tevékenység");await Flush();Check("Activity UI","Progressive filters default","Advanced device input hidden",PrototypeWindow.Find(w.Surface,"ActivityDevice")==null);Click(w,"ToggleActivityFilters");await Flush();Check("Activity UI","Progressive filters expanded","Advanced input present and table virtualized",PrototypeWindow.Find(w.Surface,"ActivityDevice")!=null&&w.CurrentTable?.EnableRowVirtualization==true);
        foreach(int hours in new[]{6,12,24}){w.InsightHours=hours;w.InsightDevice="";var bins=w.InsightBins();Check("Chart",hours+"h actual fixture aggregation","Counts equal same source time window",bins.Sum(b=>b.Count)==store.NetworkEvents.Count(e=>e.Time>=bins[0].Start&&e.Time<bins[^1].End));}
        w.InsightDevice="device-1";Check("Chart","Device series filter","Bins count only existing device ID",w.InsightBins().Sum(b=>b.Count)==store.NetworkEvents.Count(e=>e.Device=="device-1"&&e.Time>=w.InsightBins()[0].Start&&e.Time<w.InsightBins()[^1].End));w.InsightDevice="";w.InsightHours=6;
        foreach(bool english in new[]{false,true})foreach(bool light in new[]{false,true})
        {
            w.ChangeLanguage(english);w.ChangeTheme(light);
            foreach(var view in new[]{"Áttekintés","Security Insights","Diagnosztika","Eszközök","Domainek és policy","Tevékenység","Beállítások"}){w.Navigate(view);await Flush();if(view=="Tevékenység"){var input=PrototypeWindow.Find(w.Surface,"ActivitySearch") as TextBox;var buttons=new[]{"ToggleActivityFilters","ApplyActivity","ClearActivity"}.Select(id=>PrototypeWindow.Find(w.Surface,id) as Button).ToArray();Check("Activity alignment",$"light={light}; english={english}","Search input and all three action buttons share lower edge and 38 DIP height",input!=null&&buttons.All(button=>button!=null&&Math.Abs(button.ActualHeight-38)<1&&Math.Abs(button.TranslatePoint(new Point(0,button.ActualHeight),w.Surface).Y-input.TranslatePoint(new Point(0,input.ActualHeight),w.Surface).Y)<1));}Check("Layout / theme / language",$"{view}; light={light}; english={english}","Stable outer frame and rendered content",w.ActualWidth==original.ActualWidth&&w.ActualHeight==original.ActualHeight);}
            w.Navigate("Security Insights");await Flush();var bins=w.InsightBins();int max=Math.Max(10,(int)Math.Ceiling(bins.Max(b=>b.Count)/10.0)*10);Check("Chart UI",$"Bar scale; light={light}; english={english}","Every bar height matches source count on shared scale",Enumerable.Range(0,6).All(i=>PrototypeWindow.Find(w.Surface,"ChartBar"+i) is Border bar&&Math.Abs(bar.Height-bins[i].Count/(double)max*142)<.01&&bar.ToolTip.ToString()!.Contains(bins[i].Start.ToString("HH:mm"))));var texts=Tree(w.Surface).OfType<TextBlock>().Select(t=>t.Text).ToArray();Check("Analyst terminology",$"light={light}, english={english}","Correct Analyst name; no Service Agent",texts.Any(t=>t==w.AnalystName)&&!texts.Any(t=>t.Contains("Service Agent",StringComparison.OrdinalIgnoreCase)));
            var field=PrototypeWindow.Find(w.Surface,"InsightDeviceSearch") as TextBox;var filter=PrototypeWindow.Find(w.Surface,"InsightDeviceFilter") as Button;var period=PrototypeWindow.Find(w.Surface,"InsightPeriod6") as Button;
            bool aligned=field!=null&&filter!=null&&period!=null&&Math.Abs(field.TranslatePoint(new Point(0,field.ActualHeight),w.Surface).Y-filter.TranslatePoint(new Point(0,filter.ActualHeight),w.Surface).Y)<1&&Math.Abs(period.TranslatePoint(new Point(0,period.ActualHeight),w.Surface).Y-filter.TranslatePoint(new Point(0,filter.ActualHeight),w.Surface).Y)<1&&Math.Abs(filter.ActualHeight-38)<1;
            Check("Chart filter alignment",$"light={light}; english={english}","Search, filter button and period selector have aligned bottom edges; 38 DIP controls",aligned);
            w.OpenPolicy("POL-YT-001");await Flush();Check("Picker theme",$"light={light}, english={english}","Picker rendered in current skin",PrototypeWindow.Find(w.Surface,"DevicePickerGrid")!=null);w.CloseModal();states.Add(w.Receipt());
        }
        w.ChangeLanguage(true);w.ClearActivityFilter("all");w.ActivityType="Observation";Check("Localization search","English event type filter","Localized event type finds underlying fixture records",w.FilterEvents().Count>0&&w.FilterEvents().All(e=>e.Type=="Megfigyelés"));w.ClearActivityFilter("all");
        w.ChangeLanguage(false);w.ChangeTheme(false);w.SelectSettingsCategory("Megjelenés");await Flush();Check("Settings UI","Vertical category rail","Seven category buttons and shared frame",Enumerable.Range(0,7).All(i=>PrototypeWindow.Find(w.Surface,"Settings"+i)!=null));
        w.SetReducedMotion(false);w.Navigate("Security Insights");await Flush(30);double early=Tree(w.Surface).OfType<StackPanel>().Where(p=>p.RenderTransform is TranslateTransform).Select(p=>p.Opacity).DefaultIfEmpty(1).Min();await Flush(350);Check("Motion","Finite 300ms page transition","Completes without outer resize",w.ActualWidth==original.ActualWidth&&w.ActualHeight==original.ActualHeight);
        w.Navigate("Eszközök");w.Navigate("Domainek és policy");w.Navigate("Security Insights");await Flush(360);Check("Motion","Rapid navigation replacement","Latest page visible without queued page transitions",w.CurrentView=="Security Insights");
        long ticks=CoreVisual.TickCount;await Flush(1000);Check("Motion","No invisible Core render loop on Insights","No large Core timer ticks",CoreVisual.TickCount==ticks);
        w.Navigate("Áttekintés");await Flush();var largeCore=Tree(w.Surface).OfType<CoreVisual>().First(c=>!c.Minimal);ScrollViewer? main=null;for(DependencyObject? parent=VisualTreeHelper.GetParent(largeCore);parent!=null;parent=VisualTreeHelper.GetParent(parent))if(parent is ScrollViewer scroll){main=scroll;break;}
        if(main?.Content is StackPanel content){var spacer=new Border{Height=1200};content.Children.Insert(0,spacer);main.ScrollToTop();await Flush(500);ticks=CoreVisual.TickCount;await Flush(700);Check("Motion viewport","Clipped Core pauses","No ticks when outside ScrollViewer viewport",CoreVisual.TickCount==ticks);content.Children.Remove(spacer);main.ScrollToTop();await Flush(500);ticks=CoreVisual.TickCount;await Flush(700);Check("Motion viewport","Core resumes when visible","Ticks resume after scrolling into view",CoreVisual.TickCount>ticks);}
        w.SetReducedMotion(true);w.Navigate("Áttekintés");await Flush();ticks=CoreVisual.TickCount;await Flush(1000);Check("Motion","Animation switch off","No Core timer ticks",CoreVisual.TickCount==ticks);
        NotTested("Environment","100% and 125% OS DPI","Native UI verification at each scale","Host is 150%; no system DPI change performed");NotTested("Environment","Mixed-DPI monitors","Move real window across displays","No controlled multi-monitor test performed");NotTested("Stability","Multi-hour soak","Stable long-duration resource use","Short runtime and separate warm samples only");
        File.WriteAllText(Path.Combine(output,"matrix.json"),JsonSerializer.Serialize(new{results=rows,passed=rows.Count(r=>r.Status=="PASS"),failed=rows.Count(r=>r.Status=="FAIL"),notTested=rows.Count(r=>r.Status=="NOT TESTED"),states,outer=new[]{w.ActualWidth,w.ActualHeight},dpi=VisualTreeHelper.GetDpi(w).DpiScaleX,limits="UI click handlers invoked in-process; native screenshots separate. Auto-lock uses the actual DispatcherTimer with an injected +6 minute fixture clock, not a one-minute wall-clock wait."},new JsonSerializerOptions{WriteIndented=true}));
        if(rows.Any(r=>r.Status=="FAIL"))throw new Exception(string.Join("; ",rows.Where(r=>r.Status=="FAIL").Select(r=>r.Goal)));
    }
}
