using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Runtime.InteropServices;
using HostsGuardian.Core.Services;
namespace DesignPrototype;
public static class RcDpi
{
    [DllImport("user32.dll")]static extern bool SetProcessDpiAwarenessContext(nint value);
    public static bool Request96()=>SetProcessDpiAwarenessContext(new nint(-1));
}
public sealed partial class PrototypeWindow
{
    internal bool RcNoLogin=>loginOverlay==null&&SessionState=="Active";
    internal bool RcTextBindingsMatch()=>engineTexts.Count>0&&engineTexts.All(x=>x.Text.Text==x.Value());
}
public static class RcVerification
{
    public static async Task Run(PrototypeWindow w,string output)
    {
        Directory.CreateDirectory(output);var checks=new List<object>();
        void Check(string test,bool pass,string actual=""){checks.Add(new{test,pass,actual});File.WriteAllText(Path.Combine(output,"rc-tests.json"),JsonSerializer.Serialize(new{checks,dpi=VisualTreeHelper.GetDpi(w).DpiScaleX},new JsonSerializerOptions{WriteIndented=true}));if(!pass)throw new Exception(test+": "+actual);}
        async Task WaitFresh(){for(int i=0;i<100&&!w.EngineData.Connected;i++)await Task.Delay(30);Check("HTTPS source is connected",w.EngineData.Connected);}
        Check("RC starts offline without fake login or fixture data",w.ReleaseCandidate&&w.RcNoLogin&&!w.EngineMode&&w.EngineData.Devices.Count==0);
        Check("Offline cannot write global policy",await w.ApplyGlobalDomain("example.invalid",true)==null);
        w.Navigate("Beállítások");Check("RC Settings exposes isolated source, no simulated account management",PrototypeWindow.Find(w.Surface,"RcStartMock")!=null&&PrototypeWindow.Find(w.Surface,"EngineDemoMode")==null);
        await w.StartReleaseMock();await WaitFresh();var mock=w.MockEngine!;
        var before=JsonSerializer.Serialize(mock.ReleasePolicy.Devices);
        var block=await w.ApplyGlobalDomain("EXAMPLE.invalid.",true);
        Check("Global Block uses existing Core path and confirms stored/applied",block?.Stored==true&&block.Applied&&mock.ReleasePolicy.GlobalBlockedDomains.Contains("example.invalid"));
        Check("Global Block preserves unrelated rules and registry",mock.ReleasePolicy.GlobalBlockedDomains.Contains("keep.invalid")&&JsonSerializer.Serialize(mock.ReleasePolicy.Devices)==before);
        Check("Global Block is reflected through shared poller projection",w.EngineData.Revision==mock.ReleaseRevision&&w.EngineData.Value("/v2/policy")?.GetProperty("policy").GetProperty("globalBlockedDomains").EnumerateArray().Any(x=>x.GetString()=="example.invalid")==true);
        long writes=mock.Writes;var already=await w.ApplyGlobalDomain("example.invalid",true);Check("Already current does not rewrite",already?.AlreadyCurrent==true&&mock.Writes==writes);
        var restore=await w.ApplyGlobalDomain("example.invalid",false);Check("Restore removes only requested global domain",restore?.Stored==true&&!mock.ReleasePolicy.GlobalBlockedDomains.Contains("example.invalid")&&mock.ReleasePolicy.GlobalBlockedDomains.Contains("keep.invalid"));
        mock.ReleaseConflict=true;var conflict=await w.ApplyGlobalDomain("conflict.invalid",true);Check("Definite CAS conflict retries once and preserves concurrent edits",conflict?.Stored==true&&mock.ReleasePolicy.GlobalBlockedDomains.Contains("concurrent.invalid"));
        mock.ReleaseFailWrite=true;writes=mock.Writes;var failed=await w.ApplyGlobalDomain("failure.invalid",true);Check("Failed write has no false confirmation or blind replay",failed?.Stored==false&&mock.Writes==writes+1&&!mock.ReleasePolicy.GlobalBlockedDomains.Contains("failure.invalid"));mock.ReleaseFailWrite=false;
        mock.ReleaseFailReadbackAfter=mock.Writes;mock.ReleaseFailReadback=true;writes=mock.Writes;var uncertain=await w.ApplyGlobalDomain("uncertain.invalid",true);Check("Uncertain readback stays unconfirmed and is not replayed",uncertain?.Stored==false&&mock.Writes==writes+1);mock.ReleaseFailReadback=false;
        mock.ReleaseInactive=true;var inactive=await w.ApplyGlobalDomain("inactive.invalid",true);Check("Stored is distinct from applied",inactive?.Stored==true&&!inactive.Applied);mock.ReleaseInactive=false;
        var dims=(w.ActualWidth,w.ActualHeight);
        foreach(var page in new[]{"Áttekintés","Eszközök","Domainek és policy","Tevékenység","Security Insights","Diagnosztika","Beállítások"})
        {w.Navigate(page);await w.Dispatcher.InvokeAsync(()=>{},System.Windows.Threading.DispatcherPriority.ApplicationIdle);Check("Stable RC navigation: "+page,(w.ActualWidth,w.ActualHeight)==dims);}
        w.Navigate("Domainek és policy");Check("Global command UI present",PrototypeWindow.Find(w.Surface,"RcGlobalBlock") is Button {IsEnabled:true}&&PrototypeWindow.Find(w.Surface,"RcGlobalRestore")!=null);
        w.Navigate("Security Insights");Check("Insights binds actual projection and preserves Unknown network proof",w.RcTextBindingsMatch()&&w.EngineData.NetworkProof!=DesignPrototype.Engine.ProofState.Verified);
        var poll=w.EnginePolling!;await poll.RunExclusiveAsync(async ct=>{Check("Poller refuses overlapping refresh during command",!await poll.PollOnceAsync());await Task.Delay(30,ct);});
        mock.Scenario="Delayed";mock.DelayMilliseconds=200;var slow=poll.PollOnceAsync();await Task.Delay(25);Check("Overlapping automatic/manual refresh is excluded",!await poll.PollOnceAsync());await slow;mock.Scenario="Normal";
        Check("Only isolated loopback management writes",mock.Writes>0&&new Uri(mock.Origin).IsLoopback&&mock.Methods.All(x=>x.StartsWith("GET ")||x=="POST /v2/policy/replace"));
        await w.StopEngine();w.Navigate("Áttekintés");Check("Source stop releases poller and does not expose demo fallback",poll.Stopped&&!w.EngineMode&&w.RcNoLogin&&PrototypeWindow.Find(w.Surface,"RcOpenSettings")!=null);
        Check("Live connection is blocked in RC preparation",await LiveDenied(w));
        if(Environment.GetCommandLineArgs().Contains("--dpi-100"))Check("Native WPF 100% process DPI",Math.Abs(VisualTreeHelper.GetDpi(w).DpiScaleX-1)<.001);
    }
    static async Task<bool> LiveDenied(PrototypeWindow w){try{await w.StartLiveEngine("not-used.json");return false;}catch(InvalidOperationException){return true;}}
}
