using System.IO;
using System.Text.Json;
using System.Windows.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using DesignPrototype.Engine;
namespace DesignPrototype;
public static class Gate6Verification
{
    public sealed record Result(string Category,string Goal,string Expected,string Actual,string Status,string Evidence,string Risk);
    sealed class ResponseHandler(string content,int code=200):HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>Task.FromResult(new HttpResponseMessage((HttpStatusCode)code){Content=new StringContent(content,Encoding.UTF8,"application/json")});
    }
    public static async Task Run(PrototypeWindow w,string output)
    {
        Directory.CreateDirectory(output);var results=new List<Result>();var evidence=Path.Combine(output,"matrix.json");
        void Check(string category,string goal,string expected,bool success,string actual,string risk="Isolated fixture; not production acceptance")=>results.Add(new(category,goal,expected,actual,success?"PASS":"FAIL",evidence,risk));
        async Task Flush(){await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);await Task.Delay(80);}
        await using var mock=new MockHttpsEngine(){AutoChange=false};mock.Start();using var reader=new EngineReader(mock.Origin,mock.Certificate,()=>mock.Token,TimeSpan.FromMilliseconds(350));
        var first=await reader.FetchAsync(default);Check("Connection","Valid HTTPS available","Fresh authenticated snapshot",first.Get("/dns/status")?.Usable==true,first.Get("/dns/status")?.Error.ToString()??"missing");
        Check("Security","GET allowlist","No write path accepted",await Throws(()=>reader.ReadAsync("/v2/policy/replace",default)),"Forbidden path throws before transport");
        foreach(var (scene,error) in new[]{("401",ReadError.Authentication),("403",ReadError.Forbidden),("500",ReadError.Server),("503",ReadError.Server),("BadJson",ReadError.InvalidJson),("Missing",ReadError.Schema),("Disconnected",ReadError.Unreachable),("Timeout",ReadError.Timeout)})
        {
            mock.Scenario=scene;var r=await reader.ReadAsync("/dns/status",default);Check("Negative transport",scene,error.ToString(),r.Error==error,r.Error.ToString());
        }
        mock.Scenario="Delayed";using(var cancel=new CancellationTokenSource(80)){var r=await reader.ReadAsync("/dns/status",cancel.Token);Check("Cancellation","In-flight cancellation","Cancelled",r.Error==ReadError.Cancelled,r.Error.ToString());}
        mock.Scenario="Normal";
        var absentMock=new MockHttpsEngine();absentMock.Start();var absentOrigin=absentMock.Origin;await absentMock.DisposeAsync();using(var absent=new EngineReader(absentOrigin,mock.Certificate,()=>mock.Token,TimeSpan.FromMilliseconds(350))){var r=await absent.ReadAsync("/dns/status",default);Check("Connection","Engine unavailable","Unreachable or bounded timeout",r.Error is ReadError.Unreachable or ReadError.Timeout,r.Error.ToString());}
        foreach(var (body,expected) in new[]{("{\"instanceId\":\"a\",\"instanceId\":\"b\",\"runtimeState\":\"Running\"}",ReadError.InvalidJson),("[]",ReadError.Schema)})
        {using var r=new EngineReader(mock.Origin,mock.Certificate,()=>mock.Token,testHandler:new ResponseHandler(body));var response=await r.ReadAsync("/dns/status",default);Check("Schema","Malformed/duplicate structure "+expected,expected.ToString(),response.Error==expected,response.Error.ToString());}
        using(var r=new EngineReader(mock.Origin,mock.Certificate,()=>mock.Token,testHandler:new ResponseHandler("{\"instanceId\":\"optional\",\"runtimeState\":\"Running\"}"))){var response=await r.ReadAsync("/dns/status",default);Check("Schema","Missing optional fields","No fabricated UDP state or source timestamp",response.Usable&&Json.S(response.Value,"udpState")==null&&response.ObservedAt==null,"UDP=null; observed=null");}
        Check("Schema","Empty optional string","Treat as missing, allow registered-name fallback",Json.S(JsonSerializer.SerializeToElement(new{alias=""}),"alias")==null,"empty alias=null");
        using(var r=new EngineReader(mock.Origin,mock.Certificate,()=>mock.Token,testHandler:new ResponseHandler(new string('x',1048577)))){var response=await r.ReadAsync("/dns/status",default);Check("Limits","Oversized response","Oversize",response.Error==ReadError.Oversize,response.Error.ToString());}
        using(var wrong=new EngineReader(mock.Origin,mock.Certificate,()=>Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)))){var r=await wrong.ReadAsync("/dns/status",default);Check("Security","Wrong credential","Authentication error",r.Error==ReadError.Authentication,r.Error.ToString());}
        foreach(var kind in new[]{"expired","wrong-name"})
        {
            await using var server=new MockHttpsEngine(kind);server.Start();using var r=new EngineReader(server.Origin,server.Certificate,()=>server.Token);var response=await r.ReadAsync("/dns/status",default);Check("TLS",kind,"TLS validation failure; no HTTP auth sent",response.Error==ReadError.Tls&&server.RequestCount==0,response.Error+"; HTTP requests="+server.RequestCount);
        }
        await using(var other=new MockHttpsEngine()){using var r=new EngineReader(mock.Origin,other.Certificate,()=>mock.Token);var response=await r.ReadAsync("/dns/status",default);Check("TLS","Different enrolled leaf","TLS validation failure",response.Error==ReadError.Tls,response.Error.ToString());}
        Check("Security","Invalid remote origins","Reject HTTP/public IP/credentials/path",new[]{"http://127.0.0.1/","https://example.com/","https://8.8.8.8/","https://a:b@127.0.0.1/","https://127.0.0.1/write"}.All(x=>{try{LiveConfiguration.ValidateOrigin(x);return false;}catch{return true;}}),"Origin validation executed before transport");
        var projection=new EngineProjection();mock.Generation=1;mock.Scenario="Normal";projection.Apply(await reader.FetchAsync(default));var stable=projection.Devices.First(x=>x.Key.StartsWith("registry:"));int before=projection.Devices.Count;
        mock.Generation=2;projection.Apply(await reader.FetchAsync(default));Check("Projection","New Engine observation","Add one row",projection.Devices.Count==before+1,projection.Devices.Count.ToString());
        mock.Generation=3;projection.Apply(await reader.FetchAsync(default));Check("Projection","Existing device changes","Same row object, updated name",ReferenceEquals(stable,projection.Devices.First(x=>x.Key==stable.Key))&&stable["Name"].Contains("Átnevezett"),stable["Name"]);
        mock.Scenario="Duplicate";projection.Apply(await reader.FetchAsync(default));Check("Projection","Duplicate API rows","No duplicate view rows",projection.Devices.Select(x=>x.Key).Distinct().Count()==projection.Devices.Count,projection.Devices.Count.ToString());
        mock.Scenario="DeviceGone";projection.Apply(await reader.FetchAsync(default));Check("Projection","Disappeared observation","Retain observation with unknown presence",projection.Devices.Count>=before&&projection.Devices.Any(x=>!x.Present),string.Join(";",projection.Devices.Select(x=>x["Presence"])));
        mock.Scenario="Empty";projection.Apply(await reader.FetchAsync(default));Check("Projection","Empty list","No fabricated fallback devices; retained rows marked absent",projection.Devices.All(x=>!x.Present)&&projection.Events.Count==0,"retained="+projection.Devices.Count+" events="+projection.Events.Count);
        var latest=projection.Latest!;Check("Ordering","Late older cycle","Reject older sequence",!projection.Apply(latest with{Sequence=latest.Sequence-1}),"Regressed cycles="+projection.Regressions);
        mock.Scenario="Normal";projection.Apply(await reader.FetchAsync(default));var good=projection.LastGood["/dns/status"];var old=good with{ObservedAt=good.ObservedAt?.AddSeconds(-1)};
        projection.Apply(new(projection.Latest!.Sequence+1,DateTimeOffset.UtcNow,new Dictionary<string,EndpointRead>{{"/dns/status",old}}));Check("Ordering","Older source timestamp","Preserve newer source",projection.LastGood["/dns/status"].ObservedAt==good.ObservedAt,"Newest source retained");
        mock.Scenario="Configured";var p2=new EngineProjection();p2.Apply(await reader.FetchAsync(default));Check("Evidence","Configured not Applied","Configured",p2.PolicyProof==ProofState.Configured,p2.PolicyProof.ToString());
        mock.Scenario="Normal";p2.Apply(await reader.FetchAsync(default));Check("Evidence","Applied not Verified","Applied / Unknown network",p2.PolicyProof==ProofState.Applied&&p2.NetworkProof==ProofState.Unknown,p2.PolicyProof+" / "+p2.NetworkProof);
        Check("Evidence","No binding","Zero bindings; no verified identity",Json.A(p2.Value("/v2/bindings"),"observations").Length==0&&p2.Events.All(x=>x.Raw("Device")==null),"bindings=0; event identities Unknown");
        Check("Evidence","IPv6 DeviceId unsupported","False, not hidden",Json.B(p2.Value("/v2/capabilities"),"ipv6DeviceEnforcement")==false,"False");
        Check("Evidence","Receiver status absent from HTTPS","Unavailable / not independently measured",p2.Receiver.Contains("Unavailable"),p2.Receiver,"Gate5 receiver UNAVAILABLE is historical, not a fresh measurement");
        mock.Scenario="503";p2.Apply(await reader.FetchAsync(default));Check("Evidence","Unavailable and stale last-good","No silent fixture fallback",!p2.Connected&&p2.PolicyProof==ProofState.Unavailable&&p2.Value("/dns/status")!=null,"Unavailable with retained source values");
        mock.Scenario="Normal";p2.Apply(await reader.FetchAsync(default));Check("Connection","Reconnect","Fresh again",p2.Connected,"Connected="+p2.Connected);
        mock.Scenario="Stale";p2.Apply(await reader.FetchAsync(default));Check("Evidence","Stale source","Not current",!p2.Connected,"Connected="+p2.Connected);
        mock.Scenario="Normal";var published=0;using var pollReader=new EngineReader(mock.Origin,mock.Certificate,()=>mock.Token);await using(var polling=new EnginePoller(pollReader,_=>{Interlocked.Increment(ref published);return Task.CompletedTask;},TimeSpan.FromSeconds(5)))
        {
            mock.Scenario="Delayed";mock.DelayMilliseconds=80;var a=polling.PollOnceAsync();await Task.Delay(20);var b=await polling.PollOnceAsync();await a;Check("Polling","Concurrent calls","Second cycle coalesced",!b&&published==1,"published="+published);
        }
        Check("Polling","Backoff maximum","Bounded <=120 seconds",Enumerable.Range(0,20).All(i=>EnginePoller.Delay(TimeSpan.FromSeconds(20),i,.1)<=TimeSpan.FromSeconds(120)),"20 exponential delay steps checked");
        mock.Scenario="503";using(var r=new EngineReader(mock.Origin,mock.Certificate,()=>mock.Token)){await using var circuit=new EnginePoller(r,_=>Task.CompletedTask,TimeSpan.FromSeconds(5));for(int i=0;i<12;i++)await circuit.PollOnceAsync();Check("Polling","Finite failure episode","Pause after 8 failed cycles",circuit.CircuitOpen&&circuit.Published==8,"paused="+circuit.CircuitOpen+" cycles="+circuit.Published);}
        mock.Scenario="Normal";var restart=new EngineProjection();restart.Apply(await reader.FetchAsync(default));mock.Instance="mock-instance-b";restart.Apply(await reader.FetchAsync(default));Check("Ordering","Engine instance change","New epoch replaces old source cache",restart.Instance=="mock-instance-b",restart.Instance??"missing");
        var remembered=restart.LastGood.Count;mock.Scenario="Stale";mock.Instance="stale-previous-instance";restart.Apply(await reader.FetchAsync(default));Check("Ordering","Stale instance cannot clear newer cache","Keep latest good instance and cache",restart.Instance=="mock-instance-b"&&restart.LastGood.Count==remembered,"instance="+restart.Instance+" cached="+restart.LastGood.Count);mock.Scenario="Normal";
        await w.StartMockEngine(false,false);await Wait(()=>w.EngineData.Connected);await Flush();var outer=(w.ActualWidth,w.ActualHeight);var builds=w.EnginePageBuilds;
        foreach(bool light in new[]{false,true})foreach(bool english in new[]{false,true})foreach(var view in new[]{"Áttekintés","Eszközök","Tevékenység","Diagnosztika","Security Insights","Domainek és policy","Beállítások"})
        {
            w.ChangeTheme(light);w.ChangeLanguage(english);w.Navigate(view);await Flush();Check("UI",$"{view} light={light} english={english}","Stable frame and Engine mode",Math.Abs(w.ActualWidth-outer.ActualWidth)<.1&&Math.Abs(w.ActualHeight-outer.ActualHeight)<.1&&w.EngineMode,"stable="+(w.ActualWidth==outer.ActualWidth)+"; mode="+w.EngineMode);
        }
        w.ChangeTheme(false);w.ChangeLanguage(false);w.Navigate("Eszközök");await Flush();var grid=w.EngineGrid!;grid.SelectedItem=w.EngineData.Devices.First(x=>x.Key.StartsWith("registry:"));var chosen=grid.SelectedItem;int pageBuilds=w.EnginePageBuilds;
        w.MockEngine!.Generation=3;await w.EnginePolling!.PollOnceAsync();await Flush();Check("UI refresh","Selected row and no page rebuild","Same row selected; no page rebuild",ReferenceEquals(grid.SelectedItem,chosen)&&w.EnginePageBuilds==pageBuilds,"builds="+w.EnginePageBuilds+" selected="+ReferenceEquals(grid.SelectedItem,chosen));
        w.ActivitySearch="video";w.Navigate("Tevékenység");await Flush();var search=PrototypeWindow.Find(w.Surface,"ActivitySearch") as TextBox;search!.Focus();search.Text="pending edit";w.MockEngine.Generation=2;await w.EnginePolling.PollOnceAsync();await Flush();Check("UI refresh","Active search during update","Pending text/focus and applied filter retained",search.Text=="pending edit"&&search.IsKeyboardFocused&&w.EngineAppliedSearch=="video","pending="+search.Text+" focus="+search.IsKeyboardFocused+" applied="+w.EngineAppliedSearch);
        var clock=new Stopwatch();int beats=0;var beat=new DispatcherTimer{Interval=TimeSpan.FromMilliseconds(20)};beat.Tick+=(_,_)=>beats++;beat.Start();w.MockEngine.Scenario="Delayed";w.MockEngine.DelayMilliseconds=120;var delayed=w.EnginePolling.PollOnceAsync();w.Navigate("Diagnosztika");clock.Start();await delayed;beat.Stop();Check("UI responsiveness","Navigation during slow network","Dispatcher continues",beats>=10&&w.CurrentView=="Diagnosztika","beats="+beats+" durationMs="+clock.ElapsedMilliseconds);
        w.MockEngine.Scenario="Many";await w.EnginePolling.PollOnceAsync();w.Navigate("Tevékenység");await Flush();Check("Volume","Large event response","Bounded virtualized rows",w.EngineData.Events.Count>1000&&w.EngineData.Events.Count<=4096&&w.EngineGrid!.EnableRowVirtualization,"events="+w.EngineData.Events.Count);
        w.MockEngine.Scenario="Normal";w.ActivitySearch="";await w.EnginePolling.PollOnceAsync();w.Navigate("Security Insights");await Flush();w.ShowEngineEvidence();await Flush();Check("UI","Evidence panel inside frame","Stable size and detail visible",w.DetailVisible&&w.ActualWidth==outer.ActualWidth&&w.ActualHeight==outer.ActualHeight,"panel="+w.DetailVisible);w.CloseDetails();
        await Measure(w,output);var poll=w.EnginePolling;var pending=w.EnginePolling!.PollOnceAsync();w.InsightDevice="engine-only-identity";await w.StopEngine();await pending;Check("Lifecycle","Stop/close cancellation","Stopped; no late publication",poll!.Stopped&&!w.EngineMode,"stopped="+poll.Stopped);Check("Modes","Explicit source switch clears incompatible identity filter","No Engine identity reused as fixture device",w.InsightDevice==""&&w.EngineAppliedSearch=="","source-local filters cleared");
        Check("Security","All mock transport methods","Only GET, zero mutations",mock.Writes==0&&mock.Methods.All(x=>x.StartsWith("GET ")),"requests="+mock.RequestCount+" writes="+mock.Writes);
        results.Add(new("Environment","100/125% native OS DPI and mixed monitors","Real OS configuration test","Host 150%; no OS setting change performed","NOT TESTED",evidence,"Cross-DPI behavior remains to be verified"));
        results.Add(new("Stability","Multi-hour soak","Several hours of polling","Short bounded soak and separate idle/active samples only","NOT TESTED",evidence,"No multi-hour or leak-proof claim"));
        File.WriteAllText(evidence,JsonSerializer.Serialize(new{results,outer=new[]{w.ActualWidth,w.ActualHeight},dpi=System.Windows.Media.VisualTreeHelper.GetDpi(w).DpiScaleX,source="Mock HTTPS loopback and injected negative transport; no production requests"},new JsonSerializerOptions{WriteIndented=true}));
        if(results.Any(x=>x.Status=="FAIL"))throw new Exception("Gate6 failed checks: "+string.Join(", ",results.Where(x=>x.Status=="FAIL").Select(x=>x.Goal)));
    }
    static async Task<bool> Throws(Func<Task> action){try{await action();return false;}catch(InvalidOperationException){return true;}}
    static async Task Wait(Func<bool> ready){for(int i=0;i<100;i++){if(ready())return;await Task.Delay(60);}throw new Exception("Mock did not become ready");}
    static async Task Measure(PrototypeWindow w,string output)
    {
        w.Navigate("Áttekintés");w.SetReducedMotion(true);w.MockEngine!.AutoChange=false;await Task.Delay(2500);var samples=new List<object>();
        foreach(var active in new[]{false,true})
        {
            var process=Process.GetCurrentProcess();process.Refresh();long start=process.WorkingSet64;var cpu=process.TotalProcessorTime;var timer=Stopwatch.StartNew();long requests=w.EngineTransport!.Requests;int updates=w.EngineRefreshes;long ticks=CoreVisual.TickCount,renders=CoreVisual.RenderCount;
            if(active)for(int i=0;i<20;i++){await w.EnginePolling!.PollOnceAsync();await Task.Delay(50);}else await Task.Delay(5000);
            process.Refresh();samples.Add(new{active,seconds=timer.Elapsed.TotalSeconds,cpuOneCorePercent=(process.TotalProcessorTime-cpu).TotalSeconds/timer.Elapsed.TotalSeconds*100,startMiB=start/1048576.0,endMiB=process.WorkingSet64/1048576.0,requests=w.EngineTransport.Requests-requests,updates=w.EngineRefreshes-updates,pageBuilds=w.EnginePageBuilds,coreTicks=CoreVisual.TickCount-ticks,coreRenders=CoreVisual.RenderCount-renders});
        }
        File.WriteAllText(Path.Combine(output,"performance.json"),JsonSerializer.Serialize(new{samples,limits="Same process includes isolated TLS mock server, client and WPF. Reduced motion. Active phase is accelerated 20 refreshes; not production load or multi-hour soak."},new JsonSerializerOptions{WriteIndented=true}));
    }
}
