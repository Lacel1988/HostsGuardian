using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
namespace DesignPrototype;
public sealed partial class PrototypeWindow
{
    public int Gate6Scene{get;private set;}
    public async Task ShowGate6Scene(int scene)
    {
        if(!EngineMode)await StartMockEngine(false);Gate6Scene=scene;CloseModal();CloseDetails();MockEngine!.Scenario=scene==8?"503":"Normal";ChangeTheme(scene is 10 or 11 or 12);ChangeLanguage(false);ActivityFiltersOpen=scene is 4 or 11;ActivitySearch=scene is 3 or 4 or 11?"video":"";
        await EnginePolling!.PollOnceAsync();Navigate(scene switch{2 or 10=>"Eszközök",3 or 4 or 11=>"Tevékenység",5 or 6 or 12=>"Security Insights",7 or 8=>"Diagnosztika",_=>"Áttekintés"});if(scene==6)ShowEngineEvidence();
    }
}
public static class Gate6Evidence
{
    public static async Task CloseTest(PrototypeWindow w,string output)
    {
        Directory.CreateDirectory(output);await w.StartMockEngine(false);for(int i=0;i<100&&!w.EngineData.Connected;i++)await Task.Delay(50);var poll=w.EnginePolling!;w.MockEngine!.Scenario="Timeout";var pending=poll.PollOnceAsync();await Task.Delay(100);var stopped=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);w.Closed+=(_,_)=>{File.WriteAllText(Path.Combine(output,"close.json"),JsonSerializer.Serialize(new{expected="Closing cancels in-flight request and stops poller",actual="Window Closed; stopped="+poll.Stopped+"; EngineMode="+w.EngineMode,status=poll.Stopped&&!w.EngineMode?"PASS":"FAIL",risk="Loopback mock only; no production request"},new JsonSerializerOptions{WriteIndented=true}));stopped.TrySetResult();};w.Close();await stopped.Task;
    }
    public static async Task Soak(PrototypeWindow w,string output,int seconds)
    {
        Directory.CreateDirectory(output);await w.StartMockEngine(false);for(int i=0;i<100&&!w.EngineData.Connected;i++)await Task.Delay(50);w.SetReducedMotion(true);w.Navigate("Áttekintés");await Task.Delay(3000);
        var process=Process.GetCurrentProcess();process.Refresh();var cpu=process.TotalProcessorTime;var clock=Stopwatch.StartNew();var samples=new List<object>();int builds=w.EnginePageBuilds;long ticks=CoreVisual.TickCount;long renders=CoreVisual.RenderCount;long initialRequests=w.EngineTransport!.Requests;
        int beats=0;double maxGap=0;
        while(clock.Elapsed.TotalSeconds<seconds)
        {
            await Task.Delay(5000);var gap=await Task.Run(async()=>{var timer=Stopwatch.StartNew();await w.Dispatcher.InvokeAsync(()=>{});return timer.Elapsed.TotalMilliseconds;});maxGap=Math.Max(maxGap,gap);beats++;process.Refresh();samples.Add(new{seconds=clock.Elapsed.TotalSeconds,workingSetMiB=process.WorkingSet64/1048576.0,managedMiB=GC.GetTotalMemory(false)/1048576.0,requests=w.EngineTransport.Requests-initialRequests,updates=w.EngineRefreshes,devices=w.EngineData.Devices.Count,events=w.EngineData.Events.Count,pageBuilds=w.EnginePageBuilds,coreTicks=CoreVisual.TickCount-ticks,coreRenders=CoreVisual.RenderCount-renders});
            File.WriteAllText(Path.Combine(output,"soak-progress.json"),JsonSerializer.Serialize(samples));
        }
        process.Refresh();var result=new{seconds=clock.Elapsed.TotalSeconds,cpuOneCorePercent=(process.TotalProcessorTime-cpu).TotalSeconds/clock.Elapsed.TotalSeconds*100,beatCount=beats,maxUiGapMs=maxGap,pageBuildsStable=builds==w.EnginePageBuilds,requests=w.EngineTransport.Requests-initialRequests,bytes=w.EngineTransport.Bytes,mockRequests=w.MockEngine!.RequestCount,mockWrites=w.MockEngine.Writes,samples,limits="Clean process, reduced motion, normal 5-second mock polling. UI probe once per 5 seconds; includes local TLS mock server and client. Not multi-hour leak proof or production benchmark."};File.WriteAllText(Path.Combine(output,"soak.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));
        await w.PauseEngineForMeasurement();await Task.Delay(2000);process.Refresh();var quietCpu=process.TotalProcessorTime;var quiet=Stopwatch.StartNew();await Task.Delay(15000);process.Refresh();File.WriteAllText(Path.Combine(output,"paused-baseline.json"),JsonSerializer.Serialize(new{seconds=quiet.Elapsed.TotalSeconds,cpuOneCorePercent=(process.TotalProcessorTime-quietCpu).TotalSeconds/quiet.Elapsed.TotalSeconds*100,workingSetMiB=process.WorkingSet64/1048576.0,condition="Same WPF surface, all adapter polling/freshness timers paused; mock server idle; reduced motion"},new JsonSerializerOptions{WriteIndented=true}));await w.StopEngine();
    }
    public static async Task Record(PrototypeWindow w,string output)
    {
        Directory.CreateDirectory(output);int frame=0;var clock=Stopwatch.StartNew();var times=new List<double>();
        async Task Capture(int ms){var c=Stopwatch.StartNew();while(c.ElapsedMilliseconds<ms){await Task.Delay(65);await Dispatcher.Yield(DispatcherPriority.Render);var bitmap=new RenderTargetBitmap((int)w.Surface.ActualWidth,(int)w.Surface.ActualHeight,96,96,PixelFormats.Pbgra32);bitmap.Render(w.Surface);var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));using(var f=File.Create(Path.Combine(output,$"{frame++:0000}.png")))encoder.Save(f);times.Add(clock.Elapsed.TotalMilliseconds);}}
        w.ChangeTheme(false);w.SetReducedMotion(false);w.SignOut();await Capture(800);w.DemoLogin("admin.demo","demo-only");await Capture(4100);
        await w.StartMockEngine(false);await Capture(850);w.Navigate("Eszközök");await Capture(650);w.MockEngine!.Generation=3;await w.EnginePolling!.PollOnceAsync();await Capture(850);
        w.Navigate("Security Insights");await Capture(700);w.ShowEngineEvidence();await Capture(900);w.CloseDetails();w.MockEngine.Scenario="503";await w.EnginePolling.PollOnceAsync();w.Navigate("Diagnosztika");await Capture(900);w.MockEngine.Scenario="Normal";await w.EnginePolling.PollOnceAsync();w.ChangeTheme(true);w.Navigate("Tevékenység");w.ActivityFiltersOpen=true;w.BuildPage();await Capture(1000);
        File.WriteAllText(Path.Combine(output,"recording.json"),JsonSerializer.Serialize(new{frames=frame,timesMs=times,method="Actual WPF runtime RenderTargetBitmap frames; not native Windows video. Existing login shackle, mock HTTPS refresh, source outage/reconnect and Dark/Light pages. No production connection."},new JsonSerializerOptions{WriteIndented=true}));await w.StopEngine();
    }
}
