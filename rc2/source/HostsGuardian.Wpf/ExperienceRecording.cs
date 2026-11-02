using System.IO;
using System.Diagnostics;
using System.Text.Json;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
namespace DesignPrototype;
public static class ExperienceRecording
{
    public static async Task Run(PrototypeWindow w,string output,bool measure=true)
    {
        Directory.CreateDirectory(output);int frame=0;var times=new List<double>();var unlock=new List<object>();var clock=Stopwatch.StartNew();
        async Task CaptureFor(int ms)
        {
            var stage=Stopwatch.StartNew();while(stage.ElapsedMilliseconds<ms)
            {
                await Task.Delay(55);await Dispatcher.Yield(DispatcherPriority.Render);
                var bitmap=new RenderTargetBitmap((int)w.Surface.ActualWidth,(int)w.Surface.ActualHeight,96,96,PixelFormats.Pbgra32);bitmap.Render(w.Surface);
                var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));using(var file=File.Create(Path.Combine(output,$"{frame++:000}.png")))encoder.Save(file);times.Add(clock.Elapsed.TotalMilliseconds);unlock.Add(new{frame=frame-1,progress=w.LoginShieldProgress,startup=w.StartupVisible,session=w.SessionState});
            }
        }
        w.ChangeTheme(false);w.ChangeLanguage(false);w.SetReducedMotion(false);w.SignOut();await CaptureFor(1100);
        w.DemoLogin("admin.demo","demo-only");await CaptureFor(4200);
        w.Navigate("Security Insights");await CaptureFor(900);w.ShowAnalystEvidence();await CaptureFor(950);w.CloseDetails();
        w.Navigate("Tevékenység");await CaptureFor(600);w.ActivityFiltersOpen=true;w.BuildPage();await CaptureFor(750);
        w.SelectSettingsCategory("Megjelenés");await CaptureFor(750);w.ChangeTheme(true);w.Navigate("Security Insights");await CaptureFor(900);w.ShowAnalystEvidence();await CaptureFor(800);w.CloseDetails();
        File.WriteAllText(Path.Combine(output,"recording.json"),JsonSerializer.Serialize(new{frames=frame,timesMs=times,unlock,method="Actual WPF RenderTargetBitmap runtime frames. Not native Windows video. Accepted login shackle, activation, 300ms page transitions, Analyst evidence panel, progressive filters, vertical settings and Dark/Light."},new JsonSerializerOptions{WriteIndented=true}));
        if(!measure)return;
        var interactions=new List<object>();var process=Process.GetCurrentProcess();var interactionCpu=process.TotalProcessorTime;var interactionClock=Stopwatch.StartNew();
        foreach(bool light in Enumerable.Range(0,10).Select(i=>i%2==0)){var call=Stopwatch.StartNew();w.ChangeTheme(light);await Dispatcher.Yield(DispatcherPriority.Render);interactions.Add(new{operation="theme",light,milliseconds=call.Elapsed.TotalMilliseconds});await Task.Delay(350);}
        foreach(var view in Enumerable.Range(0,16).Select(i=>new[]{"Security Insights","Beállítások","Domainek és policy","Áttekintés"}[i%4])){var call=Stopwatch.StartNew();w.Navigate(view);await Dispatcher.Yield(DispatcherPriority.Render);interactions.Add(new{operation="navigate",view,milliseconds=call.Elapsed.TotalMilliseconds});await Task.Delay(350);}
        process.Refresh();File.WriteAllText(Path.Combine(output,"interaction-performance.json"),JsonSerializer.Serialize(new{interactions,wallSeconds=interactionClock.Elapsed.TotalSeconds,cpuOneCorePercent=(process.TotalProcessorTime-interactionCpu).TotalSeconds/interactionClock.Elapsed.TotalSeconds*100,workingSetMiB=process.WorkingSet64/1048576.0,limits="Application call plus dispatcher Render opportunity, not GPU completion. Includes 350ms observation intervals between interactions."},new JsonSerializerOptions{WriteIndented=true}));
        w.ExitStartup();w.ChangeTheme(false);w.Navigate("Áttekintés");
        var samples=new List<object>();
        foreach(bool reduced in new[]{true,false})
        {
            w.SetReducedMotion(reduced);await Task.Delay(3000);var p=Process.GetCurrentProcess();p.Refresh();var cpu=p.TotalProcessorTime;var memory=p.WorkingSet64;long ticks=CoreVisual.TickCount;var watch=Stopwatch.StartNew();
            await Task.Delay(30000);p.Refresh();
            samples.Add(new{reduced,seconds=watch.Elapsed.TotalSeconds,cpuOneCorePercent=(p.TotalProcessorTime-cpu).TotalSeconds/watch.Elapsed.TotalSeconds*100,startMiB=memory/1048576.0,endMiB=p.WorkingSet64/1048576.0,coreTicks=CoreVisual.TickCount-ticks});
        }
        File.WriteAllText(Path.Combine(output,"idle-performance.json"),JsonSerializer.Serialize(new{samples,limits="Two 30-second warm idle samples on this host. Not a multi-hour soak, memory leak proof or cross-hardware performance guarantee."},new JsonSerializerOptions{WriteIndented=true}));
    }
}
