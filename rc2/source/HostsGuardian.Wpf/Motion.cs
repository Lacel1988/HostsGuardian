using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace DesignPrototype;

public sealed partial class PrototypeWindow
{
    public bool AutoStartup {get;set;}
    public bool ActivationLab {get;set;}
    public double AutoStartupDuration {get;set;}=2.5;
    Border? startupOverlay;
    CoreVisual? startupCore;
    Border? startupFill;
    TextBlock? startupStage;
    TextBlock? startupNote;
    StackPanel? startupWordmark;
    readonly DispatcherTimer startupTimer=new(){Interval=TimeSpan.FromMilliseconds(33)};
    readonly Stopwatch startupClock=new();
    double startupDuration=2.5;
    int startupPreviewPhase=-1;
    public bool StartupVisible=>startupOverlay?.Visibility==Visibility.Visible;
    public double StartupProgress {get;private set;}
    public bool FixtureInitializationCompleted {get;private set;}
    public double LastStartupElapsed {get;private set;}
    public string StartupPhaseText=>startupStage?.Text??"";
    readonly List<object> startupRuns=new();
    void InitializeIdentity()
    {
        startupTimer.Tick+=(_,_)=>
        {
            StartupProgress=Math.Clamp(startupClock.Elapsed.TotalSeconds/startupDuration,0,1);ApplyStartupPhase(StartupProgress,false);
            if(StartupProgress>=1)FinishStartup();
        };
        Closed+=(_,_)=>startupTimer.Stop();
        
    }
    void EnsureStartup()
    {
        if(startupOverlay!=null)return;
        var grid=new Grid();grid.RowDefinitions.Add(new(){Height=new GridLength(1,GridUnitType.Star)});grid.RowDefinitions.Add(new(){Height=GridLength.Auto});
        var content=new StackPanel{HorizontalAlignment=HorizontalAlignment.Center,VerticalAlignment=VerticalAlignment.Center,MaxWidth=600,Margin=new Thickness(24,8,24,8)};
        startupCore=new CoreVisual{Width=Compact?280:420,Height=Compact?210:315};content.Children.Add(startupCore);
        startupWordmark=Ui.Stack(Ui.Text("HOSTSGUARDIAN",Compact?27:38,"#E7F6FF",true),Ui.Text("SECURITY INTELLIGENCE PLATFORM",Compact?11:15,"#83DFFF"));
        foreach(FrameworkElement child in startupWordmark.Children){if(child is TextBlock t)t.TextAlignment=TextAlignment.Center;child.HorizontalAlignment=HorizontalAlignment.Center;}
        content.Children.Add(startupWordmark);
        var track=new Border{Width=Compact?280:440,Height=8,Background=Ui.Brush("#1B3856"),CornerRadius=new CornerRadius(4),Margin=new Thickness(0,20,0,14)};
        startupFill=new Border{Width=1,Height=8,HorizontalAlignment=HorizontalAlignment.Left,CornerRadius=new CornerRadius(4),Background=new LinearGradientBrush(Color.FromRgb(13,131,226),Color.FromRgb(72,226,255),0)};track.Child=startupFill;content.Children.Add(track);
        startupStage=Ui.Text("Mélytér és fénymező",14,"#B6C6DA");startupStage.TextAlignment=TextAlignment.Center;content.Children.Add(startupStage);
        startupNote=Ui.Text("DEKORATÍV INDÍTÁSI IDŐVONAL • NEM BETÖLTÉSI MÉRÉS",11,"#FFD58A");startupNote.TextAlignment=TextAlignment.Center;content.Children.Add(startupNote);
        grid.Children.Add(content);
        var actions=new WrapPanel{HorizontalAlignment=HorizontalAlignment.Center,Margin=new Thickness(12,8,12,14)};
        foreach(var (text,action,id) in new (string,Action,string)[]{("Felület megnyitása",FinishStartup,"SkipStartup")}){var b=Ui.Button(text,action,id);b.Margin=new Thickness(4);actions.Children.Add(b);}Grid.SetRow(actions,1);grid.Children.Add(actions);
        startupOverlay=new Border{Background=new RadialGradientBrush(Ui.Brush("#15314E").Color,Ui.Brush("#080F1D").Color),Child=grid};Grid.SetRowSpan(startupOverlay,3);Panel.SetZIndex(startupOverlay,100);Surface.Children.Add(startupOverlay);
        AutomationProperties.SetName(startupOverlay,"Dekoratív Core Activation bemutató. Nem valós rendszerállapot vagy betöltési százalék.");
    }
    public void StartStartup(double seconds)
    {
        if(!BackendSessionActive)return;
        EnsureStartup();startupTimer.Stop();startupDuration=Math.Clamp(seconds,.5,10);startupPreviewPhase=-1;StartupProgress=0;FixtureInitializationCompleted=false;
        // Independent, bounded local fixture initialization. No Engine dependency or service start.
        FixtureInitializationCompleted=EngineData.Connected;
        if(CoreVisual.ReducedMotion){startupOverlay!.Visibility=Visibility.Collapsed;FinishStartup();LastStartupElapsed=0;StartupProgress=1;WriteStateReceipt();return;}
        startupOverlay!.Opacity=1;startupOverlay.Visibility=Visibility.Visible;startupClock.Restart();ApplyStartupPhase(0,false);startupTimer.Start();
        if(Find(startupOverlay,"SkipStartup") is Button skip)Dispatcher.BeginInvoke(()=>skip.Focus(),DispatcherPriority.Input);
        WriteStateReceipt();
    }
    void ApplyStartupPhase(double progress,bool preview)
    {
        if(startupCore==null||startupWordmark==null||startupFill==null||startupStage==null||startupNote==null)return;
        startupCore.Reveal=Math.Clamp((progress-.12)/.30,0,1);startupCore.InvalidateVisual();startupWordmark.Opacity=Math.Clamp((progress-.45)/.22,0,1);
        startupFill.Width=Math.Max(1,(Compact?280:440)*progress);
        startupStage.Text=progress<.15?"01 / Mélytér és fénymező":progress<.32?"02 / Absztrakt kapcsolati pontok":progress<.55?"03 / Security Core megjelenése":progress<.77?"04 / Rétegek és fényimpulzusok":progress<.94?"05 / HostsGuardian identitás":"06 / Átmenet a kezelőfelületre";
        if(Loc.English)startupStage.Text=progress<.15?"01 / Depth and light field":progress<.32?"02 / Abstract connection points":progress<.55?"03 / Security Core reveal":progress<.77?"04 / Layers and light pulses":progress<.94?"05 / HostsGuardian identity":"06 / Transition to Control Center";
        startupNote.Text=preview?"MEGÁLLÍTOTT BEMUTATÓFÁZIS • NEM ÉLŐ INICIALIZÁCIÓ":"DEKORATÍV IDŐVONAL • NEM BETÖLTÉSI MÉRÉS";
        if(Loc.English)startupNote.Text=preview?"HELD DEMO PHASE • NOT LIVE INITIALIZATION":"DECORATIVE TIMELINE • NOT LOADING PROGRESS";
    }
    public void AdvanceStartupPhase()
    {
        EnsureStartup();startupTimer.Stop();startupPreviewPhase=(startupPreviewPhase+1)%4;startupOverlay!.Visibility=Visibility.Visible;startupOverlay.Opacity=1;
        StartupProgress=new[]{.08,.35,.68,.94}[startupPreviewPhase];ApplyStartupPhase(StartupProgress,true);WriteStateReceipt();
    }
    public void FinishStartup()
    {
        if(startupOverlay==null)return;
        startupTimer.Stop();LastStartupElapsed=startupClock.Elapsed.TotalSeconds;startupClock.Stop();startupOverlay.Visibility=Visibility.Collapsed;startupPreviewPhase=-1;
        if(!CoreVisual.ReducedMotion){page.BeginAnimation(OpacityProperty,new DoubleAnimation(.72,1,TimeSpan.FromMilliseconds(180)));}
        if(BackendSessionActive){body.Visibility=Visibility.Visible;Navigate("Áttekintés");}else body.Visibility=Visibility.Hidden;
        NavigationButton.Focus();startupRuns.Add(new{duration=startupDuration,actualSeconds=LastStartupElapsed,fixtureReady=FixtureInitializationCompleted,decorative=true});WriteStateReceipt();
    }
    public void SetReducedMotion(bool reduced)
    {
        CoreVisual.ReducedMotion=reduced||!SystemParameters.ClientAreaAnimation;if(CoreVisual.ReducedMotion&&StartupVisible)FinishStartup();
        if(CoreVisual.ReducedMotion){page.BeginAnimation(OpacityProperty,null);page.Opacity=1;page.RenderTransform=Transform.Identity;foreach(var child in page.Children.OfType<FrameworkElement>())child.BeginAnimation(OpacityProperty,null);detailBorder.BeginAnimation(OpacityProperty,null);detailBorder.Opacity=1;detailBorder.RenderTransform=Transform.Identity;}
        foreach(var core in Descendants(Surface).OfType<CoreVisual>())core.RefreshMotion();foreach(var shield in Descendants(Surface).OfType<ShieldVisual>())shield.RefreshMotion();BuildPage();WriteStateReceipt();
    }
    static IEnumerable<DependencyObject> Descendants(DependencyObject root)
    {
        for(int i=0;i<VisualTreeHelper.GetChildrenCount(root);i++){var child=VisualTreeHelper.GetChild(root,i);yield return child;foreach(var next in Descendants(child))yield return next;}
    }
    public void ExitStartup()=>FinishStartup();
    public void SaveMotionRuns(string file)=>File.WriteAllText(file,JsonSerializer.Serialize(startupRuns,new JsonSerializerOptions{WriteIndented=true}));
}

public static class MotionVerification
{
    static async Task Flush(){await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);await Task.Delay(100);}
    public static async Task Run(PrototypeWindow w,string output)
    {
        Directory.CreateDirectory(output);var passed=new List<string>();void Check(bool ok,string name){if(!ok)throw new Exception(name);passed.Add(name);}
        await Flush();var size=(w.ActualWidth,w.ActualHeight);w.SetScenario("Dense");
        w.Navigate("Eszközök");await Flush();Check(w.CurrentTable?.Items.Count==180,"Dense device fixture 180 rows");Check(w.CurrentTable!.EnableRowVirtualization,"DataGrid row virtualization enabled");
        w.Navigate("Tevékenység");await Flush();Check(w.CurrentTable?.Items.Count==600,"Dense activity fixture 600 events");w.CurrentTable!.SelectedIndex=599;w.CurrentTable.ScrollIntoView(w.CurrentTable.SelectedItem);await Flush();Check(w.CurrentTable.SelectedIndex==599,"Last event reachable by scrolling");
        w.Navigate("Domainek és policy");await Flush();Check(w.CurrentTable?.Items.Count==4,"V2.3.1 shared policy fixture has four original rules");
        w.SetScenario("Incident");w.Navigate("Security Insights");await Flush();w.SelectFinding("Primary");await Flush();Check(w.DetailVisible,"Incident evidence details open");w.CloseDetails();
        if(w.Compact){double before=w.MainViewportWidth;w.ToggleNavigation();await Flush();Check(w.NavigationOverlayOpen&&w.NavigationOwnsFocus,"Compact overlay opens with focus");Check(Math.Abs(w.MainViewportWidth-before)<1,"Overlay does not push main content");w.Navigate("Eszközök");await Flush();Check(!w.NavigationOverlayOpen&&w.NavigationButton.IsKeyboardFocused,"Selecting compact menu closes overlay and restores focus");}
        w.Navigate("Áttekintés");w.SetScenario("Fresh");
        var samples=new List<object>();
        foreach(bool reduced in new[]{true,false})
        {
            w.SetReducedMotion(reduced);await Flush();await Task.Delay(1600);var p=Process.GetCurrentProcess();var cpu=p.TotalProcessorTime;long ticks=CoreVisual.TickCount,renders=CoreVisual.RenderCount;int index=CoreVisual.RenderTimes.Count;var clock=Stopwatch.StartNew();await Task.Delay(3200);p.Refresh();clock.Stop();
            var times=CoreVisual.RenderTimes.Skip(index).Order().ToArray();
            samples.Add(new{reduced,wallSeconds=clock.Elapsed.TotalSeconds,cpuSeconds=(p.TotalProcessorTime-cpu).TotalSeconds,cpuOneCorePercent=(p.TotalProcessorTime-cpu).TotalSeconds/clock.Elapsed.TotalSeconds*100,workingSetMiB=p.WorkingSet64/1048576.0,timerTicks=CoreVisual.TickCount-ticks,renders=CoreVisual.RenderCount-renders,meanDrawMs=times.Length==0?0:times.Average(),p95DrawMs=times.Length==0?0:times[(int)((times.Length-1)*.95)]});
            if(reduced)Check(CoreVisual.TickCount==ticks,"Reduced motion has no Core timer ticks");else Check(CoreVisual.TickCount>ticks,"Visible Overview Core animates");
        }
        foreach(double duration in new[]{2.5,4.0})
        {
            var clock=Stopwatch.StartNew();w.StartStartup(duration);await Task.Delay((int)(duration*1000)+400);await Flush();clock.Stop();
            Check(!w.StartupVisible,"Startup completes "+duration);Check(w.LastStartupElapsed>=duration&&w.LastStartupElapsed<duration+1,"Startup duration bounded "+duration);Check(w.FixtureInitializationCompleted,"Fixture initialization independent and complete "+duration);
        }
        // Actual WPF runtime export for an optional animated demonstration, not native screenshots.
        var frames=Path.Combine(output,"motion-frames");Directory.CreateDirectory(frames);w.StartStartup(4);var recording=Stopwatch.StartNew();int frame=0;var frameTimes=new List<double>();
        while(recording.Elapsed.TotalSeconds<4.25)
        {
            await Task.Delay(80);await Dispatcher.Yield(DispatcherPriority.Render);
            frameTimes.Add(recording.Elapsed.TotalMilliseconds);var bitmap=new RenderTargetBitmap((int)Math.Ceiling(w.Surface.ActualWidth),(int)Math.Ceiling(w.Surface.ActualHeight),96,96,PixelFormats.Pbgra32);bitmap.Render(w.Surface);var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));using(var file=File.Create(Path.Combine(frames,$"{frame++:000}.png")))encoder.Save(file);
        }
        w.SetReducedMotion(true);w.StartStartup(4);await Flush();Check(!w.StartupVisible,"Reduced startup skips decorative wait");Check(Math.Abs(w.ActualWidth-size.ActualWidth)<.1&&Math.Abs(w.ActualHeight-size.ActualHeight)<.1,"All motion and density transitions preserve outer size");
        w.SaveMotionRuns(Path.Combine(output,"startup-runs.json"));
        File.WriteAllText(Path.Combine(output,"motion-verification.json"),JsonSerializer.Serialize(new{passed,samples,frames=frame,frameTimesMs=frameTimes,frameExport="Actual WPF visual-tree runtime frames, not native Windows capture. Native screenshots delivered separately.",hardware=RenderCapability.Tier>>16,dpi=VisualTreeHelper.GetDpi(w).DpiScaleX},new JsonSerializerOptions{WriteIndented=true}));
    }
}
