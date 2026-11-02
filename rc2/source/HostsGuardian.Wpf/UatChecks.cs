using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using System.Runtime.InteropServices;
using DesignPrototype.Engine;
namespace DesignPrototype;
public static class UatChecks
{
 [DllImport("user32.dll")]static extern uint GetDpiForWindow(nint hwnd);
 [DllImport("user32.dll")]static extern nint GetWindowDpiAwarenessContext(nint hwnd);
 [DllImport("user32.dll")]static extern bool AreDpiAwarenessContextsEqual(nint a,nint b);
 static object Dpi(PrototypeWindow w)=>new{native=GetDpiForWindow(new WindowInteropHelper(w).Handle),wpf=VisualTreeHelper.GetDpi(w).PixelsPerInchX,perMonitorV2=AreDpiAwarenessContextsEqual(GetWindowDpiAwarenessContext(new WindowInteropHelper(w).Handle),new nint(-4))};
 public static async Task Run(PrototypeWindow w,string output)
 {
  Directory.CreateDirectory(output);var rows=new List<object>();
  void Check(string name,bool pass){rows.Add(new{name,pass});File.WriteAllText(Path.Combine(output,"checks.json"),JsonSerializer.Serialize(new{rows,dpi=Dpi(w),scope="Loopback mock only; no production connection or writes"},new JsonSerializerOptions{WriteIndented=true}));if(!pass)throw new Exception(name);}
  async Task Flush()=>await w.Dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);
  Check("UAT title, offline start and no fake login",w.Title=="HostsGuardian V2.3.1 – UAT"&&!w.EngineMode&&w.UatNoLogin);
  w.Navigate("Beállítások");Check("Connect UI available; no user mock-source control",PrototypeWindow.Find(w.Surface,"UatConnect")!=null&&PrototypeWindow.Find(w.Surface,"RcStartMock")==null);
  await using(var mock=new MockHttpsEngine{ReleaseManagement=true,AutoChange=false})
  {
   mock.Start();await w.AttachUatTestReader(new(mock.Origin,mock.Certificate,()=>mock.Token));
   Check("Read-only reader projects real HTTPS responses without fixture fallback",w.EngineData.Connected&&!w.EngineMock&&w.MockEngine==null&&w.EngineData.Devices.Count>0);
   foreach(bool light in new[]{false,true})
   foreach(var size in new[]{(1360d,850d),(1000d,760d)})
   {
    w.Width=size.Item1;w.Height=size.Item2;w.ChangeTheme(light);await Flush();var outer=(w.ActualWidth,w.ActualHeight);
    foreach(var page in new[]{"Áttekintés","Eszközök","Domainek és policy","Tevékenység","Security Insights","Diagnosztika","Beállítások"})
    {w.Navigate(page);await Flush();Check("Navigation/layout "+page+" "+size+" light="+light,(w.ActualWidth,w.ActualHeight)==outer&&w.UatMainScroll.ViewportHeight>0&&w.UatMainScroll.ViewportWidth>0);}
   }
   w.Navigate("Domainek és policy");await Flush();var input=PrototypeWindow.Find(w.Surface,"RcGlobalDomain") as TextBox;w.Activate();input!.Focus();input.Text="example.invalid";Check("Keyboard focus and domain input",input.IsKeyboardFocusWithin&&input.Text=="example.invalid");
   Check("Live Block/Restore actions disabled",PrototypeWindow.Find(w.Surface,"RcGlobalBlock") is Button{IsEnabled:false}&&PrototypeWindow.Find(w.Surface,"RcGlobalRestore") is Button{IsEnabled:false});
   foreach(bool blocked in new[]{true,false}){w.UatPreview(blocked);await Flush();Check("Read-only confirmation preview "+blocked,PrototypeWindow.Find(w.Surface,"UatWriteLocked") is Button{IsEnabled:false});w.CloseModal();}
   Check("Direct live mutation call cannot bypass lock",await w.ApplyGlobalDomain("example.invalid",true)==null&&await w.ApplyGlobalDomain("example.invalid",false)==null&&mock.Writes==0);
   w.Navigate("Security Insights");await Flush();w.ShowEngineEvidence();await Flush();Check("Evidence panel stays within application frame",w.DetailVisible&&w.ActualWidth==1000&&w.ActualHeight==760);w.CloseDetails();
   w.Navigate("Tevékenység");await Flush();w.UatMainScroll.ScrollToBottom();Check("Main content has scrolling support",w.UatMainScroll.VerticalScrollBarVisibility==ScrollBarVisibility.Auto);
   var poll=w.EnginePolling!;await w.StopEngine();Check("Disconnect stops poller",poll.Stopped&&!w.EngineMode);
   await w.AttachUatTestReader(new(mock.Origin,mock.Certificate,()=>"invalid"));Check("Invalid credential cannot show online data",!w.EngineData.Connected&&w.EngineData.Devices.Count==0&&w.EngineData.ConnectionError==ReadError.Authentication);await w.StopEngine();
   mock.Scenario="503";await w.AttachUatTestReader(new(mock.Origin,mock.Certificate,()=>mock.Token));Check("Unavailable Engine cannot show false online",!w.EngineData.Connected&&w.EngineData.Devices.Count==0);await w.StopEngine();
  }
  // Only the unchanged Core command path is exercised, against the existing loopback fixture.
  foreach(var mode in new[]{"success","conflict","write-failure","readback-failure"})
  {
   await w.StartReleaseMock();var mock=w.MockEngine!;
   if(mode=="conflict")mock.ReleaseConflict=true;if(mode=="write-failure")mock.ReleaseFailWrite=true;if(mode=="readback-failure"){mock.ReleaseFailReadbackAfter=mock.Writes;mock.ReleaseFailReadback=true;}
   var result=await w.ApplyGlobalDomain("example.invalid",true);
   Check("Core global Block regression "+mode,mode.EndsWith("failure")?result?.Stored==false:result?.Stored==true);
   if(mode=="success"){var restored=await w.ApplyGlobalDomain("example.invalid",false);Check("Core Restore preserves unrelated rules",restored?.Stored==true&&!mock.ReleasePolicy.GlobalBlockedDomains.Contains("example.invalid")&&mock.ReleasePolicy.GlobalBlockedDomains.Contains("keep.invalid"));}
   await w.StopEngine();
  }
 }
 public static async Task Live(PrototypeWindow w,string output)
 {
  Directory.CreateDirectory(output);await w.ConnectUat();for(int i=0;i<150&&!w.EngineData.Connected;i++)await Task.Delay(40);
  var views=new List<object>();foreach(var page in new[]{"Áttekintés","Eszközök","Domainek és policy","Tevékenység","Security Insights","Diagnosztika","Beállítások"}){w.Navigate(page);await w.Dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);views.Add(new{page,stable=w.ActualWidth>0&&w.ActualHeight>0});}
  w.Navigate("Domainek és policy");await w.Dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);
  var result=new{status=w.EngineMode&&!w.EngineMock&&w.EngineData.Connected&&w.MockEngine==null&&PrototypeWindow.Find(w.Surface,"RcGlobalBlock") is Button{IsEnabled:false}?"PASS":"FAIL",title=w.Title,instance=w.EngineData.Instance,revision=w.EngineData.Revision,devices=w.EngineData.Devices.Count,events=w.EngineData.Events.Count,requests=w.EngineTransport?.Requests,writeRequests=0,views,dpi=Dpi(w),policyRaw=w.EngineData.Value("/v2/policy")?.GetRawText()};
  File.WriteAllText(Path.Combine(output,"readonly-live.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));var poll=w.EnginePolling;await w.StopEngine();File.WriteAllText(Path.Combine(output,"stopped.json"),JsonSerializer.Serialize(new{stopped=poll?.Stopped==true&&!w.EngineMode}));
 }
}
