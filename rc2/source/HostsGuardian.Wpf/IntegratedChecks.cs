using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using DesignPrototype.Engine;

namespace DesignPrototype;
public sealed partial class PrototypeWindow
{
 internal async Task RunIntegratedChecks(string fixtureFile,string output)
 {
  Directory.CreateDirectory(output);using var fixture=JsonDocument.Parse(File.ReadAllBytes(fixtureFile));var root=fixture.RootElement;var password=root.GetProperty("password").GetString()!;
  var config=root.GetProperty("configuration").Deserialize<LiveConfiguration>()!;ConnectionProvider=_=>Task.FromResult(new LabConnection(config,root.GetProperty("credentialDirectory").GetString()!));
  if(!System.Net.IPAddress.IsLoopback(System.Net.IPAddress.Parse(new Uri(config.Origin).Host)))throw new InvalidOperationException("QA permits loopback fixture only");
  var rows=new List<object>();void Check(string name,bool pass){rows.Add(new{name,pass});File.WriteAllText(Path.Combine(output,"wpf-rbac.json"),JsonSerializer.Serialize(new{rows,dpi=System.Windows.Media.VisualTreeHelper.GetDpi(this).PixelsPerDip,source="Actual WPF and pinned HTTPS Engine"},new JsonSerializerOptions{WriteIndented=true}));if(!pass)throw new InvalidOperationException(name);}
  Button? Find(string id)=>Descendants(Surface).OfType<Button>().FirstOrDefault(b=>AutomationProperties.GetAutomationId(b)==id);
  async Task Wait(Func<bool> done){var until=DateTime.UtcNow.AddSeconds(10);while(!done()&&DateTime.UtcNow<until)await Task.Delay(50);if(!done())throw new InvalidOperationException("UI operation timed out");}
  async Task Login(string name,bool animate=false)
  {
   SetReducedMotion(!animate);var pending=LoginToEngine(name,password);bool shield=false,startup=false,hidden=true;
   while(!pending.IsCompleted||StartupVisible||LoginVisible&&BackendSessionActive){await Task.Delay(25);shield|=LoginShieldProgress>0;startup|=StartupVisible;if(StartupVisible)hidden&=!DashboardVisible;}
   await pending;Check(name+" authenticated",BackendSessionActive&&EngineData.Connected&&!EngineMock&&userSession?.Username==name);
   if(animate){Check("Original ShieldVisual unlock executed",shield);Check("Startup animation executed before Dashboard",startup&&hidden);}
  }
  Check("Login visible without active session",LoginVisible&&!BackendSessionActive&&!DashboardVisible);
  foreach(bool light in new[]{true,false}){ChangeTheme(light);await Task.Delay(100);Check("Login theme fits "+light,LoginScrollableHeight<1);}
  await LoginToEngine("admin",Guid.NewGuid().ToString());Check("Wrong password never unlocks",LoginVisible&&!BackendSessionActive&&!DashboardVisible&&(LoginShieldProgress??0)==0);
  await Login("admin",true);if(EngineData.Instance!="wpf-rbac-fixture")throw new InvalidOperationException("QA refuses non-fixture Engine before any user or policy write");Check("Admin role is server-provided",IsAdmin&&CanChangeRules);
  await RunBlockListUiChecks(output, Check);
  foreach(var view in new[]{"Áttekintés","Eszközök","Tevékenység","Security Insights","Diagnosztika","Domainek és policy","Beállítások"}){Navigate(view);await Task.Delay(100);Check("Admin navigation "+view,BackendSessionActive&&!LoginVisible);}
  await Wait(()=>Find("CreateServerUser")!=null);Find("CreateServerUser")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));await Task.Delay(100);
  Descendants(Surface).OfType<TextBox>().Single(t=>AutomationProperties.GetAutomationId(t)=="ServerUserName").Text="qa.created.in.wpf";
  Descendants(editorOverlay!).OfType<ComboBox>().Single().SelectedItem="Operator";Descendants(editorOverlay!).OfType<CheckBox>().First().IsChecked=true;Descendants(editorOverlay!).OfType<PasswordBox>().Single().Password=password;
  Find("SaveServerUser")!.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));await Wait(()=>editorOverlay==null);
  var users=await userSession!.Call("/v1/users");var created=users!.Value.EnumerateArray().Single(u=>u.GetProperty("name").GetString()=="qa.created.in.wpf");Check("WPF create persists role and assignment in Engine",created.GetProperty("role").GetString()=="Operator"&&created.GetProperty("devices").GetArrayLength()==1);
  await EndEngineSession("Test logout");Check("Logout returns to login",LoginVisible&&!BackendSessionActive&&!DashboardVisible);
  await Login("operator");Check("Operator cannot administer users",!IsAdmin&&CanChangeRules&&userSession!.Devices.Length==1);
  Navigate("Beállítások");await Task.Delay(100);Check("Operator management UI hidden",Find("CreateServerUser")==null);
  Navigate("Domainek és policy");await Wait(()=>Find("AddBlockDomain")?.IsEnabled==true);Check("Operator assigned rule control available",Find("AddBlockDomain")?.IsEnabled==true);
  var policy=await userSession!.Call("/v2/policy");Check("Operator actual HTTPS read is scoped",policy!.Value.GetProperty("policy").GetProperty("devices").GetArrayLength()==1);
  await EndEngineSession("Test logout");await Login("observer");Check("Observer cannot modify",!IsAdmin&&!CanChangeRules);
  Navigate("Domainek és policy");await Task.Delay(100);Check("Observer rule button disabled",Find("AddBlockDomain")?.IsEnabled==false);
  var observerPolicy=await userSession!.Call("/v2/policy");Check("Observer sees all devices",observerPolicy!.Value.GetProperty("policy").GetProperty("devices").GetArrayLength()==2);
  Width=1000;Height=760;await EndEngineSession("Test logout");await Task.Delay(150);Check("Compact login fits",LoginVisible&&LoginScrollableHeight<1);
  Check("Demo authenticator cannot activate",!DemoLogin("admin",password)&&!BackendSessionActive);
 }
}
