using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
namespace DesignPrototype;
public sealed partial class PrototypeWindow
{
 internal bool LoginVisible=>loginOverlay!=null;
 internal bool DashboardVisible=>body.Visibility==Visibility.Visible&&!LoginVisible&&!StartupVisible;
 internal void ExpireLocalSessionForTest()=>userSession?.Dispose();
}
public static class LoginChecks
{
 static byte[] Secret()
 {
  if(Console.IsInputRedirected)return Encoding.UTF8.GetBytes(Console.ReadLine()??"");
  var chars=new List<char>();while(true){var key=Console.ReadKey(true);if(key.Key==ConsoleKey.Enter)break;if(!char.IsControl(key.KeyChar))chars.Add(key.KeyChar);}var data=Encoding.UTF8.GetBytes(chars.ToArray());for(int i=0;i<chars.Count;i++)chars[i]='\0';return data;
 }
 public static async Task Run(PrototypeWindow w,string output)
 {
  Directory.CreateDirectory(output);var rows=new List<object>();
  void Check(string test,bool pass){rows.Add(new{test,pass});File.WriteAllText(Path.Combine(output,"wpf-login.json"),JsonSerializer.Serialize(new{rows,dpi=System.Windows.Media.VisualTreeHelper.GetDpi(w).PixelsPerInchX,source="Actual isolated Kestrel HTTPS Engine, not mock login"},new JsonSerializerOptions{WriteIndented=true}));if(!pass)throw new Exception(test);}
  async Task Flush()=>await w.Dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);
  var secret=Secret();try
  {
   await Flush();Check("Original login visible at startup",w.LoginVisible&&w.SessionState=="SignedOut"&&!w.DashboardVisible);
   Check("Empty password field, single admin",PrototypeWindow.Find(w.Surface,"LoginPassword") is PasswordBox{Password:""}&&PrototypeWindow.Find(w.Surface,"LoginName") is TextBox{Text:"admin"});
   foreach(bool light in new[]{false,true}){w.ChangeTheme(light);await Flush();Check("Login fits, theme "+light,w.LoginVisible&&w.LoginScrollableHeight<1);}
   w.ChangeTheme(false);await Flush();
   var original=w.ConnectionProvider;w.ConnectionProvider=_=>throw new IOException("Isolated unavailable test");await w.LoginToEngine("admin",Guid.NewGuid().ToString());Check("Unavailable Engine never activates or animates",w.SessionState!="Active"&&w.LoginVisible&&!w.StartupVisible&&(w.LoginShieldProgress??0)==0);w.ConnectionProvider=original;
   var real=await original(CancellationToken.None);var chooser=new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback,0);chooser.Start();int closedPort=((System.Net.IPEndPoint)chooser.LocalEndpoint).Port;chooser.Stop();
   w.ConnectionProvider=_=>Task.FromResult(real with{Config=real.Config with{Origin=$"https://127.0.0.1:{closedPort}/"}});await w.LoginToEngine("admin",Encoding.UTF8.GetString(secret));Check("Actual unreachable HTTPS endpoint never activates",w.LoginVisible&&w.SessionState!="Active"&&!w.StartupVisible);
   await using(var wrongCert=new DesignPrototype.Engine.MockHttpsEngine()){w.ConnectionProvider=_=>Task.FromResult(real with{Config=real.Config with{EnrolledCertificate=wrongCert.Certificate}});await w.LoginToEngine("admin",Encoding.UTF8.GetString(secret));Check("Wrong enrolled certificate rejects login before activation",w.LoginVisible&&w.SessionState!="Active"&&!w.StartupVisible&&(w.LoginShieldProgress??0)==0);}w.ConnectionProvider=original;
   Check("Demo authenticator cannot activate session",!w.DemoLogin("admin",Encoding.UTF8.GetString(secret))&&w.SessionState!="Active");
   await w.LoginToEngine("admin",Guid.NewGuid().ToString());Check("Real Engine rejects wrong password without animation",w.SessionState!="Active"&&w.LoginVisible&&!w.DashboardVisible&&!w.StartupVisible&&(w.LoginShieldProgress??0)==0);
   w.SetReducedMotion(false);var pending=w.LoginToEngine("admin",Encoding.UTF8.GetString(secret));bool sawUnlock=false,sawStartup=false,hiddenDuringStartup=true;
   var until=DateTime.UtcNow.AddSeconds(15);while(DateTime.UtcNow<until&&(!pending.IsCompleted||w.StartupVisible||w.LoginVisible)){await Task.Delay(30);if(w.LoginShieldProgress>0)sawUnlock=true;if(w.StartupVisible)sawStartup=true;if(w.StartupVisible)hiddenDuringStartup&=!w.DashboardVisible;}
   await pending;Check("Dashboard remains hidden throughout startup animation",hiddenDuringStartup);Check("Server authentication precedes Active state",w.BackendSessionActive&&w.EngineData.Connected&&!w.EngineMock&&w.SessionState=="Active");
   Check("Original unlock and startup animations executed",sawUnlock&&sawStartup);Check("Dashboard visible after animation",w.DashboardVisible&&w.CurrentView=="Áttekintés");
   foreach(var page in new[]{"Eszközök","Domainek és policy","Tevékenység","Security Insights","Diagnosztika","Beállítások"}){w.Navigate(page);await Flush();Check("Authenticated navigation "+page,w.BackendSessionActive&&!w.LoginVisible);}
   Check("Policy writes remain impossible",await w.ApplyGlobalDomain("example.invalid",true)==null);
   w.ExpireLocalSessionForTest();await Task.Delay(1300);await Flush();Check("Expired/invalid local session returns to login",w.SessionState!="Active"&&w.LoginVisible&&!w.DashboardVisible&&!w.EngineMode);
   w.SetReducedMotion(true);await w.LoginToEngine("admin",Encoding.UTF8.GetString(secret));await Flush();Check("Reduced-motion still requires actual Engine authentication",w.BackendSessionActive&&w.DashboardVisible);
   await w.EndEngineSession("Kijelentkezési teszt.");Check("Explicit logout hides Dashboard and stops poller",w.LoginVisible&&!w.DashboardVisible&&!w.EngineMode&&w.SessionState!="Active");
   w.Width=1000;w.Height=760;await Flush();Check("Compact login remains usable",w.LoginVisible&&w.LoginScrollableHeight<1);
  }
  finally{CryptographicOperations.ZeroMemory(secret);LoginLabBackend.Stop();}
 }
}
