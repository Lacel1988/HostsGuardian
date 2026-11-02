using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using DesignPrototype.Engine;
namespace DesignPrototype;
public sealed partial class PrototypeWindow
{
 EngineUserSession? userSession;CancellationTokenSource? signIn;long authEpoch;bool loginBusy,endingSession;
 readonly DispatcherTimer userLease=new(){Interval=TimeSpan.FromSeconds(1)};
 internal bool BackendSessionActive=>SessionState=="Active"&&userSession?.IsValid==true;
 internal Func<CancellationToken,Task<LabConnection>> ConnectionProvider=LoginLabBackend.Connect;
 void InitializeLoginUat()
 {
  Title="HostsGuardian V2.3.1 – Engine / RBAC";SessionState="SignedOut";ApplyTheme();InitializeIdentity();DetailsButton.IsEnabled=false;scenarioButton.IsEnabled=false;ShowLogin(false);
  userLease.Tick+=async(_,_)=>{if(SessionState=="Active"&&userSession?.IsValid!=true)await EndEngineSession("A bejelentkezés lejárt. Kérlek, jelentkezz be újra.");};userLease.Start();
  Closing+=(_,_)=>{authEpoch++;signIn?.Cancel();userLease.Stop();userSession?.Dispose();userSession=null;LoginLabBackend.Stop();};
 }
 internal async Task LoginToEngine(string username,string password,PasswordBox? input=null,TextBlock? error=null,Button? submit=null)
 {
  if(loginBusy)return;loginBusy=true;long epoch=++authEpoch;signIn?.Cancel();signIn=new();if(submit!=null)submit.IsEnabled=false;if(error!=null)error.Text="Engine-hitelesítés folyamatban…";
  EngineUserSession? candidate=null;
  try
  {
   var connection=await ConnectionProvider(signIn.Token);if(epoch!=authEpoch)return;
   candidate=new EngineUserSession(connection);var failure=await candidate.Authenticate(username,password,signIn.Token);input?.Clear();
   if(failure!=null){LastMessage=failure;if(error!=null)error.Text=failure;return;}
   if(epoch!=authEpoch||!candidate.IsValid)return;
   var store=new ReadOnlyCredential(connection.CredentialDirectory);var validated=candidate;
   EngineMock=false;await AttachEngine(new EngineReader(connection.Config.Origin,connection.Config.EnrolledCertificate,()=>store.Read(connection.Config.CredentialId),session:()=>validated.Token),20,false);
   if(epoch!=authEpoch||!EngineData.Connected||!candidate.IsValid){await StopEngine();LastMessage="Az Engine állapota nem olvasható hitelesítetten. Nem indult munkamenet.";if(error!=null)error.Text=LastMessage;return;}
   userSession=candidate;candidate=null;uatConnectionNotice="Linux Engine: "+connection.Config.Origin;SessionState="Active";Account=new(){Name=userSession.Username,Role=userSession.Role};
   EnginePolling!.Start();var accepted=loginOverlay;
   if(accepted!=null){foreach(var shield in Descendants(accepted).OfType<ShieldVisual>())shield.Unlock();if(MotionEnabled)await RemoveAcceptedLogin(accepted);else{Surface.Children.Remove(accepted);loginOverlay=null;StartStartup(AutoStartupDuration);}}
  }
  catch(OperationCanceledException){LastMessage="A bejelentkezés megszakadt.";if(error!=null)error.Text=LastMessage;}
  catch{LastMessage="Az Engine-kapcsolat nem indítható. Ellenőrizd a kapcsolat beállítását. Nem indult munkamenet.";if(error!=null)error.Text=LastMessage;}
  finally{input?.Clear();if(candidate!=null){await candidate.Logout();candidate.Dispose();}loginBusy=false;if(submit!=null)submit.IsEnabled=true;}
 }
 internal async Task EndEngineSession(string notice)
 {
  if(endingSession)return;endingSession=true;
  try{authEpoch++;signIn?.Cancel();SessionState="SignedOut";body.Visibility=Visibility.Hidden;SessionNotice=notice;var old=userSession;userSession=null;await StopEngine();EngineData=new();if(old!=null){await old.Logout();old.Dispose();}ShowLogin(false);}
  finally{endingSession=false;}
 }
 void QueueSessionFailure()
 {
  if(SessionState!="Active")return;SessionState="SignedOut";body.Visibility=Visibility.Hidden;
  Dispatcher.BeginInvoke(async()=>await EndEngineSession("A hitelesített Engine-kapcsolat megszakadt vagy lejárt. Kérlek, jelentkezz be újra."));
 }
}

