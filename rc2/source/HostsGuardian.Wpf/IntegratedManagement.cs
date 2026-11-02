using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using DesignPrototype.Engine;
using HostsGuardian.Core.Services;

namespace DesignPrototype;

public sealed record ServerUser(Guid Id,string Name,string Role,bool Enabled,Guid[] Devices,long Version);
public sealed partial class PrototypeWindow
{
 bool IsAdmin=>BackendSessionActive&&userSession?.Role=="Admin";
 bool CanChangeRules=>BackendSessionActive&&userSession?.Role is "Admin" or "Operator";
 void IntegratedAnalystCard()
 {
  var summary=Ui.Text("A diagnosztikai összefoglaló külön kérésre használja a meglévő AI Security Analyst szolgáltatást. Az AI kizárólag elemez és javasol; szabályt nem módosít.");
  var button=Ui.Button("Diagnosztikai elemzés kérése",async()=>await RemoteAction(async()=>
  {
   summary.Text="Elemzés folyamatban…";var result=await userSession!.Call("/v1/analyst",new{question=Loc.English?"Summarize DNS health and available evidence without changing anything.":"Foglald össze a DNS állapotát és az elérhető bizonyítékokat. Ne módosíts semmit.",language=Loc.English?"en":"hu",session_id=Guid.NewGuid().ToString("N")});
   summary.Text=result is {} r?Json.S(r,"answer")??"Nincs igazolt válasz.":"Nincs igazolt válasz.";
  },summary),"RequestScopedAnalysis");page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("AI Security Analyst",21,bold:true),summary,button)));
 }
 void AboveLoginModal(string title,UIElement content){Modal(title,content);if(editorOverlay!=null)Panel.SetZIndex(editorOverlay,200);}
 void ConfigureRemoteConnection()
 {
  var origin=Input("https://192.168.1.1:5380/","RemoteOrigin");var token=new PasswordBox();string certificate="";var certLabel=Ui.Text("Tanúsítvány még nincs kiválasztva.");var feedback=Ui.Text("",13,"#FFD58A");
  var pick=Ui.Button("Megbízható nyilvános Engine-tanúsítvány kiválasztása",()=>
  {
   var dialog=new Microsoft.Win32.OpenFileDialog{Filter="Certificate|*.pem;*.crt;*.cer|All files|*.*"};if(dialog.ShowDialog(this)!=true)return;
   try{var raw=File.ReadAllBytes(dialog.FileName);if(raw.Length>32768)throw new InvalidDataException();using var cert=System.Text.Encoding.ASCII.GetString(raw).Contains("-----BEGIN CERTIFICATE-----")?X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(raw)):new X509Certificate2(raw);if(cert.HasPrivateKey||cert.NotAfter.ToUniversalTime()<DateTime.UtcNow)throw new InvalidDataException();certificate=Convert.ToBase64String(cert.RawData);certLabel.Text="SHA-256: "+cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256);}
   catch{feedback.Text="A nyilvános tanúsítvány érvénytelen vagy lejárt.";}
  },"ChooseEngineCertificate");
  AboveLoginModal("Linux Engine-kapcsolat",Ui.Stack(Ui.Text("A címet és a tanúsítvány ujjlenyomatát megbízható, külön csatornán ellenőrizd. Nincs automatikus bizalom vagy TLS-megkerülés."),Field("HTTPS origin",origin),pick,certLabel,Field("Meglévő management token (64 hex karakter)",token),feedback,Actions(("Kapcsolat mentése",()=>
  {
   try
   {
    var uri=LiveConfiguration.ValidateOrigin(origin.Text.Trim());if(certificate.Length==0||HostsGuardian.Core.Services.ManagementSecurity.ParseToken(token.Password)==null)throw new InvalidDataException();
    Directory.CreateDirectory(LoginLabBackend.Root);var id=Guid.NewGuid().ToString("N");new ProtectedCredentialStore(LoginLabBackend.CredentialDirectory).Write(id,token.Password);token.Clear();
    var config=new LiveConfiguration(uri.AbsoluteUri,certificate,id,20);File.WriteAllText(LoginLabBackend.ConfigurationPath,JsonSerializer.Serialize(config));CloseModal();SessionNotice="Engine-kapcsolat elmentve. Jelentkezz be.";ShowLogin(false);
   }
   catch{token.Clear();feedback.Text="Nem sikerült menteni. Ellenőrizd a címet, tanúsítványt és tokent.";}
  },"SaveEngineConnection"))));
 }
 void ResetPasswordForm()
 {
  var token=new PasswordBox();var password=new PasswordBox();var confirm=new PasswordBox();var feedback=Ui.Text("",13,"#FFD58A");
  AboveLoginModal("Jelszó biztonságos visszaállítása",Ui.Stack(Ui.Text("Az Admin által kiadott egyszer használatos visszaállító token 10 percig érvényes. A jelszó legyen legalább 15 karakter."),Field("Visszaállító token",token),Field("Új jelszó",password),Field("Jelszó ismét",confirm),feedback,Actions(("Jelszó visszaállítása",async()=>
  {
   try{if(password.Password!=confirm.Password)throw new InvalidOperationException("A jelszavak eltérnek.");using var client=new EngineUserSession(await ConnectionProvider(default));await client.ResetPassword(token.Password,password.Password);token.Clear();password.Clear();confirm.Clear();CloseModal();SessionNotice="Jelszó frissítve. Jelentkezz be.";ShowLogin(false);}
   catch(Exception e){feedback.Text=e is InvalidOperationException?e.Message:"Az Engine nem érhető el.";password.Clear();confirm.Clear();}
  },"CompletePasswordReset"))));
 }
 async Task RemoteAction(Func<Task> action,TextBlock feedback)
 {
  try{if(!BackendSessionActive)throw new InvalidOperationException("Jelentkezz be újra.");await action();}
  catch(Exception e){feedback.Text=e is InvalidOperationException?e.Message:"Nem sikerült hitelesített választ kapni az Engine-től. Az eredmény nem igazolt.";}
 }
 void IntegratedSettings()
 {
  page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Megjelenés",21,bold:true),Actions(("Sötét",()=>ChangeTheme(false),"RcDark"),("Világos",()=>ChangeTheme(true),"RcLight"),("Magyar",()=>ChangeLanguage(false),"RcHu"),("English",()=>ChangeLanguage(true),"RcEn")))));
  page.Children.Add(Ui.Card(Ui.Stack(Ui.Text("Hitelesített Engine-kapcsolat",21,bold:true),Ui.Text(uatConnectionNotice),Ui.Text((userSession?.Username??"")+" · "+(userSession?.Role??"")+" · 15 perces munkamenet"),Actions(("Kijelentkezés",()=>SignOut(),"RemoteSignOut")))));
  if(IsAdmin){var content=Ui.Stack(Ui.Text("Felhasználók és jogosultságok",21,bold:true));page.Children.Add(Ui.Card(content));_=LoadServerUsers(content);}
  else page.Children.Add(Ui.Text("A felhasználókezelés kizárólag Admin jogosultsággal érhető el."));
  page.Children.Add(Ui.Text("Az Engine-konfiguráció szerkesztéséhez a jelenlegi API nem ad általános konfigurációs végpontot. Ez a felület nem szimulál konfigurációmentést."));
 }
 async Task LoadServerUsers(StackPanel content)
 {
  var error=Ui.Text("Betöltés…",13,"#FFD58A");content.Children.Add(error);
  await RemoteAction(async()=>
  {
   if(!IsAdmin)return;var data=await userSession!.Call("/v1/users");var users=data!.Value.Deserialize<ServerUser[]>(new JsonSerializerOptions{PropertyNameCaseInsensitive=true})!;
   if(!IsAdmin)return;content.Children.Remove(error);var table=Table(users,("Felhasználó","Name",180),("Szerepkör","Role",110),("Engedélyezett","Enabled",100));content.Children.Add(table);content.Children.Add(error);error.Text="";
   content.Children.Add(Actions(("Új felhasználó",()=>ServerUserEditor(null),"CreateServerUser"),("Szerepkör / eszközök",()=>{if(table.SelectedItem is ServerUser u)ServerUserEditor(u);},"EditServerUser"),("Letiltás / engedélyezés",async()=>await RemoteAction(async()=>{if(table.SelectedItem is ServerUser u){await userSession!.Call($"/v1/users/{u.Id}/update",new{expectedVersion=u.Version,role=u.Role,enabled=!u.Enabled,devices=u.Devices});BuildPage();}},error),"DisableServerUser"),("Munkamenetek visszavonása",async()=>await RemoteAction(async()=>{if(table.SelectedItem is ServerUser u){await userSession!.Call($"/v1/users/{u.Id}/revoke",new{});BuildPage();}},error),"RevokeServerSessions"),("Jelszó-visszaállítás",async()=>await RemoteAction(async()=>{if(table.SelectedItem is ServerUser u){var result=await userSession!.Call($"/v1/users/{u.Id}/reset",new{});var reset=new TextBox{Text=result!.Value.GetProperty("resetToken").GetString(),IsReadOnly=true,TextWrapping=TextWrapping.Wrap};Modal("Egyszer használatos visszaállító token",Ui.Stack(Ui.Text("Csak most jelenik meg. 10 percig érvényes; add át a felhasználónak biztonságos csatornán. A korábbi munkamenetek visszavonva."),reset));}},error),"ResetServerPassword")));
  },error);
 }
 void ServerUserEditor(ServerUser? user)
 {
  if(!IsAdmin)return;var name=Input(user?.Name??"","ServerUserName");name.IsReadOnly=user!=null;var role=new ComboBox{ItemsSource=new[]{"Admin","Operator","Observer"},SelectedItem=user?.Role??"Observer",MinWidth=180,Margin=new Thickness(0,0,0,10)};
  var password=new PasswordBox();var devices=new StackPanel();var selected=(user?.Devices??[]).ToHashSet();
  foreach(var device in Json.A(Json.P(EngineData.Value("/v2/policy"),"policy"),"devices"))
  {
   if(!Guid.TryParse(Json.S(device,"deviceId"),out var id))continue;var box=new CheckBox{Content=(Json.S(device,"name")??id.ToString())+" · "+id,IsChecked=selected.Contains(id)};box.Checked+=(_,_)=>selected.Add(id);box.Unchecked+=(_,_)=>selected.Remove(id);devices.Children.Add(box);
  }
  void UpdateDeviceState()=>devices.IsEnabled=Convert.ToString(role.SelectedItem)=="Operator";role.SelectionChanged+=(_,_)=>UpdateDeviceState();UpdateDeviceState();
  var error=Ui.Text("",13,"#FFD58A");var content=Ui.Stack(Field("Felhasználónév",name),Field("Szerepkör",role),Ui.Text("Eszközök – csak Operatorhoz. A hozzárendelés az Engine-ben tárolódik."),devices,error);
  if(user==null)content.Children.Add(Field("Egyedi kezdeti jelszó (legalább 15 karakter)",password));
  content.Children.Add(Actions(("Mentés az Engine-ben",async()=>await RemoteAction(async()=>
  {
   var selectedRole=Convert.ToString(role.SelectedItem)!;var ids=selectedRole=="Operator"?selected.ToArray():Array.Empty<Guid>();
   try{if(user==null)await userSession!.Call("/v1/users",new{name=name.Text.Trim(),role=selectedRole,devices=ids,password=password.Password});else await userSession!.Call($"/v1/users/{user.Id}/update",new{expectedVersion=user.Version,role=selectedRole,enabled=user.Enabled,devices=ids});CloseModal();BuildPage();}finally{password.Clear();}
  },error),"SaveServerUser")));Modal(user==null?"Új Engine-felhasználó":"Engine-jogosultság módosítása",content);
 }
 void IntegratedRulesPage()=>BuildDomainBlockList();
}
