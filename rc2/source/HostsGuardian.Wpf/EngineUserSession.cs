using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DesignPrototype.Engine;
namespace DesignPrototype;
public sealed record LabConnection(LiveConfiguration Config,string CredentialDirectory);
public static class LoginLabBackend
{
 public static string Root=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HostsGuardian","V231");
 public static string ConfigurationPath=>Path.Combine(Root,"engine-connection.json");
 public static string CredentialDirectory=>Path.Combine(Root,"credentials");
 public static bool AutoStart{get;set;} // retained for existing test source compatibility; never launches an Engine.
 public static Task<LabConnection> Connect(CancellationToken ct)
 {
  ct.ThrowIfCancellationRequested();
  if(File.Exists(ConfigurationPath))return Task.FromResult(new LabConnection(LiveConfiguration.Load(ConfigurationPath),CredentialDirectory));
  if(!File.Exists(HostsGuardian.Core.Services.PathsService.ConfigPath))throw new InvalidOperationException("Engine-kapcsolat beállítása szükséges.");
  var existing=new HostsGuardian.Core.Services.ConfigService().Load().DnsEngine;
  if(existing.LegacyCredentialPresent)throw new InvalidOperationException("A régi, nem védett credential külön migrációt igényel.");
  var origin=HostsGuardian.Core.Services.ManagementSecurity.Endpoint(existing).ToString();LiveConfiguration.ValidateOrigin(origin);
  return Task.FromResult(new LabConnection(new(origin,existing.TrustedCertificate,existing.CredentialId,20),Path.Combine(HostsGuardian.Core.Services.PathsService.AppFolder,"credentials")));
 }
 public static void Stop(){} // Remote Engine lifetime is never owned by WPF.
}
public sealed class EngineUserSession:IDisposable
{
 readonly HttpClient http;readonly Func<string?> credential;readonly Stopwatch age=new();TimeSpan lifetime;string? token;
 public string Username{get;private set;}=""; public string Role{get;private set;}=""; public Guid[] Devices{get;private set;}=[]; public string? Token=>IsValid?token:null;public bool IsValid=>token!=null&&age.IsRunning&&age.Elapsed<lifetime;
 public EngineUserSession(LabConnection connection)
 {
  var c=connection.Config;var store=new ReadOnlyCredential(connection.CredentialDirectory);credential=()=>store.Read(c.CredentialId);
  http=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false,UseProxy=false,UseCookies=false,ServerCertificateCustomValidationCallback=(_,cert,_,errors)=>ManagementSecurity.ValidateCertificate(cert,c.EnrolledCertificate,errors)}){BaseAddress=LiveConfiguration.ValidateOrigin(c.Origin),Timeout=TimeSpan.FromSeconds(40)};
 }
 async Task<HttpResponseMessage> Send(string path,HttpMethod method,CancellationToken ct,byte[]? body=null)
 {
  var bearer=credential();if(ManagementSecurity.ParseToken(bearer)==null)throw new InvalidOperationException("Credential unavailable");
  using var request=new HttpRequestMessage(method,path);request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",bearer);
  if(token!=null)request.Headers.Add("X-HostsGuardian-Session",token);
  if(body!=null){request.Content=new ByteArrayContent(body);request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/json");}
  return await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,ct).ConfigureAwait(false);
 }
 public async Task<string?> Authenticate(string username,string password,CancellationToken ct)
 {
  using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(8));ct=deadline.Token;
  byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(new{username,password});
  try
  {
   using var response=await Send("/v1/auth/login",HttpMethod.Post,ct,bytes);
   if(!response.IsSuccessStatusCode)return response.StatusCode==HttpStatusCode.TooManyRequests?"Túl sok próbálkozás. Kérlek, várj egy percet.":"A bejelentkezés sikertelen. Ellenőrizd a belépési adatokat.";
   var data=await response.Content.ReadAsByteArrayAsync(ct);if(data.Length>4096)throw new InvalidOperationException();using var json=JsonDocument.Parse(data);var root=json.RootElement;
   var issued=root.GetProperty("sessionToken").GetString();int seconds=root.GetProperty("lifetimeSeconds").GetInt32();
   Username=root.GetProperty("username").GetString()??""; Role=root.GetProperty("role").GetString()??""; Devices=root.GetProperty("devices").EnumerateArray().Select(x=>x.GetGuid()).ToArray(); if(Username.Length==0||Role is not ("Admin" or "Operator" or "Observer")||ManagementSecurity.ParseToken(issued)==null||seconds is <1 or >900)throw new InvalidOperationException();
   token=issued;lifetime=TimeSpan.FromSeconds(seconds);age.Restart();
   using var confirm=await Send("/v1/auth/session",HttpMethod.Get,ct);if(!confirm.IsSuccessStatusCode)throw new InvalidOperationException();
   using var proof=JsonDocument.Parse(await confirm.Content.ReadAsByteArrayAsync(ct));if(!proof.RootElement.GetProperty("authenticated").GetBoolean()||proof.RootElement.GetProperty("username").GetString()!=Username||proof.RootElement.GetProperty("role").GetString()!=Role)throw new InvalidOperationException();
   return null;
  }
  catch(OperationCanceledException){token=null;return "Az Engine nem válaszolt időben, vagy a művelet megszakadt.";}
  catch{token=null;return "Az Engine nem érhető el, vagy a biztonságos kapcsolat nem igazolható.";}
  finally{CryptographicOperations.ZeroMemory(bytes);}
 }
 public async Task Logout(){try{using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(2));if(token!=null)using(await Send("/v1/auth/logout",HttpMethod.Post,stop.Token)){} }catch{}finally{token=null;age.Stop();}}
 public async Task<JsonElement?> Call(string path,object? body=null)
 {
  if(!IsValid)throw new InvalidOperationException("A munkamenet lejárt.");
  return await CallCore(path,body);
 }
 async Task<JsonElement?> CallCore(string path,object? body)
 {
  byte[]? bytes=body==null?null:JsonSerializer.SerializeToUtf8Bytes(body);
  try
  {
   using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(path=="/v1/analyst"?40:10));
   using var response=await Send(path,body==null?HttpMethod.Get:HttpMethod.Post,stop.Token,bytes);
   if(response.StatusCode==HttpStatusCode.Unauthorized){token=null;throw new InvalidOperationException("A munkamenet érvénytelen. Jelentkezz be újra.");}
   if(!response.IsSuccessStatusCode)throw new InvalidOperationException("Az Engine elutasította a műveletet ("+(int)response.StatusCode+"). Frissítsd az adatokat; ellenőrizd a jogosultságot és a megadott értékeket.");
   if(response.StatusCode==HttpStatusCode.NoContent)return null;
   if(response.Content.Headers.ContentLength>1048576)throw new InvalidOperationException("Túl nagy válasz.");
   using var stream=await response.Content.ReadAsStreamAsync(stop.Token);using var memory=new MemoryStream();var buffer=new byte[4096];int count;
   while((count=await stream.ReadAsync(buffer,stop.Token))>0){if(memory.Length+count>1048576)throw new InvalidOperationException("Túl nagy válasz.");memory.Write(buffer,0,count);}
   using var doc=JsonDocument.Parse(memory.ToArray());return doc.RootElement.Clone();
  }
  finally{if(bytes!=null)CryptographicOperations.ZeroMemory(bytes);}
 }
 public Task<JsonElement?> ResetPassword(string resetToken,string password)=>CallCore("/v1/auth/password-reset",new{resetToken,password});
 public void Dispose(){token=null;age.Stop();http.Dispose();}
}


