using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using HostsGuardian.DnsEngine;
using HostsGuardian.Core.Services;

static class WpfFixture
{
 public static async Task Resume(string output)
 {
  var root=Path.GetFullPath(output);using var data=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root,"fixture.json")));
  var origin=new Uri(data.RootElement.GetProperty("configuration").GetProperty("Origin").GetString()!);
  if(!IPAddress.IsLoopback(IPAddress.Parse(origin.Host)))throw new InvalidOperationException("Only isolated loopback fixture can resume");
  using var users=new UserDirectory(Path.Combine(root,"users.json"));
  var cfg=new EngineConfig{ApiBindIp="127.0.0.1",ApiPort=origin.Port,DnsListenPort=15353,CredentialPath=Path.Combine(root,"management"),CertificatePath=Path.Combine(root,"cert.pem"),CertificateKeyPath=Path.Combine(root,"key.pem"),PolicyFilePath=Path.Combine(root,"policy.json")};
  var settings=EngineSettings.FromConfig(cfg);var rules=new RuleStore("wpf-rbac-fixture");await using var dns=new DnsProxyServer(rules,settings);var policy=new PolicyApplicationService(rules,new PolicyPersistence(cfg.PolicyFilePath),dns.PolicyState);
  await using var api=new ApiServer(policy,settings,dns.RuntimeStatus,users:users);api.InitializePolicyForStartup();await api.StartAsync();
  Console.WriteLine("Private WPF fixture resumed without resetting policy or users");
  var until=DateTime.UtcNow.AddMinutes(2);while(DateTime.UtcNow<until&&!File.Exists(Path.Combine(root,"stop-resume")))await Task.Delay(200);
 }
 public static async Task Run(string output)
 {
  var root=Path.GetFullPath(output);Directory.CreateDirectory(root);
  if(OperatingSystem.IsWindows()){var sid=WindowsIdentity.GetCurrent().User!;var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);acl.SetOwner(sid);acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));new DirectoryInfo(root).SetAccessControl(acl);}
  else File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
  string password=Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
  using var users=new UserDirectory(Path.Combine(root,"users.json"));users.InitializeAdmin(password);var login=await users.Login("admin",password,default);var admin=users.Authenticate(login.SessionToken)!;
  var first=Guid.NewGuid();var second=Guid.NewGuid();var registered=new HashSet<Guid>{first,second};
  users.Create(admin,"operator",UserRole.Operator,[first],password,registered);users.Create(admin,"observer",UserRole.Observer,[],password,registered);users.Logout(login.SessionToken);
  var management=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));File.WriteAllText(Path.Combine(root,"management"),management);
  using var key=RSA.Create(2048);var request=new CertificateRequest("CN=wpf-rbac-fixture",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);var san=new SubjectAlternativeNameBuilder();san.AddIpAddress(IPAddress.Loopback);request.CertificateExtensions.Add(san.Build());request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new("1.3.6.1.5.5.7.3.1")},true));using var cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(1));
  File.WriteAllText(Path.Combine(root,"cert.pem"),cert.ExportCertificatePem());File.WriteAllText(Path.Combine(root,"key.pem"),key.ExportPkcs8PrivateKeyPem());
  var socket=new TcpListener(IPAddress.Loopback,0);socket.Start();int port=((IPEndPoint)socket.LocalEndpoint).Port;socket.Stop();var cfg=new EngineConfig{ApiBindIp="127.0.0.1",ApiPort=port,DnsListenPort=15353,CredentialPath=Path.Combine(root,"management"),CertificatePath=Path.Combine(root,"cert.pem"),CertificateKeyPath=Path.Combine(root,"key.pem"),PolicyFilePath=Path.Combine(root,"policy.json")};var settings=EngineSettings.FromConfig(cfg);var rules=new RuleStore("wpf-rbac-fixture");await using var dns=new DnsProxyServer(rules,settings);var policy=new PolicyApplicationService(rules,new PolicyPersistence(cfg.PolicyFilePath),dns.PolicyState);
  var now=DateTimeOffset.UtcNow;dns.RequestProcessor.Bindings.Replace(new(0,[new("192.0.2.10",null,first,"isolated fixture",now.AddSeconds(-1),now.AddMinutes(10),true),new("192.0.2.11",null,second,"isolated fixture",now.AddSeconds(-1),now.AddMinutes(10),true)]));
  await using var api=new ApiServer(policy,settings,dns.RuntimeStatus,bindings:dns.RequestProcessor.Bindings,users:users);api.InitializePolicyForStartup();var read=policy.ReadFullPolicy();if(!policy.ReplaceFull(new(read.Revision,read.Policy with{Devices=[new(first,"Assigned device",null,"test","manual"),new(second,"Other device",null,"test","manual")]},read.InstanceId)).Success)throw new InvalidOperationException();await api.StartAsync();
  var id=Guid.NewGuid().ToString("N");var credentialDirectory=Path.Combine(root,"credentials");if(OperatingSystem.IsWindows())new ProtectedCredentialStore(credentialDirectory).Write(id,management);
  File.WriteAllText(Path.Combine(root,"fixture.json"),JsonSerializer.Serialize(new{password,credentialDirectory,configuration=new{Origin=$"https://127.0.0.1:{port}/",EnrolledCertificate=Convert.ToBase64String(cert.RawData),CredentialId=id,PollSeconds=20}}));Console.WriteLine("Private WPF fixture ready");
  var deadline=DateTime.UtcNow.AddMinutes(10);while(DateTime.UtcNow<deadline&&!File.Exists(Path.Combine(root,"stop")))await Task.Delay(200);
 }
}
