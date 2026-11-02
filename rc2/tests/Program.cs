using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using HostsGuardian.DnsEngine;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;

if (args[0] == "--resume-wpf-fixture") { await WpfFixture.Resume(args[1]); return; }
if (args[0] == "--wpf-fixture") { await WpfFixture.Run(args[1]); return; }
var output = Path.GetFullPath(args[0]); Directory.CreateDirectory(output);
var fixture = Path.Combine(output, "private-fixture-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(fixture);
if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(fixture, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
var results = new List<object>();
void Check(string name, bool pass) { results.Add(new { name, pass }); File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true })); if (!pass) throw new InvalidOperationException(name); }
void Rejected(string name, Action run, int status) { try { run(); Check(name, false); } catch (AuthFailure f) { Check(name, f.Status == status); } }
var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
var clock = new Clock(); var storeFile = Path.Combine(fixture, "users.json");
using var users = new UserDirectory(storeFile, clock);
Check("No automatic accounts", !users.Initialized);
Rejected("Weak initial password rejected", () => users.InitializeAdmin("admin"), 400);
users.InitializeAdmin(password); Check("One initialized administrator only", users.Initialized);
Rejected("Bootstrap permanently closed", () => users.InitializeAdmin(password), 409);
Check("Store has Argon2id hash, no plaintext", File.ReadAllText(storeFile).Contains("argon2id") && !File.ReadAllText(storeFile).Contains(password));
var adminLogin = await users.Login("admin", password, default); var admin = users.Authenticate(adminLogin.SessionToken)!;
var device1 = Guid.NewGuid(); var device2 = Guid.NewGuid(); ISet<Guid> registered = new HashSet<Guid> { device1, device2 };
var op = users.Create(admin, "operator", UserRole.Operator, [device1], password, registered);
var obs = users.Create(admin, "observer", UserRole.Observer, [], password, registered);
Check("Accounts manually created by Admin API logic", users.List(admin).Length == 3);
Rejected("Last administrator cannot be disabled", () => users.Update(admin, admin.Id, admin.Version, UserRole.Admin, false, [], registered), 409);
Rejected("Last administrator cannot be demoted", () => users.Update(admin, admin.Id, admin.Version, UserRole.Observer, true, [], registered), 409);
Rejected("Unknown assignment rejected", () => users.Create(admin, "bad-user", UserRole.Operator, [Guid.NewGuid()], password, registered), 400);
var operatorLogin = await users.Login("operator", password, default); var operatorActor = users.Authenticate(operatorLogin.SessionToken)!;
var observerLogin = await users.Login("observer", password, default); var observerActor = users.Authenticate(observerLogin.SessionToken)!;
Rejected("Operator cannot enumerate accounts", () => users.List(operatorActor), 403);
Rejected("Observer cannot create accounts", () => users.Create(observerActor, "forbidden", UserRole.Admin, [], password, registered), 403);

var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)); var tokenFile = Path.Combine(fixture, "management-token"); File.WriteAllText(tokenFile, token);
using var key = RSA.Create(2048); var csr = new CertificateRequest("CN=rbac-tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); csr.CertificateExtensions.Add(san.Build());
csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true)); csr.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
using var cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
var certFile = Path.Combine(fixture, "cert.pem"); var keyFile = Path.Combine(fixture, "key.pem"); File.WriteAllText(certFile, cert.ExportCertificatePem()); File.WriteAllText(keyFile, key.ExportPkcs8PrivateKeyPem());
var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
var config = new EngineConfig { ApiBindIp = "127.0.0.1", ApiPort = port, DnsListenPort = 15353, CredentialPath = tokenFile, CertificatePath = certFile, CertificateKeyPath = keyFile, PolicyFilePath = Path.Combine(fixture, "policy.json") };
var settings = EngineSettings.FromConfig(config); var rules = new RuleStore("rbac-tests");
await using var dns = new DnsProxyServer(rules, settings); var policy = new PolicyApplicationService(rules, new PolicyPersistence(config.PolicyFilePath), dns.PolicyState);
await using var api = new ApiServer(policy, settings, dns.RuntimeStatus, users: users); api.InitializePolicyForStartup();
var initial = policy.ReadFullPolicy(); Check("Fixture registration committed", policy.ReplaceFull(new(initial.Revision, initial.Policy with { Devices = [new(device1, "Assigned", null, "test", "manual"), new(device2, "Other", null, "test", "manual")] }, initial.InstanceId)).Success);
await api.StartAsync(); var pin = Convert.ToBase64String(cert.RawData);
using var http = new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false, ServerCertificateCustomValidationCallback = (_, c, _, e) => ManagementSecurity.ValidateCertificate(c, pin, e) }) { BaseAddress = new Uri($"https://127.0.0.1:{port}"), Timeout = TimeSpan.FromSeconds(10) };
async Task<HttpResponseMessage> Send(string path, string method, string? session, object? body = null, bool management = true)
{ using var request = new HttpRequestMessage(new(method), path); if (management) request.Headers.Authorization = new("Bearer", token); if (session != null) request.Headers.Add(UserDirectory.SessionHeader, session); if (body != null) request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"); return await http.SendAsync(request); }
async Task<int> Status(string path, string method, string? session, object? body = null, bool management = true) { using var r = await Send(path, method, session, body, management); return (int)r.StatusCode; }
Check("Management bearer still mandatory", await Status("/v1/auth/session", "GET", adminLogin.SessionToken, management: false) == 401);
Check("Management bearer alone cannot bypass RBAC", await Status("/v2/policy", "GET", null) == 401);
Check("User input role cannot override identity", await Status("/v1/auth/login", "POST", null, new { username = "observer", password, role = "Admin" }) == 400);
using (var login = await Send("/v1/auth/login", "POST", null, new { username = "admin", password })) Check("Real pinned HTTPS login", login.IsSuccessStatusCode && login.Headers.CacheControl?.NoStore == true);
Check("Observer full policy read allowed", await Status("/v2/policy", "GET", observerLogin.SessionToken) == 200);
using (var response = await Send("/v1/users", "GET", adminLogin.SessionToken)) { var raw = await response.Content.ReadAsStringAsync(); Check("Admin account list never exposes hashes or passwords", response.IsSuccessStatusCode && !raw.Contains("argon2id") && !raw.Contains("password", StringComparison.OrdinalIgnoreCase) && !raw.Contains("sessionToken")); }
using (var response = await Send("/v2/policy", "GET", operatorLogin.SessionToken)) { var raw = await response.Content.ReadAsStringAsync(); Check("Operator read excludes other device", response.IsSuccessStatusCode && raw.Contains(device1.ToString()) && !raw.Contains(device2.ToString())); }
Check("Observer cannot read credential records", await Status("/v1/users", "GET", observerLogin.SessionToken) == 403);
foreach (var path in new[] { "/v2/policy/replace", "/v2/bindings/replace", "/safe-mode/enter", "/v2/discovery/refresh", "/rules/blocked/add", "/v1/users", "/future/mutation" }) Check("Observer rejects mutation " + path, await Status(path, "POST", observerLogin.SessionToken, new { }) == 403);
foreach (var path in new[] { "/v2/policy/replace", "/v2/bindings/replace", "/safe-mode/enter", "/v2/discovery/refresh", "/rules/blocked/add" }) Check("Operator rejects unscoped mutation " + path, await Status(path, "POST", operatorLogin.SessionToken, new { }) == 403);
object DeviceRule(Guid id) { var read = policy.ReadFullPolicy(); return new { expectedInstanceId = read.InstanceId, expectedRevision = read.Revision, deviceId = id, domain = "example.invalid", state = "Block" }; }
Check("Operator cross-device mutation denied", await Status("/v1/access/device-rule", "POST", operatorLogin.SessionToken, DeviceRule(device2)) == 403);
Check("Operator assigned-device mutation allowed", await Status("/v1/access/device-rule", "POST", operatorLogin.SessionToken, DeviceRule(device1)) == 200);
Check("Policy audit identifies authenticated actor", policy.Audit.Read().Any(e => e.Operation == "PolicyCommit" && e.ActorEvidence.Contains("operator")));
Check("Observer scoped mutation denied", await Status("/v1/access/device-rule", "POST", observerLogin.SessionToken, DeviceRule(device1)) == 403);
Check("Other device and global policy retained", policy.ReadFullPolicy().Policy.Devices.Length == 2 && policy.ReadFullPolicy().Policy.Overrides.All(r => r.DeviceId == device1) && policy.ReadFullPolicy().Policy.GlobalBlockedDomains.Length == 0);
var revision = policy.ReadFullPolicy().Revision; Check("Operator global mutation denied", await Status("/v1/access/global-rule", "POST", operatorLogin.SessionToken, new { expectedInstanceId = "rbac-tests", expectedRevision = revision, domain = "example.invalid", blocked = true }) == 403);
await BlockListChecks.Run(policy, device1, device2, adminLogin.SessionToken, operatorLogin.SessionToken, observerLogin.SessionToken, (p,m,s,b,a) => Send(p,m,s,b,a), Check, fixture);
users.Update(admin, op.Id, op.Version, UserRole.Operator, true, [device2], registered);
Check("Assignment change revokes old session", await Status("/v2/policy", "GET", operatorLogin.SessionToken) == 401);
var reset = users.BeginReset(admin, obs.Id); Check("Password reset revokes sessions immediately", users.Authenticate(observerLogin.SessionToken) == null);
users.CompleteReset(reset, password + "-replacement"); Rejected("Reset is single use", () => users.CompleteReset(reset, password), 401);
Check("Logout invalidates token", await Status("/v1/auth/logout", "POST", adminLogin.SessionToken) == 204 && users.Authenticate(adminLogin.SessionToken) == null);
clock.Advance(TimeSpan.FromMinutes(1)); var fresh = await users.Login("admin", password, default); clock.Advance(TimeSpan.FromSeconds(901)); Check("Server monotonic session expiry", users.Authenticate(fresh.SessionToken) == null);
for (int i = 0; i < 5; i++) { try { await users.Login("missing-user", password, default); } catch (AuthFailure) { } }
try { await users.Login("admin", password, default); Check("Rate limit", false); } catch (AuthFailure f) { Check("Rate limit", f.Status == 429); }
clock.Advance(TimeSpan.FromMinutes(1)); var recovered = await users.Login("admin", password, default); Check("Rate limit recovers", users.Authenticate(recovered.SessionToken) != null);
var refreshedAdmin = users.Authenticate(recovered.SessionToken)!;
var currentOperator = users.List(refreshedAdmin).Single(u => u.Id == op.Id);
users.Update(refreshedAdmin, op.Id, currentOperator.Version, UserRole.Operator, false, [device2], registered);
try { await users.Login("operator", password, default); Check("Disabled user rejected", false); } catch(AuthFailure f) { Check("Disabled user rejected", f.Status == 401); }
Rejected("Stale user version rejected", () => users.Update(refreshedAdmin, op.Id, currentOperator.Version, UserRole.Observer, true, [], registered), 409);
var disabledReset=users.BeginReset(refreshedAdmin,op.Id);users.CompleteReset(disabledReset,password+"-disabled-reset");
Check("Password reset never re-enables a disabled account", !users.List(refreshedAdmin).Single(u=>u.Id==op.Id).Enabled);
await api.DisposeAsync(); users.Dispose();
await using (var required = new ApiServer(policy, settings, dns.RuntimeStatus, userAuthorizationRequired: true))
{
    var retained = policy.ReadFullPolicy();
    try { await required.StartAsync(); Check("Missing user store cannot enable legacy bearer-only API", false); }
    catch (InvalidOperationException) { Check("Missing user store closes management and retains policy", !required.IsRunning && policy.ReadFullPolicy() == retained); }
}
using (var reopened = new UserDirectory(storeFile, clock))
{
    var session = await reopened.Login("admin", password, default); var principal = reopened.Authenticate(session.SessionToken)!;
    var retained = reopened.List(principal).Single(u => u.Id == op.Id);
    Check("Accounts and assignment persist across restart", !retained.Enabled && retained.Role == "Operator" && retained.Devices.SequenceEqual(new[]{device2}));
    Check("Server restart invalidates earlier sessions", reopened.Authenticate(recovered.SessionToken) == null);
    Rejected("Restart does not reopen initialization", () => reopened.InitializeAdmin(password), 409);
}
Check("No passwords or tokens in public result file", !File.ReadAllText(Path.Combine(output, "results.json")).Contains(password) && !File.ReadAllText(Path.Combine(output, "results.json")).Contains(token));
Console.WriteLine($"RBAC: {results.Count} PASS");

sealed class Clock : TimeProvider { long ticks; public override long TimestampFrequency => TimeSpan.TicksPerSecond; public override long GetTimestamp() => ticks; public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow.AddTicks(ticks); public void Advance(TimeSpan value) => ticks += value.Ticks; }
