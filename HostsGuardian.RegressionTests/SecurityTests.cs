using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
internal static class SecurityTests
{
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static int Port() { var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port; }
    public static async Task Run(Action<string,Action> test, Func<string,Func<Task>,Task> asyncTest, string directory)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var wrong = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var store = new ProtectedCredentialStore(Path.Combine(directory, "protected"));
        var id = Guid.NewGuid().ToString("N");
        test("credential parsing and strict authorization", () =>
        {
            var expected = ManagementSecurity.ParseToken(token)!;
            foreach (var headers in new[] { Array.Empty<string>(), new[] { "" }, new[] { "Bearer " }, new[] { "Bearer malformed" }, new[] { "Bearer " + wrong }, new[] { "Bearer " + token, "Bearer " + token }, new[] { "Bearer " + token + ",Bearer " + token } })
                Check(!ManagementSecurity.Authorize(headers, expected), "Invalid authorization accepted");
            Check(ManagementSecurity.Authorize(new[] { "Bearer " + token }, expected), "Valid token rejected");
        });
        test("DPAPI round-trip and corrupt/missing credential fail closed", () =>
        {
            store.Write(id, token); Check(store.Read(id) == token, "DPAPI roundtrip failed");
            Check(!Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(directory,"protected",id+".bin"))).Contains(token), "Plaintext protected file");
            Check(store.Read(Guid.NewGuid().ToString("N")) == null, "Missing credential accepted");
            File.WriteAllText(Path.Combine(directory,"protected",id+".bin"), "corrupt"); Check(store.Read(id) == null, "Corrupt credential accepted"); store.Write(id, token);
        });
        test("normal serialization and sentinel export/log redaction", () =>
        {
            var cfg = new AppConfig(); cfg.DnsEngine.ApiToken = token;
            Check(!JsonSerializer.Serialize(cfg).Contains(token), "Serialized token");
            var entry = new AuditLogEntry { Message = "Bearer " + token + " " + token };
            var exporter = new StatusExportService();
            Check(!exporter.ExportActivityCsv(new[] { entry }).Contains(token) && !exporter.ExportActivityJson(new[] { entry }).Contains(token), "Export leaked token");
            Check(!SecretRedactor.Clean(entry.Message).Contains(token), "Log redaction leaked token");
            var logPath = Path.Combine(directory,"audit-fixture.log"); new AuditLogService(logPath).Write(entry.Message);
            Check(!File.ReadAllText(logPath).Contains(token), "Actual log leaked token");
        });
        test("explicit migration protects before removal and remains recoverable", () =>
        {
            var path = Path.Combine(directory,"migration.json");
            File.WriteAllText(path, "{\"DnsEngine\":{\"ApiToken\":\""+token+"\"}}");
            var original = File.ReadAllText(path); var service = new ConfigService(path); var cfg = service.Load();
            Check(cfg.DnsEngine.LegacyCredentialPresent, "Legacy credential undetected");
            try { service.Save(cfg); throw new Exception("Silent plaintext removal"); } catch (InvalidOperationException) { }
            try { service.MigrateCredential(cfg, new FailingStore()); throw new Exception("Migration falsely succeeded"); } catch (IOException) { }
            Check(File.ReadAllText(path) == original, "Failed protection destroyed original");
            service.MigrateCredential(cfg,store);
            Check(!File.ReadAllText(path).Contains(token) && store.Read(cfg.DnsEngine.CredentialId) == token, "Migration lost credential");
        });
        test("migration configuration write failure preserves original credential", () =>
        {
            var path = Path.Combine(directory,"locked-migration.json");
            File.WriteAllText(path,"{\"DnsEngine\":{\"ApiToken\":\""+token+"\"}}");
            var original = File.ReadAllText(path); var service = new ConfigService(path); var cfg = service.Load();
            using (var locked = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
            {
                try { service.MigrateCredential(cfg,store); throw new Exception("Locked migration succeeded"); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                Check(File.ReadAllText(path) == original && cfg.DnsEngine.CredentialId == "", "Failed replacement destroyed original");
            }
        });
        await asyncTest("connection error categories and missing credentials never expose secrets", async () =>
        {
            var cfg = new DnsEngineConfig { Address = "fixture.invalid", ManagementPort = 3000, ApiToken = token };
            foreach (var sample in new[] { (ConnectionState.Timeout, (Exception)new OperationCanceledException(token)),
                (ConnectionState.Unreachable, new HttpRequestException(HttpRequestError.NameResolutionError,token)),
                (ConnectionState.NetworkFailure,new HttpRequestException(HttpRequestError.Unknown,token)) })
            {
                var adapter = new DnsEngineService(() => new HttpClient(new FixtureHandler(_ => throw sample.Item2)));
                var result = await adapter.TestConnectionAsync(cfg);
                Check(result.State == sample.Item1 && !result.Message.Contains(token),"Unsafe error category");
            }
            foreach (var status in new[] { HttpStatusCode.OK, HttpStatusCode.InternalServerError })
            {
                var adapter = new DnsEngineService(() => new HttpClient(new FixtureHandler(_ => new HttpResponseMessage(status) { Content = new StringContent(token) })));
                var result = await adapter.TestConnectionAsync(cfg);
                Check(result.State == (status == HttpStatusCode.OK ? ConnectionState.Incompatible : ConnectionState.EngineError) && !result.Message.Contains(token),"Unsafe response body");
            }
            cfg.ApiToken = "";
            var missing = await new DnsEngineService(() => throw new Exception("Should not send"),store).TestConnectionAsync(cfg);
            Check(missing.State == ConnectionState.CredentialUnavailable,"Missing credential sent request");
        });
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,true));
        var eku = new OidCollection(); eku.Add(new Oid("1.3.6.1.5.5.7.3.1")); request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku,true));
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1));
        var certPath = Path.Combine(directory,"temporary-cert.pem"); var keyPath = Path.Combine(directory,"temporary-key.pem");
        File.WriteAllText(certPath,certificate.ExportCertificatePem()); File.WriteAllText(keyPath,key.ExportPkcs8PrivateKeyPem());
        var tokenPath = Path.Combine(directory,"temporary-token"); File.WriteAllText(tokenPath,token);
        var config = new EngineConfig { ApiBindIp = "127.0.0.1", ApiPort = Port(), DnsListenPort = Port(), UpstreamDnsIpv4 = "127.0.0.1", UpstreamDnsPort = Port(), UpstreamTimeoutMs = 50, CredentialPath = tokenPath, CertificatePath = certPath, CertificateKeyPath = keyPath, PolicyFilePath = Path.Combine(directory, "security-policy.json") };
        var rules = new RuleStore("security-fixture"); rules.SetBlockedDomains(new[] { "explicit.invalid" });
        Check(new PolicyApplicationService(rules, new PolicyPersistence(config.PolicyFilePath)).Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
        var dns = new DnsProxyServer(rules,config); var api = new ApiServer(rules,config,dns);
        var enrollment = Convert.ToBase64String(certificate.RawData);
        test("explicit certificate trust checks identity name and validity", () =>
        {
            Check(ManagementSecurity.ValidateCertificate(certificate,enrollment,SslPolicyErrors.RemoteCertificateChainErrors), "Enrolled certificate rejected");
            Check(!ManagementSecurity.ValidateCertificate(certificate,"",SslPolicyErrors.RemoteCertificateChainErrors), "Unenrolled certificate accepted");
            Check(!ManagementSecurity.ValidateCertificate(certificate,enrollment,SslPolicyErrors.RemoteCertificateNameMismatch), "Name mismatch accepted");
            using var expired = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3),DateTimeOffset.UtcNow.AddDays(-1));
            Check(!ManagementSecurity.ValidateCertificate(expired,Convert.ToBase64String(expired.RawData),SslPolicyErrors.None), "Expired certificate accepted");
        });
        await asyncTest("invalid Engine security configuration opens no listener", async () =>
        {
            foreach (var value in new[] { "", "invalid", " " })
            {
                File.WriteAllText(tokenPath,value);
                try { await api.StartAsync(); throw new Exception("Invalid credential started API"); } catch (InvalidOperationException) { }
                Check(!api.IsRunning, "Invalid startup left listener active");
                using var socket = new TcpClient();
                try { await socket.ConnectAsync(IPAddress.Loopback,config.ApiPort); throw new Exception("Listener opened"); } catch (SocketException) { }
            }
            File.WriteAllText(tokenPath,token);
            var originalPath = config.CertificatePath; config.CertificatePath = Path.Combine(directory,"missing-cert");
            try { await api.StartAsync(); throw new Exception("Missing certificate accepted"); } catch (InvalidOperationException) { }
            config.CertificatePath = originalPath;
        });
        await api.StartAsync();
        try
        {
            using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, ServerCertificateCustomValidationCallback = (_,cert,_,errors) => ManagementSecurity.ValidateCertificate(cert,enrollment,errors) });
            var endpoint = $"https://127.0.0.1:{config.ApiPort}";
            await asyncTest("all management endpoints authenticate before policy access", async () =>
            {
                foreach (var route in new[] { "/", "/health", "/dns/status", "/rules/blocked", "/rules/blocked/replace", "/rules/blocked/add", "/rules/blocked/remove", "/unknown" })
                foreach (var header in new[] { "", "Bearer ", "Bearer invalid", "Bearer "+wrong, "Bearer "+token+",Bearer "+token })
                {
                    using var message = new HttpRequestMessage(route.Contains("replace") || route.EndsWith("add") || route.EndsWith("remove") ? HttpMethod.Post : HttpMethod.Get,endpoint+route);
                    if (header != "") message.Headers.TryAddWithoutValidation("Authorization",header);
                    message.Content = new StringContent("malformed");
                    using var response = await http.SendAsync(message); Check(response.StatusCode == HttpStatusCode.Unauthorized,"Unauthorized route accepted: "+route);
                }
                Check(rules.GetBlockedDomains().SequenceEqual(new[] { "explicit.invalid" }),"Rejected request mutated policy");
            });
            var clientConfig = new DnsEngineConfig { Address = "127.0.0.1", ManagementPort = config.ApiPort, TrustedCertificate = enrollment, CredentialId = id };
            var client = new DnsEngineService(credentials:store);
            await asyncTest("authenticated draft connection test is policy and configuration read-only", async () =>
            {
                var before = JsonSerializer.Serialize(clientConfig); var policy = rules.GetBlockedDomains();
                var result = await client.TestConnectionAsync(clientConfig);
                Check(result.Ok && result.Transport != null && !result.Transport.UdpListening,"Authenticated test failed: "+result.Message);
                Check(before == JsonSerializer.Serialize(clientConfig) && policy.SequenceEqual(rules.GetBlockedDomains()),"Connection test changed state");
            });
            await asyncTest("trust and authentication errors are sanitized", async () =>
            {
                clientConfig.TrustedCertificate = ""; var result = await client.TestConnectionAsync(clientConfig);
                Check(result.State == ConnectionState.TrustFailure && !result.Message.Contains(token),"Trust failure not distinguished");
                clientConfig.TrustedCertificate = enrollment; clientConfig.ApiToken = wrong;
                result = await client.TestConnectionAsync(clientConfig); Check(result.State == ConnectionState.AuthenticationFailed,"Wrong token accepted"); clientConfig.ApiToken = "";
            });
            await asyncTest("malformed and oversized authorized requests preserve rules", async () =>
            {
                foreach (var body in new[] { "{", "{}", "{\"blocked\":[\"new.invalid\",12]}", "{\"blocked\":[\"new.invalid\",\"bad name\"]}", new string('x',70000) })
                {
                    using var message = new HttpRequestMessage(HttpMethod.Post,endpoint+"/rules/blocked/replace"); message.Headers.Authorization = new AuthenticationHeaderValue("Bearer",token); message.Content = new StringContent(body);
                    using var response = await http.SendAsync(message); Check(!response.IsSuccessStatusCode,"Malformed update accepted");
                    Check(!(await response.Content.ReadAsStringAsync()).Contains(token),"Error leaked credential");
                    Check(rules.GetBlockedDomains().SequenceEqual(new[] { "explicit.invalid" }),"Malformed update mutated policy");
                }
                Check((await client.PushBlockedDomainsAsync(clientConfig,new[] { "authorized.invalid" })).ok,"Authorized update failed");
            });
            await asyncTest("DNS fixture cannot invoke management policy mutations", async () =>
            {
                dns.Start(); var before = rules.GetBlockedDomains();
                using var udp = new UdpClient(); await udp.SendAsync(Encoding.ASCII.GetBytes("POST /rules/blocked/replace"),new IPEndPoint(IPAddress.Loopback,config.DnsListenPort));
                await Task.Delay(100); Check(before.SequenceEqual(rules.GetBlockedDomains()),"DNS mutated management policy"); dns.Stop();
            });
        }
        finally { dns.Stop(); await api.StopAsync(); }
        await asyncTest("HTTPS redirects are refused without sending to destination", async () =>
        {
            var calls = 0; var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
            var port = Port(); builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback,port,e => e.UseHttps(certificate)));
            await using var redirect = builder.Build(); redirect.Run(ctx => { calls++; ctx.Response.StatusCode = 302; ctx.Response.Headers.Location = "http://127.0.0.1:1/secret"; return Task.CompletedTask; });
            await redirect.StartAsync();
            try
            {
                var cfg = new DnsEngineConfig { Address = "127.0.0.1", ManagementPort = port, TrustedCertificate = enrollment, ApiToken = token };
                cfg.TrustedCertificate = "";
                var rejected = await new DnsEngineService().TestConnectionAsync(cfg);
                Check(rejected.State == ConnectionState.TrustFailure && calls == 0, "Untrusted server received management request");
                cfg.TrustedCertificate = enrollment;
                var result = await new DnsEngineService().TestConnectionAsync(cfg);
                Check(result.State == ConnectionState.Incompatible && calls == 1,"Redirect followed");
            }
            finally { await redirect.StopAsync(); }
        });
    }
    private sealed class FixtureHandler(Func<HttpRequestMessage,HttpResponseMessage> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct) => Task.FromResult(send(request)); }
    private sealed class FailingStore : ICredentialStore
    { public string? Read(string id) => null; public void Write(string id,string token) => throw new IOException("fixture storage failure"); public void Delete(string id) {} }
}
