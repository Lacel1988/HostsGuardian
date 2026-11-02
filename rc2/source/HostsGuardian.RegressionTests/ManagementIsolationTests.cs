using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using HostsGuardian.DnsEngine;

internal static class ManagementIsolationTests
{
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    private static async Task Until(Func<bool> condition, CancellationToken ct)
    { while (!condition()) await Task.Delay(10, ct); }

    private static Phase5DTests.Fixture Fixture(string root)
    {
        var directory = Path.Combine(root, "management-isolation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        foreach (var name in new[] { "temporary-cert.pem", "temporary-key.pem", "temporary-token" })
            File.Copy(Path.Combine(root, name), Path.Combine(directory, name));
        var fixture = new Phase5DTests.Fixture(directory);
        Check(fixture.Policy.Replace(["explicit.invalid"]).Success, "Fixture policy commit failed");
        return fixture;
    }

    private static byte[] Query()
    {
        var bytes = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in "explicit.invalid".Split('.'))
        { bytes.Add((byte)label.Length); bytes.AddRange(Encoding.ASCII.GetBytes(label)); }
        bytes.AddRange(new byte[] { 0, 0, 1, 0, 1 }); return bytes.ToArray();
    }

    private static void Blocked(byte[] response)
    { Check(response.Length > 16 && response[7] == 1 && response[^4..].SequenceEqual(new byte[4]), "Filtering response absent"); }

    private static async Task Filtering(Phase5DTests.Fixture f, CancellationToken ct)
    {
        using var udp = new UdpClient();
        await udp.SendAsync(Query(), new IPEndPoint(IPAddress.Loopback, f.Config.DnsListenPort), ct);
        Blocked((await udp.ReceiveAsync(ct)).Buffer);
        using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, f.Config.DnsListenPort, ct);
        var query = Query(); var stream = tcp.GetStream();
        await stream.WriteAsync(new byte[] { (byte)(query.Length >> 8), (byte)query.Length }.Concat(query).ToArray(), ct);
        var prefix = new byte[2]; await stream.ReadExactlyAsync(prefix, ct);
        var response = new byte[(prefix[0] << 8) | prefix[1]]; await stream.ReadExactlyAsync(response, ct); Blocked(response);
        Check(f.Upstream.Available == 0, "Blocked query escaped to upstream");
    }

    private static void PortsReleased(Phase5DTests.Fixture f)
    {
        using var udp = new UdpClient(f.Config.DnsListenPort);
        var tcp = new TcpListener(IPAddress.Any, f.Config.DnsListenPort); tcp.Start(); tcp.Stop();
        var api = new TcpListener(IPAddress.Loopback, f.Config.ApiPort); api.Start(); api.Stop();
    }

    public static async Task Run(Func<string, Func<Task>, Task> test, string directory)
    {
        foreach (var failure in new[] { "expired", "missing", "malformed", "mismatched-key", "wrong-EKU", "credential-missing" })
            await test("Management isolation startup " + failure + " preserves UDP/TCP filtering and policy", async () =>
            {
                await using var f = Fixture(directory);
                var policy = File.ReadAllBytes(f.Config.PolicyFilePath);
                if (failure == "missing") File.Delete(f.Config.CertificatePath);
                if (failure == "malformed") File.WriteAllText(f.Config.CertificatePath, "NOT A CERTIFICATE");
                if (failure == "credential-missing") File.Delete(f.Config.CredentialPath);
                if (failure == "mismatched-key")
                { using var key = RSA.Create(2048); File.WriteAllText(f.Config.CertificateKeyPath, key.ExportPkcs8PrivateKeyPem()); }
                if (failure is "expired" or "wrong-EKU")
                {
                    using var key = RSA.Create(2048);
                    var request = new CertificateRequest("CN=ISOLATED-TEST", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    var eku = new OidCollection { new(failure == "expired" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") };
                    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
                    using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3),
                        DateTimeOffset.UtcNow.AddDays(failure == "expired" ? -1 : 1));
                    File.WriteAllText(f.Config.CertificatePath, cert.ExportCertificatePem());
                    File.WriteAllText(f.Config.CertificateKeyPath, key.ExportPkcs8PrivateKeyPem());
                }
                using var stop = new CancellationTokenSource(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var started = DateTimeOffset.UtcNow;
                var lifetime = new EngineLifetime(f.Api, f.Dns).RunAsync(stop.Token);
                try
                {
                    await Until(() => f.Api.GetDnsStatus().RuntimeState == "Degraded", deadline.Token);
                    var status = f.Api.GetDnsStatus();
                    Check(!f.Api.IsRunning && !status.ManagementListening && status.ManagementState == "Faulted" &&
                        status.FilteringEnabled && !status.EmergencySafeMode && status.PolicyRevision == 1, "Unsafe degraded status");
                    Check(EngineLog.RecentEvents().Any(e => e.AtUtc >= started && e.Component == "Management" &&
                        e.Level == "ERROR" && e.Message.Contains(failure == "credential-missing" ? "credential" : "certificate")), "Missing actionable management failure log");
                    await Filtering(f, deadline.Token); await Task.Delay(50, deadline.Token); await Filtering(f, deadline.Token);
                    Check(!lifetime.IsCompleted && policy.SequenceEqual(File.ReadAllBytes(f.Config.PolicyFilePath)), "Policy or lifetime changed");
                    using var probe = new TcpClient();
                    try { await probe.ConnectAsync(IPAddress.Loopback, f.Config.ApiPort, deadline.Token); throw new Exception("Unexpected management fallback listener"); }
                    catch (SocketException) { }
                }
                finally { stop.Cancel(); Check(await lifetime.WaitAsync(deadline.Token) == 0, "Partial shutdown failed"); }
                Check(!f.Dns.IsRunning && !f.Api.IsRunning && f.Dns.ActiveRequestCount == 0, "Orphan resources");
                PortsReleased(f);
            });

        await test("Management isolation runtime API host stop preserves real UDP/TCP filtering", async () =>
        {
            await using var f = Fixture(directory); var policy = File.ReadAllBytes(f.Config.PolicyFilePath);
            using var stop = new CancellationTokenSource(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var lifetime = new EngineLifetime(f.Api, f.Dns).RunAsync(stop.Token);
            try
            {
                await Until(() => f.Api.GetDnsStatus().RuntimeState == "Running", deadline.Token);
                await Filtering(f, deadline.Token);
                // Simulates host termination, not a whole-process crash or an OS service failure.
                await f.Api.StopAsync();
                await Until(() => f.Api.GetDnsStatus().ManagementState == "Faulted", deadline.Token);
                await Filtering(f, deadline.Token);
                Check(!lifetime.IsCompleted && f.Api.GetDnsStatus().RuntimeState == "Degraded" &&
                    policy.SequenceEqual(File.ReadAllBytes(f.Config.PolicyFilePath)), "Runtime failure crossed fault boundary");
            }
            finally { stop.Cancel(); Check(await lifetime.WaitAsync(deadline.Token) == 0, "Runtime degraded shutdown failed"); }
            PortsReleased(f);
        });

        await test("Management isolation occupied HTTPS port preserves UDP/TCP filtering", async () =>
        {
            await using var f = Fixture(directory);
            var occupied = new TcpListener(IPAddress.Loopback, f.Config.ApiPort) { ExclusiveAddressUse = true }; occupied.Start();
            using var stop = new CancellationTokenSource(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var lifetime = new EngineLifetime(f.Api, f.Dns).RunAsync(stop.Token);
            try
            {
                await Until(() => f.Api.GetDnsStatus().RuntimeState == "Degraded", deadline.Token);
                await Filtering(f, deadline.Token);
                Check(!f.Api.IsRunning && !lifetime.IsCompleted && EngineLog.RecentEvents().Any(e =>
                    e.Component == "Management" && e.Message.Contains("HTTPS port unavailable")), "Unreported port conflict");
            }
            finally { stop.Cancel(); Check(await lifetime.WaitAsync(deadline.Token) == 0, "Port-conflict shutdown failed"); occupied.Stop(); }
            PortsReleased(f);
        });

        await test("Management isolation runtime Safe Mode is not an independent filtering policy", async () =>
        {
            await using var f = Fixture(directory);
            using var stop = new CancellationTokenSource(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var lifetime = new EngineLifetime(f.Api, f.Dns).RunAsync(stop.Token);
            try
            {
                await Until(() => f.Api.GetDnsStatus().RuntimeState == "Running", deadline.Token);
                Check(f.Policy.SetSafeMode(true).Success, "Fixture Safe Mode failed");
                await f.Api.StopAsync();
                Check(await lifetime.WaitAsync(deadline.Token) == 1 && !f.Dns.IsRunning &&
                    f.Api.GetDnsStatus().RuntimeState == "Faulted", "API-less Safe Mode bypass continued");
            }
            finally { stop.Cancel(); await lifetime.WaitAsync(deadline.Token); }
            PortsReleased(f);
        });

        await test("Management isolation TLS failure does not hide fatal DNS bind failure", async () =>
        {
            await using var f = Fixture(directory); File.Delete(f.Config.CertificatePath);
            using var occupied = new UdpClient(new IPEndPoint(IPAddress.Any, f.Config.DnsListenPort));
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            Check(await new EngineLifetime(f.Api, f.Dns).RunAsync(deadline.Token) == 1 &&
                !f.Dns.IsRunning && !f.Api.IsRunning && f.Api.GetDnsStatus().RuntimeState == "Faulted", "DNS bind failure swallowed");
            occupied.Dispose(); PortsReleased(f);
        });

        foreach (var invalid in new[] { "missing", "corrupt" })
            await test("Management isolation rejects unavailable HTTPS with " + invalid + " policy", async () =>
            {
                await using var f = Fixture(directory);
                // A fresh policy service must load the on-disk failure, not the seeded in-memory policy.
                if (invalid == "missing") File.Delete(f.Config.PolicyFilePath); else File.WriteAllText(f.Config.PolicyFilePath, "{corrupt");
                File.Delete(f.Config.CertificatePath);
                var rules = new RuleStore("invalid-policy");
                await using var dns = new DnsProxyServer(rules, f.Settings);
                await using var api = new ApiServer(new PolicyApplicationService(rules, new PolicyPersistence(f.Config.PolicyFilePath), dns.PolicyState), f.Settings, dns.RuntimeStatus);
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                Check(await new EngineLifetime(api, dns).RunAsync(deadline.Token) == 1 && !dns.IsRunning && !api.IsRunning,
                    "Untrusted policy obtained management-independent DNS fallback");
                Check(dns.RuntimeStatus.GetSnapshot().RuntimeState == "Faulted" &&
                    (invalid == "missing" ? dns.RuntimeStatus.GetSnapshot().PolicyRevision == 0 : !dns.RuntimeStatus.GetSnapshot().PolicyLoaded), "False policy health");
                PortsReleased(f);
            });
    }
}
