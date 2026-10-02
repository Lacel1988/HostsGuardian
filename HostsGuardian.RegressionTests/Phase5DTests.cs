using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class Phase5DTests
{
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    private static int Port()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
    private static CancellationTokenSource Deadline() => new(TimeSpan.FromSeconds(10));
    private static async Task Until(Func<bool> condition, CancellationToken ct)
    { while (!condition()) await Task.Delay(10, ct); }
    private static byte[] Query()
    {
        var bytes = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in "allowed.invalid".Split('.'))
        { bytes.Add((byte)label.Length); bytes.AddRange(Encoding.ASCII.GetBytes(label)); }
        bytes.AddRange(new byte[] { 0, 0, 1, 0, 1 });
        return bytes.ToArray();
    }
    private sealed class Fixture : IAsyncDisposable
    {
        public UdpClient Upstream { get; } = new(new IPEndPoint(IPAddress.Loopback, 0));
        public EngineConfig Config { get; }
        public EngineSettings Settings { get; }
        public RuleStore Rules { get; } = new(Guid.NewGuid().ToString("N"));
        public DnsProxyServer Dns { get; }
        public PolicyApplicationService Policy { get; }
        public ApiServer Api { get; }
        public DnsEngineConfig ClientConfig { get; }
        public Fixture(string directory, Func<UdpClient, CancellationToken, ValueTask<UdpReceiveResult>>? receive = null,
            Func<byte[], CancellationToken, Task<byte[]?>>? process = null)
        {
            Config = new EngineConfig
            {
                ApiBindIp = "127.0.0.1", ApiPort = Port(), DnsListenPort = Port(),
                UpstreamDnsIpv4 = "127.0.0.1", UpstreamDnsPort = ((IPEndPoint)Upstream.Client.LocalEndPoint!).Port,
                UpstreamTimeoutMs = 50, UpstreamRetryCount = 0,
                PolicyFilePath = Path.Combine(directory, "phase5d-" + Guid.NewGuid().ToString("N"), "policy.json"),
                CredentialPath = Path.Combine(directory, "temporary-token"),
                CertificatePath = Path.Combine(directory, "temporary-cert.pem"),
                CertificateKeyPath = Path.Combine(directory, "temporary-key.pem")
            };
            Settings = EngineSettings.FromConfig(Config);
            Dns = new DnsProxyServer(Rules, Settings, process, receive);
            Policy = new PolicyApplicationService(Rules, new PolicyPersistence(Config.PolicyFilePath), Dns.PolicyState);
            Api = new ApiServer(Policy, Settings, Dns.RuntimeStatus);
            using var certificate = X509Certificate2.CreateFromPem(File.ReadAllText(Config.CertificatePath));
            ClientConfig = new DnsEngineConfig
            {
                Address = "127.0.0.1", ManagementPort = Config.ApiPort,
                ApiToken = File.ReadAllText(Config.CredentialPath).Trim(),
                TrustedCertificate = Convert.ToBase64String(certificate.RawData)
            };
        }
        public async ValueTask DisposeAsync()
        { await Api.StopAsync(); await Dns.StopAsync(); Upstream.Dispose(); }
    }
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(send(request));
    }
    private static HttpResponseMessage Json(object value, HttpStatusCode code = HttpStatusCode.OK)
        => new(code) { Content = new StringContent(JsonSerializer.Serialize(value)) };
    private static DnsEngineConfig MockConfig() => new()
    { Address = "fixture.invalid", ApiToken = new string('A', 64) };
    private static DnsServiceStatus ValidStatus(long revision = 1) => new()
    {
        Implementation = "HostsGuardian.DnsEngine", DnsPort = 53, TcpTargetPort = 53, ApiPort = 3000,
        PolicyLoaded = true, PolicyRevision = revision, FilteringEnabled = true,
        CommittedRuleCount = 1, ActiveRuleCount = 1
    };
    private static DnsEngineService MockStatus(DnsServiceStatus status) => new(() => new HttpClient(new Handler(request =>
        request.RequestUri!.AbsolutePath == "/health"
            ? Json(new { engine = "HostsGuardian.DnsEngine", apiVersion = 1 }) : Json(status))));

    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest, string directory)
    {
        await asyncTest("Phase5D clean startup confirms all independent listeners and shutdown", async () =>
        {
            await using var f = new Fixture(directory);
            using var stop = new CancellationTokenSource(); using var deadline = Deadline();
            var lifetime = new EngineLifetime(f.Api, f.Dns).RunAsync(stop.Token);
            try
            {
                await Until(() => f.Dns.RuntimeStatus.GetSnapshot().RuntimeState == "Running", deadline.Token);
                var result = await new DnsEngineService().TestConnectionAsync(f.ClientConfig);
                var status = result.Transport!;
                Check(result.Ok && status.ManagementListening && status.UdpListening && status.TcpListening, "False startup status");
                Check(status.SnapshotUtc != null && status.LastUpstreamOutcome == "NotObserved", "Startup performed a probe");
            }
            finally { stop.Cancel(); Check(await lifetime.WaitAsync(deadline.Token) == 0, "Shutdown failed"); }
            Check(f.Dns.RuntimeStatus.GetSnapshot().RuntimeState == "Stopped", "Stale Running after shutdown");
        });
        await asyncTest("Phase5D restored policy status retains durable revision and rule count", async () =>
        {
            await using var f = new Fixture(directory);
            Check(f.Policy.Replace(new[] { "explicit.invalid" }).Success, "Commit failed");
            var restored = new EnginePolicyState();
            new PolicyApplicationService(new RuleStore("restored"), new PolicyPersistence(f.Config.PolicyFilePath), restored).InitializeForStartup();
            var status = new EngineRuntimeStatus(f.Settings, "restored", restored).GetSnapshot();
            Check(status.PolicyRestoreState == "Restored" && status.PolicyRevision == 1 && status.ActiveRuleCount == 1, "Restore ambiguous");
        });
        await asyncTest("Phase5D corrupt policy reports Safe Mode and preserves evidence", async () =>
        {
            await using var f = new Fixture(directory);
            Directory.CreateDirectory(Path.GetDirectoryName(f.Config.PolicyFilePath)!);
            File.WriteAllText(f.Config.PolicyFilePath, "corrupt"); f.Policy.InitializeForStartup();
            var status = f.Dns.RuntimeStatus.GetSnapshot();
            Check(!status.PolicyLoaded && status.PolicyRevision == null && status.EmergencySafeMode && !status.FilteringEnabled && status.ActiveRuleCount == 0, "Corrupt policy enabled");
            Check(status.PersistenceFault == "PolicyInvalid" && File.ReadAllText(f.Config.PolicyFilePath) == "corrupt", "Evidence lost");
            Check(!f.Policy.SetSafeMode(false).Success, "Implicit recovery allowed");
        });
        await asyncTest("Phase5D management remains truthful while UDP has faulted", async () =>
        {
            await using var f = new Fixture(directory, (_, _) => ValueTask.FromException<UdpReceiveResult>(new IOException("sentinel")));
            await f.Api.StartAsync(); await f.Dns.StartAsync();
            try { await f.Dns.Completion; } catch (IOException) { }
            var result = await new DnsEngineService().TestConnectionAsync(f.ClientConfig);
            Check(result.Ok && result.Transport!.ManagementListening && !result.Transport.UdpListening && result.Transport.UdpState == "Faulted", "DNS failure falsified management");
            try { await f.Dns.StopAsync(); } catch (IOException) { }
        });
        await asyncTest("Phase5D UDP startup bind failure rolls back every owned listener", async () =>
        {
            await using var f = new Fixture(directory);
            using var occupied = new UdpClient(new IPEndPoint(IPAddress.Any, f.Config.DnsListenPort));
            using var deadline = Deadline();
            Check(await new EngineLifetime(f.Api, f.Dns).RunAsync(deadline.Token) == 1, "Bind failure returned success");
            var status = f.Dns.RuntimeStatus.GetSnapshot();
            Check(status.RuntimeState == "Faulted" && status.UdpState == "Faulted" && !status.ManagementListening && !status.TcpListening, "Partial startup orphaned listener");
            var rebound = new TcpListener(IPAddress.Loopback, f.Config.ApiPort); rebound.Start(); rebound.Stop();
        });
        await asyncTest("Phase5D TCP startup failure rolls back UDP without changing committed policy", async () =>
        {
            await using var f = new Fixture(directory);
            f.Policy.Replace(new[] { "explicit.invalid" }); var before = File.ReadAllBytes(f.Config.PolicyFilePath);
            var occupied = new TcpListener(IPAddress.Any, f.Config.DnsListenPort); occupied.Start();
            try
            {
                using var deadline = Deadline();
                Check(await new EngineLifetime(f.Api, f.Dns).RunAsync(deadline.Token) == 1, "TCP bind failure succeeded");
                var status = f.Dns.RuntimeStatus.GetSnapshot();
                Check(!status.UdpListening && !status.ManagementListening && status.TcpState == "Faulted", "UDP orphan after TCP failure");
                Check(before.SequenceEqual(File.ReadAllBytes(f.Config.PolicyFilePath)), "Startup altered policy");
                using var rebound = new UdpClient(f.Config.DnsListenPort);
            }
            finally { occupied.Stop(); }
        });
        await asyncTest("Phase5D UDP and TCP states are independently published", async () =>
        {
            await using var f = new Fixture(directory);
            await f.Dns.StartAsync();
            await using var tcp = new TcpDnsServer(f.Settings, f.Dns.RequestProcessor, f.Dns.RuntimeStatus);
            Check(f.Dns.RuntimeStatus.GetSnapshot().UdpListening && !f.Dns.RuntimeStatus.GetSnapshot().TcpListening, "UDP implies TCP");
            await tcp.StartAsync(); await tcp.StopAsync();
            Check(f.Dns.IsRunning && !f.Dns.RuntimeStatus.GetSnapshot().TcpListening, "TCP stop falsified UDP");
        });
        await asyncTest("Phase5D upstream failure does not imply management or Engine failure", async () =>
        {
            await using var f = new Fixture(directory);
            await f.Api.StartAsync(); await f.Dns.StartAsync();
            var response = await f.Dns.RequestProcessor.ProcessAsync(Query(), CancellationToken.None);
            Check(response != null && (response[3] & 15) == 2, "SERVFAIL changed");
            var result = await new DnsEngineService().TestConnectionAsync(f.ClientConfig);
            Check(result.Ok && result.Transport!.UdpListening && result.Transport.LastUpstreamFailureUtc != null, "Upstream failure marks Engine offline");
        });
        await asyncTest("Phase5D upstream recovery changes latest outcome and keeps failure historical", async () =>
        {
            await using var f = new Fixture(directory);
            await f.Dns.RequestProcessor.ProcessAsync(Query(), CancellationToken.None);
            var failure = f.Dns.RuntimeStatus.GetSnapshot().LastUpstreamFailureUtc;
            using var deadline = Deadline();
            // Drain the earlier timed-out query before serving the new transaction.
            while (f.Upstream.Available > 0) await f.Upstream.ReceiveAsync(deadline.Token);
            var processing = f.Dns.RequestProcessor.ProcessAsync(Query(), deadline.Token);
            var request = await f.Upstream.ReceiveAsync(deadline.Token);
            var reply = (byte[])request.Buffer.Clone(); reply[2] |= 0x80; reply[3] |= 0x80;
            await f.Upstream.SendAsync(reply, request.RemoteEndPoint, deadline.Token); await processing;
            var status = f.Dns.RuntimeStatus.GetSnapshot();
            Check(status.LastUpstreamOutcome == "Response" && status.LastUpstreamSuccessUtc != null && status.LastUpstreamFailureUtc == failure, "Stale recovery observation");
        });
        await asyncTest("Phase5D Safe Mode snapshots retain committed revision and rules", async () =>
        {
            await using var f = new Fixture(directory); f.Policy.Replace(new[] { "explicit.invalid" });
            var bytes = File.ReadAllBytes(f.Config.PolicyFilePath); f.Policy.SetSafeMode(true);
            var status = f.Dns.RuntimeStatus.GetSnapshot();
            Check(status.PolicyRevision == 1 && status.CommittedRuleCount == 1 && status.ActiveRuleCount == 0 && !status.FilteringEnabled, "Safe Mode erased policy");
            Check(bytes.SequenceEqual(File.ReadAllBytes(f.Config.PolicyFilePath)), "Safe Mode wrote policy");
        });
        await asyncTest("Phase5D authenticated status diagnostics do not mutate policy", async () =>
        {
            await using var f = new Fixture(directory); f.Policy.Replace(new[] { "explicit.invalid" }); await f.Api.StartAsync();
            var bytes = File.ReadAllBytes(f.Config.PolicyFilePath); var service = new DnsEngineService();
            for (var i = 0; i < 4; i++) Check((await service.TestConnectionAsync(f.ClientConfig)).Ok, "Diagnostic failed");
            Check(bytes.SequenceEqual(File.ReadAllBytes(f.Config.PolicyFilePath)) && f.Policy.State.GetSnapshot().Revision == 1 && f.Upstream.Available == 0, "Diagnostic mutated/probed");
        });
        await asyncTest("Phase5D authentication error remains distinct from DNS availability", async () =>
        {
            await using var f = new Fixture(directory); await f.Api.StartAsync();
            f.ClientConfig.ApiToken = new string('B', 64);
            Check((await new DnsEngineService().TestConnectionAsync(f.ClientConfig)).State == ConnectionState.AuthenticationFailed, "Auth error misclassified");
        });
        await asyncTest("Phase5D unenrolled certificate remains a trust failure", async () =>
        {
            await using var f = new Fixture(directory); await f.Api.StartAsync(); f.ClientConfig.TrustedCertificate = "";
            Check((await new DnsEngineService().TestConnectionAsync(f.ClientConfig)).State == ConnectionState.TrustFailure, "Trust silently enrolled");
        });
        await asyncTest("Phase5D timeout and network exceptions retain sanitized classifications", async () =>
        {
            foreach (var sample in new[] { (ConnectionState.Timeout, (Exception)new OperationCanceledException("sentinel")),
                (ConnectionState.Unreachable, new HttpRequestException(HttpRequestError.ConnectionError, "sentinel")),
                (ConnectionState.NetworkFailure, new HttpRequestException(HttpRequestError.Unknown, "sentinel")) })
            {
                var service = new DnsEngineService(() => new HttpClient(new Handler(_ => throw sample.Item2)));
                var result = await service.TestConnectionAsync(MockConfig());
                Check(result.State == sample.Item1 && !result.Message.Contains("sentinel"), "Unsafe exception classification");
            }
        });
        await asyncTest("Phase5D malformed and contradictory status is incompatible", async () =>
        {
            var invalid = ValidStatus(); invalid.ActiveRuleCount = 2;
            Check((await MockStatus(invalid).TestConnectionAsync(MockConfig())).State == ConnectionState.Incompatible, "Contradictory counts accepted");
            var service = new DnsEngineService(() => new HttpClient(new Handler(request => request.RequestUri!.AbsolutePath == "/health"
                ? Json(new { engine = "HostsGuardian.DnsEngine", apiVersion = 1 }) : new(HttpStatusCode.OK) { Content = new StringContent("{bad") })));
            Check((await service.TestConnectionAsync(MockConfig())).State == ConnectionState.Incompatible, "Malformed status accepted");
        });
        await asyncTest("Phase5D policy HTTP success without revision is never confirmed", async () =>
        {
            var service = new DnsEngineService(() => new HttpClient(new Handler(_ => Json(new { ok = true }))));
            var result = await service.ReplacePolicyAsync(MockConfig(), new[] { "explicit.invalid" });
            Check(!result.Confirmed && result.CommittedRevision == null && result.Connection.State == ConnectionState.Incompatible, "Fabricated revision");
        });
        test("Phase5D unreachable filtering is unknown rather than disabled", () =>
        {
            var view = new EngineStatusPresentation(); view.Complete(new(ConnectionState.Unreachable, "Unreachable"));
            Check(view.Filtering == "Unknown" && view.Describe().Contains("Unreachable"), "Offline became disabled");
        });
        await asyncTest("Phase5D cancellation is clean stopped lifecycle rather than fault", async () =>
        {
            await using var f = new Fixture(directory); using var stop = new CancellationTokenSource(); using var deadline = Deadline();
            var task = new EngineLifetime(f.Api, f.Dns).RunAsync(stop.Token);
            await Until(() => f.Dns.RuntimeStatus.GetSnapshot().RuntimeState == "Running", deadline.Token); stop.Cancel();
            Check(await task.WaitAsync(deadline.Token) == 0, "Cancellation faulted");
            var status = f.Dns.RuntimeStatus.GetSnapshot();
            Check(status.RuntimeState == "Stopped" && !status.ManagementListening && !status.UdpListening && !status.TcpListening, "Stale shutdown state");
        });
        await asyncTest("Phase5D shutdown awaits cancelled owned UDP worker", async () =>
        {
            var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var completed = false;
            await using var f = new Fixture(directory, process: async (_, ct) =>
            { started.SetResult(); try { await Task.Delay(Timeout.Infinite, ct); } finally { completed = true; } return null; });
            await f.Dns.StartAsync(); using var sender = new UdpClient(); using var deadline = Deadline();
            await sender.SendAsync(Query(), new IPEndPoint(IPAddress.Loopback, f.Config.DnsListenPort), deadline.Token);
            await started.Task.WaitAsync(deadline.Token); await f.Dns.StopAsync().WaitAsync(deadline.Token);
            Check(completed && f.Dns.ActiveRequestCount == 0 && !f.Dns.IsRunning, "Orphaned worker");
        });
        await asyncTest("Phase5D status and API error never disclose fixture security material", async () =>
        {
            await using var f = new Fixture(directory); await f.Api.StartAsync();
            var status = JsonSerializer.Serialize(f.Api.GetDnsStatus());
            Check(!status.Contains(f.ClientConfig.ApiToken) && !status.Contains("PRIVATE KEY") && !status.Contains(f.Config.PolicyFilePath), "Status leaked secrets/path");
            f.ClientConfig.ApiToken = new string('B', 64);
            var error = await new DnsEngineService().TestConnectionAsync(f.ClientConfig);
            Check(!error.Message.Contains(f.ClientConfig.ApiToken), "Error leaked bearer");
        });
        test("Phase5D failed refresh leaves confirmed history stale and current unknown", () =>
        {
            var view = new EngineStatusPresentation(); view.Complete(new(ConnectionState.Authenticated, "OK", ValidStatus()), 1);
            view.Complete(new(ConnectionState.Timeout, "Timeout"));
            Check(view.LastConfirmed?.PolicyRevision == 1 && view.Current == null && view.Filtering == "Unknown" && view.Synchronization == "Unknown", "Historical success presented as current");
        });
        await asyncTest("Phase5D failed persistence does not advance committed revision", async () =>
        {
            await using var f = new Fixture(directory); f.Policy.Replace(new[] { "explicit.invalid" });
            using var file = new FileStream(f.Config.PolicyFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var result = f.Policy.Replace(new[] { "other.invalid" });
            var status = f.Dns.RuntimeStatus.GetSnapshot();
            Check(!result.Success && status.PolicyRevision == 1 && status.CommittedRuleCount == 1 && status.PersistenceFault == "PolicyWriteFailed", "False commit after disk failure");
        });
        await asyncTest("Phase5D failed persistence returns API failure and no GUI confirmation", async () =>
        {
            await using var f = new Fixture(directory); f.Policy.Replace(new[] { "explicit.invalid" }); await f.Api.StartAsync();
            using var file = new FileStream(f.Config.PolicyFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var result = await new DnsEngineService().ReplacePolicyAsync(f.ClientConfig, new[] { "other.invalid" });
            Check(!result.Confirmed && result.Connection.State == ConnectionState.EngineError && result.CommittedRevision == null && result.Connection.Message.Contains("503"), "API/client false success");
            Check(f.Policy.State.GetSnapshot().Revision == 1, "Rejected update advanced revision");
        });
        await asyncTest("Phase5D concurrent snapshot reads preserve policy bytes and consistent counts", async () =>
        {
            await using var f = new Fixture(directory); f.Policy.Replace(new[] { "explicit.invalid" }); var bytes = File.ReadAllBytes(f.Config.PolicyFilePath);
            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
            { for (var i = 0; i < 1000; i++) { var s = f.Api.GetDnsStatus(); Check(s.PolicyRevision == 1 && s.ActiveRuleCount == s.CommittedRuleCount && s.FilteringEnabled, "Inconsistent snapshot"); } })));
            Check(bytes.SequenceEqual(File.ReadAllBytes(f.Config.PolicyFilePath)), "Reads wrote policy");
        });
        await asyncTest("Phase5D unexpected management termination is observed by lifetime", async () =>
        {
            await using var f = new Fixture(directory); using var stop = new CancellationTokenSource(); using var deadline = Deadline();
            var task = new EngineLifetime(f.Api, f.Dns).RunAsync(stop.Token);
            await Until(() => f.Dns.RuntimeStatus.GetSnapshot().RuntimeState == "Running", deadline.Token); await f.Api.StopAsync();
            Check(await task.WaitAsync(deadline.Token) == 1 && !f.Dns.IsRunning && !f.Api.IsRunning, "Management failure left DNS orphaned");
        });
        await asyncTest("Phase5D fatal UDP task is observed and ports released", async () =>
        {
            await using var f = new Fixture(directory, (_, _) => ValueTask.FromException<UdpReceiveResult>(new IOException("sentinel")));
            using var deadline = Deadline();
            Check(await new EngineLifetime(f.Api, f.Dns).RunAsync(deadline.Token) == 1, "Fatal listener returned success");
            Check(!f.Dns.IsRunning && !f.Api.IsRunning && f.Dns.RuntimeStatus.GetSnapshot().RuntimeState == "Faulted", "Fatal task unobserved");
            using var rebound = new UdpClient(f.Config.DnsListenPort);
        });
        test("Phase5D time expiry turns online observation into stale unknown", () =>
        {
            var now = DateTimeOffset.UtcNow; var view = new EngineStatusPresentation(() => now);
            view.Complete(new(ConnectionState.Authenticated, "OK", ValidStatus()), 1);
            now += EngineStatusPresentation.MaximumStatusAge + TimeSpan.FromSeconds(1);
            Check(view.Current == null && view.Filtering == "Unknown" && view.Describe().Contains("Stale"), "Expired state remains current");
        });
        test("Phase5D changed endpoint clears old synchronization and history", () =>
        {
            var view = new EngineStatusPresentation(); view.Complete(new(ConnectionState.Authenticated, "OK", ValidStatus()), 1); view.Reset();
            Check(view.LastConfirmed == null && view.Current == null && view.Synchronization == "Unknown", "Wrong endpoint policy retained");
        });
        await asyncTest("Phase5D acknowledgement followed by different revision is unconfirmed", async () =>
        {
            var service = new DnsEngineService(() => new HttpClient(new Handler(request => request.RequestUri!.AbsolutePath switch
            {
                "/rules/blocked/replace" => Json(new { ok = true, revision = 1, count = 1 }),
                "/health" => Json(new { engine = "HostsGuardian.DnsEngine", apiVersion = 1 }),
                _ => Json(ValidStatus(2))
            })));
            var result = await service.ReplacePolicyAsync(MockConfig(), new[] { "explicit.invalid" });
            Check(!result.Confirmed && result.CommittedRevision == 1, "Superseded revision became synchronized");
        });
        test("Phase5D requested state is pending rather than confirmed", () =>
        {
            var view = new EngineStatusPresentation(); view.Complete(new(ConnectionState.Authenticated, "OK", ValidStatus()), 1); view.BeginRequest();
            Check(view.Current == null && view.Filtering == "Unknown" && view.Synchronization == "Pending", "Button implies success");
        });
        await asyncTest("Phase5D lifecycle snapshots never claim Running with absent listener", async () =>
        {
            await using var f = new Fixture(directory); var runtime = f.Dns.RuntimeStatus;
            runtime.SetManagementListening(true); runtime.SetTcpListening(true); runtime.SetRuntimeState("Running");
            await Task.WhenAll(Task.Run(() => { for (var i = 0; i < 10000; i++) runtime.SetUdpListening(i % 2 == 0); }),
                Task.Run(() => { for (var i = 0; i < 10000; i++) { var s = runtime.GetSnapshot(); Check(s.RuntimeState != "Running" || (s.UdpListening && s.TcpListening && s.ManagementListening), "Impossible lifecycle snapshot"); } }));
        });
        await asyncTest("Phase5D successful policy replacement is confirmed by actual revision status", async () =>
        {
            await using var f = new Fixture(directory); await f.Api.StartAsync();
            var result = await new DnsEngineService().ReplacePolicyAsync(f.ClientConfig, new[] { "explicit.invalid" });
            Check(result.Confirmed && result.CommittedRevision == 1 && result.Connection.Transport!.PolicyRevision == 1, "Successful revision not confirmed");
        });
        test("Phase5D different Engine instance cannot inherit synchronization at same revision", () =>
        {
            var view = new EngineStatusPresentation(); var first = ValidStatus(); first.InstanceId = "first";
            view.Complete(new(ConnectionState.Authenticated, "OK", first), 1);
            var second = ValidStatus(); second.InstanceId = "second"; view.Complete(new(ConnectionState.Authenticated, "OK", second));
            Check(view.Synchronization == "Unconfirmed", "Different Engine inherited synchronization");
        });
        await asyncTest("Phase5D unrecognized status categories cannot become UI success or raw error text", async () =>
        {
            var status = ValidStatus(); status.PersistenceFault = "sentinel-secret";
            var result = await MockStatus(status).TestConnectionAsync(MockConfig());
            Check(result.State == ConnectionState.Incompatible && !result.Message.Contains("sentinel-secret"), "Untrusted status text displayed");
        });
        await asyncTest("Phase5D explicit retry after persistence failure restores truthful status", async () =>
        {
            await using var f = new Fixture(directory); f.Policy.Replace(new[] { "explicit.invalid" });
            using (var file = new FileStream(f.Config.PolicyFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                Check(!f.Policy.Replace(new[] { "other.invalid" }).Success, "Locked commit succeeded");
            Check(f.Policy.Replace(new[] { "other.invalid" }).Success, "Explicit recovery failed");
            var status = f.Api.GetDnsStatus();
            Check(status.PolicyRevision == 2 && status.PersistenceFault == "" && status.ActiveRuleCount == 1, "Recovery status stale");
        });
        await asyncTest("Phase5D concurrent policy commits and status reads publish one coherent policy snapshot", async () =>
        {
            await using var f = new Fixture(directory); f.Policy.Replace(new[] { "one.invalid" });
            await Task.WhenAll(Task.Run(() =>
            {
                for (var revision = 2; revision <= 20; revision++)
                    Check(f.Policy.Replace(revision % 2 == 0 ? new[] { "one.invalid", "two.invalid" } : new[] { "one.invalid" }).Success, "Fixture commit failed");
            }), Task.Run(() =>
            {
                for (var i = 0; i < 10000; i++)
                {
                    var status = f.Api.GetDnsStatus();
                    Check(status.CommittedRuleCount == (status.PolicyRevision % 2 == 0 ? 2 : 1) && status.ActiveRuleCount == status.CommittedRuleCount, "Mixed policy publication");
                }
            }));
        });
        test("Phase5D WPF projects confirmed state with one passive expiration timer", () =>
        {
            var root = new DirectoryInfo(AppContext.BaseDirectory);
            while (root != null && !File.Exists(Path.Combine(root.FullName, "HostsGuardian.sln"))) root = root.Parent;
            Check(root != null, "Source root absent");
            var source = File.ReadAllText(Path.Combine(root!.FullName, "HostsGuardian.Wpf", "ViewModels", "MainViewModel.cs"));
            var constructor = source.IndexOf("public MainViewModel(", StringComparison.Ordinal);
            var initialNavigation = source.IndexOf("ShowDomains();", constructor, StringComparison.Ordinal);
            var timer = source.IndexOf("var statusTimer =", constructor, StringComparison.Ordinal);
            Check(timer > constructor && timer < initialNavigation && source.IndexOf("var statusTimer =", timer + 1, StringComparison.Ordinal) < 0, "Timer is conditional or duplicated");
            var commands = source.Substring(source.IndexOf("private async void TestDnsEngine()", StringComparison.Ordinal));
            commands = commands[..commands.IndexOf("// ===================== LOG COMMAND", StringComparison.Ordinal)];
            Check(!commands.Contains("Task.Run") && commands.Contains("ReplacePolicyAsync") && commands.Contains("confirmation.CommittedRevision"), "WPF ignores confirmed response");
        });
        await asyncTest("Phase5D management bind failure does not start DNS or retain resources", async () =>
        {
            await using var f = new Fixture(directory);
            var occupied = new TcpListener(IPAddress.Loopback, f.Config.ApiPort) { ExclusiveAddressUse = true }; occupied.Start();
            try
            {
                using var deadline = Deadline();
                Check(await new EngineLifetime(f.Api, f.Dns).RunAsync(deadline.Token) == 1, "Management bind failure succeeded");
                var status = f.Api.GetDnsStatus();
                Check(status.ManagementState == "Faulted" && !status.ManagementListening && status.UdpState == "NotStarted" && !status.TcpListening, "Failed management exposed DNS");
            }
            finally { occupied.Stop(); }
        });
        await asyncTest("Phase5D UDP peer-reset notification continues serving without a false lifetime fault", async () =>
        {
            var first = true;
            await using var f = new Fixture(directory, (listener, token) =>
            {
                if (first) { first = false; return ValueTask.FromException<UdpReceiveResult>(new SocketException((int)SocketError.ConnectionReset)); }
                return listener.ReceiveAsync(token);
            }, (request, _) => Task.FromResult<byte[]?>(request));
            await f.Dns.StartAsync(); using var sender = new UdpClient(); using var deadline = Deadline();
            await sender.SendAsync(Query(), new IPEndPoint(IPAddress.Loopback, f.Config.DnsListenPort), deadline.Token);
            var response = await sender.ReceiveAsync(deadline.Token);
            Check(response.Buffer.SequenceEqual(Query()) && f.Dns.IsRunning && !f.Dns.Completion.IsCompleted, "Datagram-local reset killed listener");
        });
        await asyncTest("Phase5D fatal exception operational logs omit raw secret sentinel", async () =>
        {
            await using var f = new Fixture(directory);
            var previous = Console.Error; using var output = new StringWriter();
            var sentinel = f.ClientConfig.ApiToken;
            await using var failing = new DnsProxyServer(f.Rules, f.Settings, null,
                (_, _) => ValueTask.FromException<UdpReceiveResult>(new IOException(sentinel)));
            await using var api = new ApiServer(new PolicyApplicationService(f.Rules, new PolicyPersistence(f.Config.PolicyFilePath), failing.PolicyState), f.Settings, failing.RuntimeStatus);
            Console.SetError(output);
            try
            {
                using var deadline = Deadline();
                Check(await new EngineLifetime(api, failing).RunAsync(deadline.Token) == 1, "Fault not observed");
                Check(!output.ToString().Contains(sentinel) && output.ToString().Contains("Startup or lifetime failed"), "Unsafe fault logging");
            }
            finally { Console.SetError(previous); }
        });
        test("Phase5D cancelled upstream observation leaves historical outcome unchanged", () =>
        {
            var state = new UpstreamRuntimeState(); state.Record(new(UpstreamOutcome.Timeout)); var before = state.GetSnapshot();
            state.Record(new(UpstreamOutcome.Cancelled)); Check(state.GetSnapshot() == before, "Cancellation recorded as failure");
        });
    }
}
