using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class Phase5ES1Tests
{
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK)
        { Content = new StringContent(JsonSerializer.Serialize(value)) };
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> action) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => action(request, ct);
    }
    private static DnsEngineConfig Config() => new() { Address = "fixture.invalid", ApiToken = new string('A', 64) };
    private static DnsServiceStatus Status(bool safeMode) => new()
    {
        Implementation = "HostsGuardian.DnsEngine", InstanceId = "fixture", DnsPort = 53, ApiPort = 3000,
        RuntimeState = "Running", SnapshotUtc = DateTimeOffset.UtcNow,
        ManagementState = "Listening", ManagementListening = true, UdpState = "Listening", UdpListening = true,
        TcpState = "Listening", TcpListening = true, TcpImplemented = true,
        PolicyLoaded = true, PolicyRestoreState = "Restored", PolicyRevision = 7,
        CommittedRuleCount = 2, ActiveRuleCount = safeMode ? 0 : 2, FilteringEnabled = !safeMode,
        EmergencySafeMode = safeMode, SafeModeReason = safeMode ? "ManagementRequested" : ""
    };
    private static DnsEngineService Client(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> action)
        => new(() => new HttpClient(new Handler(action)));
    private static DnsEngineService Mock(DnsServiceStatus status, object? acknowledgement = null)
        => Client((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath switch
        {
            "/safe-mode/enter" or "/safe-mode/exit" => Json(acknowledgement ?? new { ok = true, revision = 7, count = 2 }),
            "/health" => Json(new { engine = "HostsGuardian.DnsEngine", apiVersion = 1 }),
            _ => Json(status)
        }));
    private static EngineStatusPresentation View(DnsServiceStatus status)
    {
        var view = new EngineStatusPresentation(); view.Complete(new(ConnectionState.Authenticated, "OK", status)); return view;
    }
    private static int Port()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop(); return port;
    }
    private sealed class Fixture : IAsyncDisposable
    {
        public EngineConfig Config { get; }
        public DnsEngineConfig ClientConfig { get; }
        public DnsProxyServer Dns { get; }
        public PolicyApplicationService Policy { get; }
        public ApiServer Api { get; }
        public Fixture(string directory, bool corrupt = false)
        {
            Config = new EngineConfig
            {
                ApiBindIp = "127.0.0.1", ApiPort = Port(), DnsListenPort = Port(),
                PolicyFilePath = Path.Combine(directory, "s1-" + Guid.NewGuid().ToString("N"), "policy.json"),
                CredentialPath = Path.Combine(directory, "temporary-token"),
                CertificatePath = Path.Combine(directory, "temporary-cert.pem"),
                CertificateKeyPath = Path.Combine(directory, "temporary-key.pem")
            };
            if (corrupt)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Config.PolicyFilePath)!);
                File.WriteAllText(Config.PolicyFilePath, "invalid fixture policy");
            }
            var rules = new RuleStore(Guid.NewGuid().ToString("N"));
            var settings = EngineSettings.FromConfig(Config);
            Dns = new DnsProxyServer(rules, settings);
            Policy = new PolicyApplicationService(rules, new PolicyPersistence(Config.PolicyFilePath), Dns.PolicyState);
            Api = new ApiServer(Policy, settings, Dns.RuntimeStatus);
            using var certificate = X509Certificate2.CreateFromPem(File.ReadAllText(Config.CertificatePath));
            ClientConfig = new DnsEngineConfig
            {
                Address = "127.0.0.1", ManagementPort = Config.ApiPort,
                ApiToken = File.ReadAllText(Config.CredentialPath).Trim(), TrustedCertificate = Convert.ToBase64String(certificate.RawData)
            };
        }
        public async ValueTask DisposeAsync() { await Api.StopAsync(); await Dns.StopAsync(); }
    }
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest, string directory)
    {
        foreach (var enabled in new[] { true, false })
        {
            await asyncTest("S1 authenticated HTTPS " + (enabled ? "enter" : "exit") + " route and empty body", async () =>
            {
                var paths = new List<string>();
                var client = Client(async (request, ct) =>
                {
                    Check(request.RequestUri!.Scheme == "https" && request.Headers.Authorization?.Scheme == "Bearer" &&
                        request.Headers.Authorization.Parameter == Config().ApiToken, "Transport security boundary lost");
                    paths.Add(request.RequestUri.AbsolutePath);
                    if (paths.Count == 1)
                    {
                        Check(request.Method == HttpMethod.Post && await request.Content!.ReadAsStringAsync(ct) == "{}", "Unexpected mutation payload");
                        return Json(new { ok = true, revision = 7, count = 2 });
                    }
                    Check(request.Method == HttpMethod.Get, "Readback mutates state");
                    return paths.Count == 2 ? Json(new { engine = "HostsGuardian.DnsEngine", apiVersion = 1 }) : Json(Status(enabled));
                });
                var result = enabled ? await client.EnterSafeModeAsync(Config()) : await client.ExitSafeModeAsync(Config());
                Check(result.Confirmed && paths.SequenceEqual(new[] { enabled ? "/safe-mode/enter" : "/safe-mode/exit", "/health", "/dns/status" }), "Transition not confirmed by readback");
            });
        }
        await asyncTest("S1 acknowledgement alone waits for authenticated status", async () =>
        {
            var readback = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var client = Client((request, _) =>
            {
                if (request.RequestUri!.AbsolutePath == "/safe-mode/enter") return Task.FromResult(Json(new { ok = true, revision = 7, count = 2 }));
                reached.SetResult(); return readback.Task;
            });
            var task = client.EnterSafeModeAsync(Config()); await reached.Task;
            Check(!task.IsCompleted, "Acknowledgement reported confirmation");
            readback.SetResult(new(HttpStatusCode.ServiceUnavailable));
            Check(!(await task).Confirmed, "Failed status confirmed transition");
        });
        foreach (var enabled in new[] { true, false })
            await asyncTest("S1 contradictory " + (enabled ? "enter" : "exit") + " status is unconfirmed", async () =>
            {
                var client = Mock(Status(!enabled));
                var result = enabled ? await client.EnterSafeModeAsync(Config()) : await client.ExitSafeModeAsync(Config());
                Check(!result.Confirmed && !result.Connection.Ok && result.Connection.Transport == null, "Contradiction became current truth");
            });
        foreach (var mismatch in new[] { "revision", "count" })
            await asyncTest("S1 superseded " + mismatch + " invalidates confirmation", async () =>
            {
                var status = Status(true);
                if (mismatch == "revision") status.PolicyRevision++;
                else status.CommittedRuleCount++;
                var result = await Mock(status).EnterSafeModeAsync(Config());
                Check(!result.Confirmed && result.Connection.State == ConnectionState.EngineError, "Superseded policy accepted");
            });
        await asyncTest("S1 malformed acknowledgement cannot confirm", async () =>
        {
            var result = await Mock(Status(true), new { ok = true }).EnterSafeModeAsync(Config());
            Check(!result.Confirmed && result.Connection.State == ConnectionState.Incompatible, "Malformed ack accepted");
        });
        await asyncTest("S1 rejected command never retries or changes presentation to requested state", async () =>
        {
            var calls = 0; var view = View(Status(false)); view.BeginRequest();
            var result = await Client((_, _) => { calls++; return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Conflict)); }).EnterSafeModeAsync(Config());
            view.Complete(result.Connection);
            Check(calls == 1 && view.Current == null && view.LastConfirmed!.EmergencySafeMode == false && view.SafeMode.Contains("Unknown"), "Failed request falsely succeeded");
        });
        foreach (var failure in new[] { ConnectionState.Timeout, ConnectionState.Unreachable, ConnectionState.AuthenticationFailed, ConnectionState.TrustFailure })
            await asyncTest("S1 distinct " + failure + " failure remains Unknown", async () =>
            {
                var calls = 0;
                var client = Client((request, _) =>
                {
                    calls++;
                    if (request.RequestUri!.AbsolutePath == "/safe-mode/enter") return Task.FromResult(Json(new { ok = true, revision = 7, count = 2 }));
                    if (failure == ConnectionState.AuthenticationFailed) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
                    if (failure == ConnectionState.Timeout) throw new OperationCanceledException();
                    throw new HttpRequestException(failure == ConnectionState.TrustFailure ? HttpRequestError.SecureConnectionError : HttpRequestError.ConnectionError, "synthetic private error");
                });
                var result = await client.EnterSafeModeAsync(Config()); var view = View(Status(false)); view.Complete(result.Connection);
                Check(!result.Confirmed && result.Connection.State == failure && view.Current == null && calls == 2 &&
                    !result.Connection.Message.Contains("private"), "Failure classification/sanitization lost");
            });
        test("S1 stale Safe Mode controls and details expire with one cache", () =>
        {
            var now = DateTimeOffset.UtcNow; var view = new EngineStatusPresentation(() => now);
            view.Complete(new(ConnectionState.Authenticated, "OK", Status(true)));
            Check(view.CanExitSafeMode, "Fresh state not controllable"); now += EngineStatusPresentation.MaximumStatusAge + TimeSpan.FromSeconds(1);
            Check(view.Current == null && !view.CanExitSafeMode && !view.CanEnterSafeMode && view.DescribeDetails().Contains("historical only"), "Expired state remains current");
        });
        test("S1 restore fault prohibits GUI exit but preserves reason", () =>
        {
            var status = Status(true); status.PolicyLoaded = false; status.PolicyRevision = null; status.CommittedRuleCount = 0;
            status.PolicyRestoreState = "Invalid"; status.SafeModeReason = "UntrustedPolicy"; status.PersistenceFault = "PolicyInvalid";
            var view = View(status);
            Check(!view.CanExitSafeMode && view.DescribeDetails().Contains("UntrustedPolicy") && view.DescribeDetails().Contains("PolicyInvalid"), "Restore fault concealed");
        });
        test("S1 explicit reason and passive history remain observational", () =>
        {
            var status = Status(true); status.LastUpstreamOutcome = "Response"; status.LastUpstreamFailure = "Timeout";
            status.LastUpstreamSuccessUtc = DateTimeOffset.UtcNow; status.LastUpstreamFailureUtc = DateTimeOffset.UtcNow.AddMinutes(-1);
            var text = View(status).DescribeDetails();
            Check(text.Contains("ManagementRequested") && text.Contains("Response (passive") && text.Contains("historical category: Timeout") &&
                text.Contains("does not establish a current outage") && text.Contains(status.LastUpstreamSuccessUtc.Value.ToString("O")), "History implies active outage");
        });
        test("S1 fallback detail reads do not alter policy or observations", () =>
        {
            var status = Status(false); status.LastUpstreamOutcome = "Response"; status.LastUpstreamRequestUsedFallback = true;
            status.LastFallbackUseUtc = DateTimeOffset.UtcNow; var before = JsonSerializer.Serialize(status);
            var view = View(status); Check(view.DescribeDetails().Contains("used fallback: True"), "Fallback missing");
            Check(JsonSerializer.Serialize(status) == before, "Presentation mutated observation");
        });
        test("S1 runtime/listener faults remain separate from filtering", () =>
        {
            var status = Status(false); status.RuntimeState = "Degraded"; status.TcpState = "Faulted"; status.TcpListening = false;
            var view = View(status); Check(view.Filtering == "Enabled" && view.DescribeDetails().Contains("TCP: Faulted"), "Listener fault changed policy state");
            view.Complete(new(ConnectionState.Unreachable, "Unavailable"));
            Check(view.Filtering == "Unknown" && !view.DescribeDetails().Contains("TCP: Faulted"), "Historical listener presented as current");
        });
        test("S1 pending commands and unavailable management cannot operate controls", () =>
        {
            var view = View(Status(false)); Check(view.CanEnterSafeMode && !view.CanExitSafeMode, "Wrong initial control");
            view.BeginRequest(); Check(!view.CanEnterSafeMode && !view.CanExitSafeMode, "Pending mutation enabled");
            var status = Status(false); status.ManagementListening = false; view.Complete(new(ConnectionState.Authenticated, "OK", status));
            Check(!view.CanEnterSafeMode, "Absent management enabled mutation");
        });
        await asyncTest("S1 actual HTTPS enter preserves policy bytes revision and committed count", async () =>
        {
            await using var f = new Fixture(directory); await f.Api.StartAsync(); Check(f.Policy.Replace(new[] { "explicit.invalid" }).Success, "Fixture policy failed");
            var before = File.ReadAllBytes(f.Config.PolicyFilePath); var result = await new DnsEngineService().EnterSafeModeAsync(f.ClientConfig);
            Check(result.Confirmed && result.AcknowledgedRevision == 1 && result.AcknowledgedCount == 1 && result.Connection.Transport!.ActiveRuleCount == 0 &&
                File.ReadAllBytes(f.Config.PolicyFilePath).SequenceEqual(before), "Enter rewrote policy");
        });
        await asyncTest("S1 actual HTTPS exit resumes retained policy without file rewrite", async () =>
        {
            await using var f = new Fixture(directory); await f.Api.StartAsync(); f.Policy.Replace(new[] { "explicit.invalid" }); f.Policy.SetSafeMode(true);
            var before = File.ReadAllBytes(f.Config.PolicyFilePath); var result = await new DnsEngineService().ExitSafeModeAsync(f.ClientConfig);
            Check(result.Confirmed && result.AcknowledgedRevision == 1 && result.Connection.Transport!.ActiveRuleCount == 1 &&
                File.ReadAllBytes(f.Config.PolicyFilePath).SequenceEqual(before), "Exit rewrote retained policy");
        });
        await asyncTest("S1 actual restore fault rejects exit and preserves rejected evidence", async () =>
        {
            await using var f = new Fixture(directory, true); await f.Api.StartAsync(); var before = File.ReadAllBytes(f.Config.PolicyFilePath);
            var result = await new DnsEngineService().ExitSafeModeAsync(f.ClientConfig);
            Check(!result.Confirmed && result.Connection.State == ConnectionState.EngineError && f.Api.GetDnsStatus().EmergencySafeMode &&
                File.ReadAllBytes(f.Config.PolicyFilePath).SequenceEqual(before), "Rejected exit changed evidence");
        });
        await asyncTest("S1 corrupt restore accepts nullable acknowledgement then requires explicit recovery exit", async () =>
        {
            await using var f = new Fixture(directory, true); await f.Api.StartAsync(); var service = new DnsEngineService();
            var entered = await service.EnterSafeModeAsync(f.ClientConfig);
            Check(entered.Confirmed && entered.AcknowledgedRevision == null, "Corrupt policy enter incorrectly rejected");
            var replaced = await service.ReplacePolicyAsync(f.ClientConfig, new[] { "explicit.invalid" });
            Check(replaced.Confirmed && replaced.Connection.Transport!.EmergencySafeMode, "Replacement implicitly exited Safe Mode");
            Check((await service.ExitSafeModeAsync(f.ClientConfig)).Confirmed, "Explicit recovery exit failed");
        });
        await asyncTest("S1 fresh empty policy accepts revision zero without inventing a file", async () =>
        {
            await using var f = new Fixture(directory); await f.Api.StartAsync(); var service = new DnsEngineService();
            Check((await service.EnterSafeModeAsync(f.ClientConfig)).Confirmed && (await service.ExitSafeModeAsync(f.ClientConfig)).Confirmed &&
                !File.Exists(f.Config.PolicyFilePath), "Empty policy transition invented persisted policy");
        });
        await asyncTest("S1 actual authentication failure cannot enter Safe Mode", async () =>
        {
            await using var f = new Fixture(directory); await f.Api.StartAsync(); f.ClientConfig.ApiToken = new string('B', 64);
            var result = await new DnsEngineService().EnterSafeModeAsync(f.ClientConfig);
            Check(result.Connection.State == ConnectionState.AuthenticationFailed && !f.Api.GetDnsStatus().EmergencySafeMode, "Anonymous mutation possible");
        });
        await asyncTest("S1 actual unenrolled certificate is refused before mutation", async () =>
        {
            await using var f = new Fixture(directory); await f.Api.StartAsync(); f.ClientConfig.TrustedCertificate = "";
            var result = await new DnsEngineService().EnterSafeModeAsync(f.ClientConfig);
            Check(result.Connection.State == ConnectionState.TrustFailure && !f.Api.GetDnsStatus().EmergencySafeMode, "Certificate bypass possible");
        });
        test("S1 WPF awaits guarded commands catches failure and ignores old endpoint results", () =>
        {
            var root = new DirectoryInfo(AppContext.BaseDirectory);
            while (root != null && !File.Exists(Path.Combine(root.FullName, "HostsGuardian.sln"))) root = root.Parent;
            Check(root != null, "Source root absent");
            var source = File.ReadAllText(Path.Combine(root!.FullName, "HostsGuardian.Wpf", "ViewModels", "MainViewModel.cs"));
            var start = source.IndexOf("private async Task ChangeEngineSafeModeAsync", StringComparison.Ordinal);
            var method = source[start..source.IndexOf("private async void TestDnsEngine()", start, StringComparison.Ordinal)];
            Check(method.Contains("catch") && method.Contains("finally") && method.Contains("await _dnsEngine.EnterSafeModeAsync") &&
                method.Contains("await _dnsEngine.ExitSafeModeAsync") && method.Contains("generation != _engineSettingsGeneration") &&
                method.Contains("_engineStatus.CanEnterSafeMode") && method.Contains("_engineStatus.Complete(transition.Connection)") &&
                !method.Contains("Task.Run") && !method.Contains(".Wait(") && !method.Contains("ReplacePolicyAsync"), "WPF asynchronous failure boundary lost");
            var xaml = File.ReadAllText(Path.Combine(root.FullName, "HostsGuardian.Wpf", "MainWindow.xaml"));
            Check(xaml.Contains("Binding EnterEngineSafeModeCommand") && xaml.Contains("Binding ExitEngineSafeModeCommand") &&
                xaml.Contains("Binding EngineStatusDetailsText"), "Controls/details unbound");
        });
    }
}
