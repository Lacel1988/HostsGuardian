using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class Phase5ATests
{
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static string PolicyPath(string directory)
        => Path.Combine(directory, "phase5a-" + Guid.NewGuid().ToString("N"), "policy.json");

    private static PolicyApplicationService Policy(string path, RuleStore? rules = null, EnginePolicyState? state = null)
        => new(rules ?? new RuleStore(Guid.NewGuid().ToString("N")), new PolicyPersistence(path), state);

    private static byte[] Query(string name, ushort type)
    {
        var bytes = new List<byte> { 0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.AddRange(new byte[] { 0, (byte)(type >> 8), (byte)type, 0, 1 });
        return bytes.ToArray();
    }

    private static int U16(byte[] bytes, int offset) => bytes[offset] * 256 + bytes[offset + 1];

    private static int ApiPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static int DnsPort()
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
    }

    private static EngineConfig Config(string directory, string policyPath) => new()
    {
        ApiBindIp = "127.0.0.1", ApiPort = ApiPort(), DnsListenPort = DnsPort(),
        UpstreamDnsIpv4 = "127.0.0.1", UpstreamDnsPort = DnsPort(), UpstreamTimeoutMs = 1000,
        PolicyFilePath = policyPath,
        CredentialPath = Path.Combine(directory, "temporary-token"),
        CertificatePath = Path.Combine(directory, "temporary-cert.pem"),
        CertificateKeyPath = Path.Combine(directory, "temporary-key.pem")
    };

    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest, string directory)
    {
        test("Phase5A A and AAAA responses reset omitted DNS sections before branching", () =>
        {
            foreach (var type in new ushort[] { 1, 28 })
            {
                var request = Query("Explicit.invalid", type).ToList();
                request[9] = 1; request[11] = 1;
                // A authority record and an OPT additional record, both deliberately omitted in the response.
                request.AddRange(new byte[] { 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1 });
                request.AddRange(new byte[] { 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0 });
                var original = request.ToArray();
                Check(DnsProtocol.TryParseQuestion(original, out var question), "Fixture query invalid");
                var response = DnsProtocol.BuildBlockedResponse(original, question, IPAddress.Parse("192.0.2.9"));
                Check(U16(response, 0) == 0xABCD && U16(response, 4) == 1, "ID/question count changed");
                Check(U16(response, 8) == 0 && U16(response, 10) == 0, "Omitted section counts survived");
                Check(U16(response, 6) == (type == 1 ? 1 : 0), "Wrong answer count");
                Check(response.Length == question.QuestionEndOffset + (type == 1 ? 16 : 0), "Inconsistent message length");
                Check((U16(response, 2) & 0x818F) == 0x8180, "QR/RD/RA/NOERROR changed");
                Check(response.AsSpan(12, question.QuestionEndOffset - 12).SequenceEqual(original.AsSpan(12, question.QuestionEndOffset - 12)), "Question changed");
                Check(request.SequenceEqual(original), "Request mutated");
                if (type == 1)
                {
                    var offset = question.QuestionEndOffset;
                    Check(U16(response, offset) == 0xC00C && U16(response, offset + 2) == 1 && U16(response, offset + 4) == 1, "A answer encoding changed");
                    Check(response[offset + 9] == 60 && U16(response, offset + 10) == 4 && response[^4..].SequenceEqual(new byte[] { 192, 0, 2, 9 }), "A TTL/address changed");
                }
            }
        });

        test("Phase5A first startup and orphan temporary writes create no policy", () =>
        {
            var path = PolicyPath(directory);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(path)!, ".policy-interrupted.tmp"), "{partial");
            var policy = Policy(path); policy.InitializeForStartup();
            var state = policy.State.GetSnapshot();
            Check(state.RestoreState == "Missing" && state.Loaded && state.Revision == 0 && state.RuleCount == 0 && !state.SafeMode, "Missing policy state incorrect");
            Check(!File.Exists(path) && policy.GetBlockedDomains().Length == 0, "Startup created policy");
        });

        test("Phase5A normalized commit restores exact content and revision across instances", () =>
        {
            var path = PolicyPath(directory);
            var first = Policy(path);
            var result = first.Replace(new[] { "B.invalid", "a.invalid", "b.invalid" });
            Check(result.Success && result.Revision == 1 && result.Count == 2, "Commit result wrong");
            Check(File.ReadAllText(path) == "{\"schemaVersion\":1,\"revision\":1,\"domains\":[\"a.invalid\",\"b.invalid\"]}", "Serialization not deterministic");
            var second = Policy(path); second.InitializeForStartup();
            Check(second.GetBlockedDomains().SequenceEqual(new[] { "a.invalid", "b.invalid" }) && second.State.GetSnapshot().Revision == 1, "Restore changed policy/revision");
            Check(second.Add(new[] { "c.invalid" }).Revision == 2, "Revision did not advance");
            var third = Policy(path); third.InitializeForStartup();
            Check(third.State.GetSnapshot().Revision == 2 && third.State.GetSnapshot().RuleCount == 3, "New revision not restored");
        });

        test("Phase5A an explicitly committed empty policy is distinct from missing state", () =>
        {
            var path = PolicyPath(directory); var policy = Policy(path);
            Check(policy.Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
            var empty = policy.Replace(Array.Empty<string>());
            Check(empty.Success && empty.Count == 0 && empty.Revision == 2, "Empty commit incorrect");
            var restored = Policy(path); restored.InitializeForStartup();
            Check(restored.State.GetSnapshot().RestoreState == "Restored" && restored.State.GetSnapshot().Revision == 2 && restored.GetBlockedDomains().Length == 0, "Empty restore incorrect");
        });

        test("Phase5A write failure preserves previous memory file and committed revision", () =>
        {
            var path = PolicyPath(directory); var policy = Policy(path);
            Check(policy.Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
            var bytes = File.ReadAllBytes(path);
            using (var locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var result = policy.Replace(new[] { "new.invalid" });
                Check(!result.Success && result.FailureCategory == "PersistenceFailure" && result.Revision == 1, "Write failure acknowledged");
                Check(!result.Message.Contains(path) && policy.State.GetSnapshot().PersistenceFault == "PolicyWriteFailed", "Unsafe/missing failure state");
                Check(policy.GetBlockedDomains().SequenceEqual(new[] { "explicit.invalid" }) && File.ReadAllBytes(path).SequenceEqual(bytes), "Failed commit changed previous state");
            }
            Check(policy.Replace(new[] { "new.invalid" }).Revision == 2 && policy.State.GetSnapshot().PersistenceFault == "", "Recovery commit failed");
        });

        test("Phase5A invalid schema domains and oversized files load no partial policy", () =>
        {
            var samples = new[]
            {
                "{", "[]", "{}", "{\"schemaVersion\":2,\"revision\":1,\"domains\":[]}",
                "{\"schemaVersion\":1,\"revision\":0,\"domains\":[]}",
                "{\"schemaVersion\":1,\"revision\":1,\"domains\":[\"explicit.invalid\",\"explicit.invalid\"]}",
                "{\"schemaVersion\":1,\"revision\":1,\"domains\":[\"EXPLICIT.invalid\"]}",
                "{\"schemaVersion\":1,\"revision\":1,\"domains\":[\"https://explicit.invalid\"]}",
                "{\"schemaVersion\":1,\"revision\":1,\"domains\":[\"b.invalid\",\"a.invalid\"]}",
                "{\"schemaVersion\":1,\"revision\":1,\"revision\":2,\"domains\":[]}",
                "{\"schemaVersion\":1,\"revision\":1,\"domains\":[null]}",
                "{\"schemaVersion\":1,\"revision\":1,\"domains\":[\"bad name\"]}",
                "{\"schemaVersion\":1,\"revision\":1,\"domains\":[],\"extra\":true}",
                new string('x', PolicyPersistence.MaximumFileBytes + 1)
            };
            foreach (var sample in samples)
            {
                var path = PolicyPath(directory); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, sample);
                var policy = Policy(path); policy.InitializeForStartup(); var state = policy.State.GetSnapshot();
                Check(!state.Loaded && state.Revision == null && state.SafeMode && state.PersistenceFault == "PolicyInvalid", "Invalid policy trusted");
                Check(policy.GetBlockedDomains().Length == 0 && File.ReadAllText(path) == sample, "Corrupt evidence changed");
                Check(!policy.SetSafeMode(false).Success && !policy.Add(new[] { "new.invalid" }).Success, "Untrusted policy activated/merged");
            }
        });

        test("Phase5A unreadable policy remains a fault instead of a missing policy", () =>
        {
            var path = PolicyPath(directory); Directory.CreateDirectory(path);
            var policy = Policy(path); policy.InitializeForStartup();
            Check(!policy.State.GetSnapshot().Loaded && policy.State.GetSnapshot().RestoreState == "Unavailable" && policy.State.GetSnapshot().SafeMode, "Unreadable policy misclassified");
        });

        test("Phase5A recovery replacement preserves rejected evidence and requires explicit safe exit", () =>
        {
            var path = PolicyPath(directory); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, "{corrupt");
            var policy = Policy(path); policy.InitializeForStartup();
            Check(policy.Replace(new[] { "authorized.invalid" }).Success, "Recovery replacement failed");
            Check(policy.State.GetSnapshot().Loaded && policy.State.GetSnapshot().SafeMode && policy.State.GetSnapshot().Revision == 1, "Recovery silently enabled filtering");
            var evidence = Directory.GetFiles(Path.GetDirectoryName(path)!, "policy.json.rejected-*").Single();
            Check(File.ReadAllText(evidence) == "{corrupt", "Rejected evidence lost");
            Check(policy.SetSafeMode(false).Success && !policy.State.GetSnapshot().SafeMode, "Trusted recovery could not exit");
        });

        test("Phase5A Safe Mode changes neither committed policy bytes nor revision", () =>
        {
            var path = PolicyPath(directory); var policy = Policy(path);
            Check(policy.Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
            var bytes = File.ReadAllBytes(path);
            Check(policy.SetSafeMode(true).Success && policy.State.GetSnapshot().ActiveRuleCount == 0, "Safe entry failed");
            Check(policy.State.GetSnapshot().RuleCount == 1 && policy.State.GetSnapshot().Revision == 1, "Safe entry erased policy");
            Check(policy.SetSafeMode(false).Success && policy.State.GetSnapshot().ActiveRuleCount == 1, "Safe exit failed");
            Check(bytes.SequenceEqual(File.ReadAllBytes(path)), "Safe Mode wrote persistence");
        });

        test("Phase5A add and remove commit revisions and empty removal restores exactly", () =>
        {
            var path = PolicyPath(directory); var policy = Policy(path);
            Check(policy.Add(new[] { "explicit.invalid" }).Revision == 1, "First authorized add failed");
            var removed = policy.Remove("EXPLICIT.invalid");
            Check(removed.Success && removed.Removed && removed.Revision == 2 && removed.Count == 0, "Remove commit wrong");
            var restored = Policy(path); restored.InitializeForStartup();
            Check(restored.State.GetSnapshot().Revision == 2 && restored.GetBlockedDomains().Length == 0, "Removed rule restored");
            Check(restored.Remove("absent.invalid").Revision == 3, "Explicit no-op revision contract changed");
        });

        await asyncTest("Phase5A simultaneous management commits do not lose rules or revisions", async () =>
        {
            var path = PolicyPath(directory); var policy = Policy(path);
            policy.InitializeForStartup();
            var commits = Enumerable.Range(0, 6).Select(index => Task.Run(() => policy.Add(new[] { $"selected{index}.invalid" }))).ToArray();
            var results = await Task.WhenAll(commits);
            Check(results.All(result => result.Success) && results.Select(result => result.Revision).Order().SequenceEqual(new long?[] { 1, 2, 3, 4, 5, 6 }), "Commits lost revisions");
            var read = policy.ReadPolicy();
            Check(read.Revision == 6 && read.Domains.Length == 6, "Read snapshot incoherent");
            var restored = Policy(path); restored.InitializeForStartup();
            Check(restored.State.GetSnapshot().Revision == 6 && restored.GetBlockedDomains().SequenceEqual(read.Domains), "Concurrent commit restore wrong");
        });

        await asyncTest("Phase5A Safe Mode bypasses filtering through unchanged upstream processing", async () =>
        {
            var path = PolicyPath(directory); using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var config = Config(directory, path); config.UpstreamDnsPort = ((IPEndPoint)upstream.Client.LocalEndPoint!).Port;
            var settings = EngineSettings.FromConfig(config); var rules = new RuleStore("safe-bypass"); var policy = Policy(path, rules);
            Check(policy.Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
            var processor = new DnsRequestProcessor(rules, settings, new UpstreamDnsForwarder(settings), policy.State);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var query = Query("explicit.invalid", 1);
            var blocked = await processor.ProcessAsync(query, deadline.Token) ?? throw new Exception("Blocked response missing");
            Check(U16(blocked!, 6) == 1 && blocked![^4..].SequenceEqual(new byte[4]), "Initial filtering absent");
            policy.SetSafeMode(true);
            var processing = processor.ProcessAsync(query, deadline.Token);
            var received = await upstream.ReceiveAsync(deadline.Token);
            Check(received.Buffer.SequenceEqual(query), "Safe Mode changed forwarded request");
            var reply = (byte[])received.Buffer.Clone(); reply[2] |= 0x80; reply[3] |= 0x80;
            await upstream.SendAsync(reply, received.RemoteEndPoint, deadline.Token);
            Check((await processing)!.SequenceEqual(reply), "Safe Mode response not forwarded");
            policy.SetSafeMode(false);
            Check((await processor.ProcessAsync(query, deadline.Token))!.SequenceEqual(blocked), "Safe exit did not restore filtering");
        });

        await asyncTest("Phase5A startup restores before serving DNS and reports independent states", async () =>
        {
            var path = PolicyPath(directory); Check(Policy(path).Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
            var settings = EngineSettings.FromConfig(Config(directory, path)); var rules = new RuleStore("restored-process");
            await using var dns = new DnsProxyServer(rules, settings);
            var policy = Policy(path, rules, dns.PolicyState);
            await using var api = new ApiServer(policy, settings, dns.RuntimeStatus);
            using var cancellation = new CancellationTokenSource(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var lifetime = new EngineLifetime(api, dns).RunAsync(cancellation.Token);
            try
            {
                while (!dns.IsRunning) await Task.Delay(10, deadline.Token);
                using var client = new UdpClient(); await client.SendAsync(Query("explicit.invalid", 1), new IPEndPoint(IPAddress.Loopback, settings.DnsPort), deadline.Token);
                var response = await client.ReceiveAsync(deadline.Token);
                Check(U16(response.Buffer, 6) == 1 && response.Buffer[^4..].SequenceEqual(new byte[4]), "DNS served before restore");
                var status = api.GetDnsStatus();
                Check(status.RuntimeState == "Running" && status.UdpListening && status.ManagementListening && status.TcpImplemented && status.TcpListening, "Transport states wrong");
                Check(status.PolicyRestoreState == "Restored" && status.PolicyRevision == 1 && status.CommittedRuleCount == 1 && status.ActiveRuleCount == 1 && !status.EmergencySafeMode && status.UpstreamHealth == "NotMeasured", "Policy status wrong");
            }
            finally { cancellation.Cancel(); await lifetime.WaitAsync(deadline.Token); }
        });

        await asyncTest("Phase5A corrupt startup keeps UDP available through safe upstream bypass", async () =>
        {
            var path = PolicyPath(directory); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, "{corrupt");
            using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var config = Config(directory, path); config.UpstreamDnsPort = ((IPEndPoint)upstream.Client.LocalEndPoint!).Port;
            var settings = EngineSettings.FromConfig(config); var rules = new RuleStore("corrupt-process");
            await using var dns = new DnsProxyServer(rules, settings); var policy = Policy(path, rules, dns.PolicyState);
            await using var api = new ApiServer(policy, settings, dns.RuntimeStatus);
            using var cancellation = new CancellationTokenSource(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var lifetime = new EngineLifetime(api, dns).RunAsync(cancellation.Token);
            try
            {
                while (!dns.IsRunning) await Task.Delay(10, deadline.Token);
                using var client = new UdpClient(); var query = Query("arbitrary.invalid", 1);
                await client.SendAsync(query, new IPEndPoint(IPAddress.Loopback, settings.DnsPort), deadline.Token);
                var received = await upstream.ReceiveAsync(deadline.Token);
                var reply = (byte[])received.Buffer.Clone(); reply[2] |= 0x80; reply[3] |= 0x80;
                await upstream.SendAsync(reply, received.RemoteEndPoint, deadline.Token);
                Check((await client.ReceiveAsync(deadline.Token)).Buffer.SequenceEqual(reply), "Corrupt startup dropped DNS availability");
                var status = api.GetDnsStatus();
                Check(status.RuntimeState == "Running" && status.PolicyRestoreState == "Invalid" && !status.PolicyLoaded && status.PolicyRevision == null && status.EmergencySafeMode && status.ActiveRuleCount == 0 && status.PersistenceFault == "PolicyInvalid", "Corrupt status not truthful");
                Check(File.ReadAllText(path) == "{corrupt", "Startup overwrote evidence");
            }
            finally { cancellation.Cancel(); await lifetime.WaitAsync(deadline.Token); }
        });

        await VerifyApi(test, asyncTest, directory);
    }

    private static async Task VerifyApi(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest, string directory)
    {
        var path = PolicyPath(directory); var config = Config(directory, path); var settings = EngineSettings.FromConfig(config);
        var rules = new RuleStore("api-commit"); await using var dns = new DnsProxyServer(rules, settings);
        var policy = Policy(path, rules, dns.PolicyState); await using var api = new ApiServer(policy, settings, dns.RuntimeStatus);
        await api.StartAsync();
        try
        {
            using var certificate = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(File.ReadAllText(config.CertificatePath));
            var enrollment = Convert.ToBase64String(certificate.RawData); var token = File.ReadAllText(config.CredentialPath);
            using var http = new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, presented, _, errors) => ManagementSecurity.ValidateCertificate(presented, enrollment, errors)
            });
            http.Timeout = TimeSpan.FromSeconds(5);
            var endpoint = $"https://127.0.0.1:{settings.ApiPort}";
            async Task<HttpResponseMessage> Post(string route, string body, bool authorized = true)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint + route);
                if (authorized) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");
                return await http.SendAsync(request);
            }

            await asyncTest("Phase5A management acknowledges durable commit and rejects failed persistence", async () =>
            {
                using (var response = await Post("/rules/blocked/replace", "{\"blocked\":[\"explicit.invalid\"]}"))
                {
                    using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    Check(response.IsSuccessStatusCode && result.RootElement.GetProperty("ok").GetBoolean() && result.RootElement.GetProperty("revision").GetInt64() == 1, "Successful commit contract wrong");
                    Check(new PolicyPersistence(path).Load().Policy!.Revision == 1, "Success preceded durable state");
                }
                var bytes = File.ReadAllBytes(path);
                using (var locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var response = await Post("/rules/blocked/replace", "{\"blocked\":[\"new.invalid\"]}"))
                {
                    var body = await response.Content.ReadAsStringAsync(); using var result = JsonDocument.Parse(body);
                    Check(response.StatusCode == HttpStatusCode.ServiceUnavailable && !result.RootElement.GetProperty("ok").GetBoolean(), "Persistence failure returned success");
                    Check(!body.Contains(path) && !body.Contains(token), "Failure leaked secrets/path");
                }
                Check(policy.GetBlockedDomains().SequenceEqual(new[] { "explicit.invalid" }) && bytes.SequenceEqual(File.ReadAllBytes(path)), "Failed API request changed committed policy");
            });

            await asyncTest("Phase5A authentication protects Safe Mode and every rule mutation", async () =>
            {
                foreach (var route in new[] { "/safe-mode/enter", "/safe-mode/exit", "/rules/blocked/replace", "/rules/blocked/add", "/rules/blocked/remove" })
                using (var response = await Post(route, "{}", authorized: false))
                    Check(response.StatusCode == HttpStatusCode.Unauthorized, "Unauthenticated mutation accepted");
                Check(!policy.State.GetSnapshot().SafeMode && policy.State.GetSnapshot().Revision == 1, "Unauthorized request changed state");
                using var malformed = await Post("/safe-mode/enter", "{\"unexpected\":true}");
                Check(malformed.StatusCode == HttpStatusCode.BadRequest && !policy.State.GetSnapshot().SafeMode, "Unbounded/implicit safe command accepted");
            });

            await asyncTest("Phase5A health and Test Connection cannot mutate policy or active Safe Mode", async () =>
            {
                var bytes = File.ReadAllBytes(path);
                using (var response = await Post("/safe-mode/enter", "{}")) Check(response.IsSuccessStatusCode, "Authenticated safe entry failed");
                var before = policy.State.GetSnapshot();
                var clientConfig = new DnsEngineConfig { Address = "127.0.0.1", ManagementPort = settings.ApiPort, TrustedCertificate = enrollment, ApiToken = token };
                var result = await new DnsEngineService().TestConnectionAsync(clientConfig);
                Check(result.Ok && result.Transport!.EmergencySafeMode && result.Transport.PolicyRevision == 1 && result.Transport.ActiveRuleCount == 0, "Safe state lost in read-only client");
                Check(policy.State.GetSnapshot() == before && bytes.SequenceEqual(File.ReadAllBytes(path)), "Connection test mutated policy/Safe Mode");
                using (var response = await Post("/safe-mode/exit", "{}")) Check(response.IsSuccessStatusCode, "Authenticated safe exit failed");
                Check(!policy.State.GetSnapshot().SafeMode && policy.State.GetSnapshot().Revision == 1 && bytes.SequenceEqual(File.ReadAllBytes(path)), "Safe exit changed committed state");
            });
        }
        finally { await api.StopAsync(); }
    }
}
