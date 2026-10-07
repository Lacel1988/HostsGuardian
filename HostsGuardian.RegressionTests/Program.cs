using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

if(args.Contains("--fingerprint-observe"))
{
    await FingerprintDiscovery.RefreshAsync();
    var now=DateTimeOffset.UtcNow;var observations=new LanObservationStore().Observe(PassiveIdentityEvidence.Read(),now);
    Console.WriteLine(JsonSerializer.Serialize(new {observations,evidence=FingerprintDiscovery.Snapshot(now),report=FingerprintDiscovery.LastReport},new JsonSerializerOptions{PropertyNamingPolicy=JsonNamingPolicy.CamelCase}));return;
}
if(args.Contains("--lan-discovery-observe") || args.Contains("--lan-discovery-passive"))
{
    var evidence=args.Contains("--lan-discovery-passive")?PassiveIdentityEvidence.Read():await LanDiscoveryRefresh.RefreshAsync();
    var observations=new LanObservationStore().Observe(evidence,DateTimeOffset.UtcNow);
    Console.WriteLine(JsonSerializer.Serialize(new {observations,evidence,discoveryStatus=LanDiscoveryRefresh.LastReport},new JsonSerializerOptions{PropertyNamingPolicy=JsonNamingPolicy.CamelCase}));
    return;
}
var passed = 0;
var fixtureRoot = Path.Combine(Path.GetTempPath(), "HostsGuardian-regression-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(fixtureRoot);
void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
void Test(string name, Action action) { action(); passed++; Console.WriteLine("PASS " + name); }
async Task AsyncTest(string name, Func<Task> action) { await action(); passed++; Console.WriteLine("PASS " + name); }
string Fixture(string name, string content)
{
    var path = Path.Combine(fixtureRoot, name);
    File.WriteAllText(path, content, new UTF8Encoding(false));
    return path;
}
var config = new AppConfig { BlockedDomains = new()
{
    new() { Domain = "neither.invalid" },
    new() { Domain = "hosts.invalid" },
    new() { Domain = "dns.invalid", DnsBlocked = true },
    new() { Domain = "both.invalid", DnsBlocked = true }
} };

try
{
    FingerprintTests.Run(Test);
    Test("shared device type inference preserves uncertainty and user authority", () =>
    {
        Check(DeviceTypes.All.Count == 13 && DeviceTypes.All.Select(t=>t.IconKey).Distinct().Count()==13, "Catalog/icon mismatch");
        Check(DeviceTypes.All.All(t=>t.Strokes.Length>0 && t.IconPath.StartsWith("M ")), "Missing vector icon");
        Check(DeviceTypes.Assess("Phone",["office-printer"]).Type.Id=="Phone", "Inference overrode user");
        Check(DeviceTypes.Assess("Unknown",["my-iphone"]).Source=="USER-CONFIRMED", "Explicit Unknown lost");
        Check(DeviceTypes.Assess("",["my-iphone"]).Confidence=="Low", "Hostname certainty fabricated");
        foreach(var names in new[]{Array.Empty<string>(),new[]{"Samsung"},new[]{"phone-printer"},new[]{"my-phone","other-phone"}})
            Check(DeviceTypes.Assess("",names).Type.Id=="Unknown", "Ambiguous/vendor evidence classified");
        Check(DeviceTypes.Assess("LegacyType",["my-iphone"]).Type.Id=="Unknown", "Legacy user metadata silently replaced");
    });
    Test("mechanism selection matrix", () =>
    {
        Check(DomainPolicySelection.ForDns(config.BlockedDomains).SequenceEqual(new[] { "both.invalid", "dns.invalid" }), "DNS leaked unselected domains");
    });
    Test("missing flags do not authorize legacy filtering", () =>
    {
        var entry = JsonSerializer.Deserialize<DomainEntry>("{\"Domain\":\"legacy.invalid\"}")!;
        Check(!entry.DnsBlocked, "Implicit legacy authorization");
    });
    Test("selection notifications and JSON persistence", () =>
    {
        var entry = new DomainEntry { Domain = "selection.invalid" };
        var changes = new List<string?>();
        entry.PropertyChanged += (_, e) => changes.Add(e.PropertyName);
        entry.DnsBlocked = true;
        var restored = JsonSerializer.Deserialize<DomainEntry>(JsonSerializer.Serialize(entry))!;
        Check(changes.SequenceEqual(new[] { "DnsBlocked" }) && restored.DnsBlocked, "Lost checkbox choices");
    });
    Test("normalization preserves selected subdomain and supports IDN", () =>
    {
        Check(DomainName.Normalize(" HTTPS://WWW.Example.invalid/path ") == "www.example.invalid", "Selection broadened");
        Check(DomainName.Normalize("bücher.invalid.") == "xn--bcher-kva.invalid", "IDN normalization failed");
        Check(DomainName.Normalize("bad name.invalid") == "" && DomainName.Normalize("a.invalid\nb.invalid") == "", "Injection accepted");
    });
    Test("legacy HOSTS flags never authorize DNS and do not serialize", () =>
    {
        var entry = JsonSerializer.Deserialize<DomainEntry>("{\"Domain\":\"legacy.invalid\",\"HostsBlocked\":true}")!;
        Check(!entry.DnsBlocked && !JsonSerializer.Serialize(entry).Contains("HostsBlocked"), "Legacy HOSTS authorization survived");
    });
    Test("legacy cleanup preserves unrelated bytes, BOM and backups", () =>
    {
        foreach (var encoding in new Encoding[] { new UTF8Encoding(false), new UTF8Encoding(true), Encoding.Unicode, Encoding.BigEndianUnicode, Encoding.UTF32 })
        foreach (var markers in new[] { ("# BEGIN HOSTSGUARDIAN", "# END HOSTSGUARDIAN"), ("# HOSTSGUARDIAN BEGIN", "# HOSTSGUARDIAN END") })
        {
            var path = Path.Combine(fixtureRoot, Guid.NewGuid().ToString("N"));
            const string unrelated = "# Árvíztűrő\r\n127.0.0.1 localhost\r\n";
            File.WriteAllText(path, unrelated + markers.Item1 + "\r\n0.0.0.0 old.invalid\r\n" + markers.Item2 + "\r\n", encoding);
            var original = File.ReadAllBytes(path);
            var cleanup = new LegacyHostsCleanup(path);
            Check(cleanup.IsBlockPresent() && cleanup.Cleanup().ok, "Cleanup failed");
            Check(File.ReadAllBytes(Directory.GetFiles(fixtureRoot, Path.GetFileName(path) + ".backup_*").Single()).SequenceEqual(original), "Backup bytes lost");
            Check(File.ReadAllText(path) == unrelated && !cleanup.IsBlockPresent(), "Unrelated content lost");
            var expected = encoding.GetPreamble().Concat(encoding.GetBytes(unrelated));
            Check(File.ReadAllBytes(path).SequenceEqual(expected), "Encoding changed");
            Check(cleanup.Cleanup().ok && Directory.GetFiles(fixtureRoot, Path.GetFileName(path) + ".backup_*").Length == 1, "Cleanup not idempotent");
        }
    });
    Test("legacy cleanup preserves arbitrary BOM-less bytes and refuses malformed encoded content", () =>
    {
        var path = Path.Combine(fixtureRoot, "legacy-byte-hosts");
        var prefix = new byte[] { 35, 32, 0x81, 0xFF, 0xC0, 10 };
        File.WriteAllBytes(path, prefix.Concat(Encoding.ASCII.GetBytes("# BEGIN HOSTSGUARDIAN\n0.0.0.0 old.invalid\n# END HOSTSGUARDIAN\n")).ToArray());
        Check(new LegacyHostsCleanup(path).Cleanup().ok && File.ReadAllBytes(path).SequenceEqual(prefix), "Unknown encoding bytes changed");
        var bad = new byte[] { 0xEF, 0xBB, 0xBF, 0xFF }; File.WriteAllBytes(path, bad);
        Check(!new LegacyHostsCleanup(path).Cleanup().ok && File.ReadAllBytes(path).SequenceEqual(bad), "Malformed Unicode rewritten");
    });
    Test("malformed ownership blocks refuse cleanup before backup", () =>
    {
        foreach (var content in new[] { "# BEGIN HOSTSGUARDIAN\n", "# END HOSTSGUARDIAN\n", "# BEGIN HOSTSGUARDIAN\n# HOSTSGUARDIAN END\n", "# BEGIN HOSTSGUARDIAN\n# BEGIN HOSTSGUARDIAN\n# END HOSTSGUARDIAN\n" })
        {
            var path = Fixture(Guid.NewGuid().ToString("N"), content);
            Check(!new LegacyHostsCleanup(path).Cleanup().ok && File.ReadAllText(path) == content && Directory.GetFiles(fixtureRoot, Path.GetFileName(path) + ".backup_*").Length == 0, "Malformed file changed");
        }
    });
    Test("Engine starts empty and read operations do not create rules", () =>
    {
        var rules = new RuleStore("isolated-fixture");
        Check(rules.GetBlockedDomains().Length == 0 && !rules.IsBlocked("arbitrary.invalid") && rules.GetBlockedDomains().Length == 0, "Automatic Engine policy");
    });
    Test("Engine rule removal leaves no generated www rule", () =>
    {
        var rules = new RuleStore("isolated-fixture");
        rules.SetBlockedDomains(new[] { "EXPLICIT.invalid.", "explicit.invalid" });
        Check(rules.GetBlockedDomains().SequenceEqual(new[] { "explicit.invalid" }), "Extra stored rule");
        Check(rules.IsBlocked("www.explicit.invalid") && rules.IsBlocked("api.explicit.invalid"), "Documented descendants not matched");
        Check(!rules.IsBlocked("otherexplicit.invalid"), "Boundary mismatch");
        Check(rules.RemoveBlockedDomain("explicit.invalid") && !rules.IsBlocked("www.explicit.invalid"), "Hidden block survived removal");
    });
    Test("invalid Engine updates preserve previous policy", () =>
    {
        var rules = new RuleStore("isolated-fixture"); rules.SetBlockedDomains(new[] { "existing.invalid" });
        foreach (var replace in new[] { true, false })
        {
            try { if (replace) rules.SetBlockedDomains(new[] { "new.invalid", "bad value" }); else rules.AddBlockedDomains(new[] { "new.invalid", "bad value" }); throw new Exception("Invalid update accepted"); }
            catch (ArgumentException) { }
            Check(rules.GetBlockedDomains().SequenceEqual(new[] { "existing.invalid" }), "Partial policy mutation");
        }
    });
    Test("MAC identity survives DHCP changes without legacy IP inheritance", () =>
    {
        var policies = new List<DevicePolicy> { new() { Ip = "192.0.2.10", Name = "Legacy", IsBlocked = true } };
        DevicePolicyIdentity.Save(policies, "192.0.2.10", "02-aa-bb-cc-dd-ee", "Device A", true);
        var original = DevicePolicyIdentity.Find(policies, "02:AA:BB:CC:DD:EE");
        Check(original != null && original.Name == "Device A" && policies[0].Name == "Legacy", "Legacy policy auto-assigned");
        DevicePolicyIdentity.Save(policies, "192.0.2.20", "02-aa-bb-cc-dd-ee", "Device A", true);
        Check(ReferenceEquals(original, DevicePolicyIdentity.Find(policies, "02:aa:bb:cc:dd:ee")) && original!.Ip == "192.0.2.20", "DHCP lost identity");
        Check(DevicePolicyIdentity.Find(policies, "02:00:00:00:00:01") == null && DevicePolicyIdentity.Find(policies, "") == null, "Unobserved identity inherited policy");
        var restored = JsonSerializer.Deserialize<List<DevicePolicy>>(JsonSerializer.Serialize(policies))!;
        Check(DevicePolicyIdentity.Find(restored, "02-aa-bb-cc-dd-ee")?.Mac == "02:AA:BB:CC:DD:EE", "MAC persistence lost");
    });
    Test("ambiguous MAC policies are not arbitrarily correlated", () =>
    {
        var policies = new List<DevicePolicy> { new() { Mac = "02:AA:BB:CC:DD:EE" }, new() { Mac = "02-aa-bb-cc-dd-ee" } };
        Check(DevicePolicyIdentity.Find(policies, "02:AA:BB:CC:DD:EE") == null, "Ambiguous identity picked");
        try { DevicePolicyIdentity.Save(policies, "192.0.2.1", "02:AA:BB:CC:DD:EE", "X", true); throw new Exception("Duplicate saved"); }
        catch (InvalidDataException) { }
    });
    await AsyncTest("reverse DNS timeout is bounded", async () =>
    {
        var watch = Stopwatch.StartNew();
        var result = await NetworkScanService.ResolveHostnameAsync("192.0.2.1", TimeSpan.FromMilliseconds(50),
            (_, _) => new TaskCompletionSource<IPHostEntry>().Task);
        Check(result == "" && watch.Elapsed < TimeSpan.FromSeconds(2), "Lookup deadline failed");
    });
    await AsyncTest("reverse DNS success and failure remain metadata only", async () =>
    {
        var before = JsonSerializer.Serialize(config);
        var found = await NetworkScanService.ResolveHostnameAsync("192.0.2.1", TimeSpan.FromSeconds(1),
            (_, _) => Task.FromResult(new IPHostEntry { HostName = "observed.invalid." }));
        var missing = await NetworkScanService.ResolveHostnameAsync("192.0.2.1", TimeSpan.FromSeconds(1),
            (_, _) => Task.FromException<IPHostEntry>(new System.Net.Sockets.SocketException()));
        Check(found == "observed.invalid" && missing == "" && before == JsonSerializer.Serialize(config), "Discovery altered policy");
    });
    await AsyncTest("client pushes only selected DNS domains and health uses GET", async () =>
    {
        var handler = new RecordingHandler();
        using var http = new HttpClient(handler);
        var client = new DnsEngineClient(http);
        var cfg = new DnsEngineConfig { Enabled = true, BaseUrl = "http://fixture.invalid:3000", ApiToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
        var before = JsonSerializer.Serialize(config);
        Check((await client.PushDomainsAsync(cfg, config)).ok, "Mock push failed");
        var request = handler.Requests.Single();
        var payload = JsonDocument.Parse(request.body);
        Check(request.method == HttpMethod.Post && request.path == "/rules/blocked/replace", "Wrong API route");
        Check(payload.RootElement.GetProperty("blocked").EnumerateArray().Select(x => x.GetString()).SequenceEqual(new[] { "both.invalid", "dns.invalid" }), "Client sent unselected domains");
        Check((await client.TestHealthAsync(cfg)).ok && handler.Requests.Last().method == HttpMethod.Get && handler.Requests.Last().path == "/dns/status", "Health modified policy");
        Check(before == JsonSerializer.Serialize(config), "Client mutated GUI policy");
    });
    await AsyncTest("primary GUI adapter pushes explicit selection; health/status are GET only", async () =>
    {
        var handler = new RecordingHandler();
        var adapter = new DnsEngineService(() => new HttpClient(handler, disposeHandler: false));
        var cfg = new DnsEngineConfig { Enabled = true, BaseUrl = "http://fixture.invalid:3000", ApiToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
        var before = JsonSerializer.Serialize(config);
        Check((await adapter.PushBlockedDomainsAsync(cfg, DomainPolicySelection.ForDns(config.BlockedDomains))).ok, "Primary push failed");
        var request = handler.Requests.Single();
        using var body = JsonDocument.Parse(request.body);
        Check(request.path == "/rules/blocked/replace" && body.RootElement.GetProperty("blocked").EnumerateArray().Select(x => x.GetString()).SequenceEqual(new[] { "both.invalid", "dns.invalid" }), "Primary payload leaked policy");
        Check((await adapter.TestAsync(cfg)).ok && (await adapter.GetBlockedDomainsAsync(cfg)).ok && (await adapter.GetDnsStatusAsync(cfg)).ok, "Read-only calls failed");
        Check(handler.Requests.Skip(1).All(r => r.method == HttpMethod.Get && r.body.Length == 0), "Read-only call issued mutation");
        Check(before == JsonSerializer.Serialize(config), "Read-only calls altered configured domain policy");
    });
    Test("DNS exports exclude unselected domains", () =>
    {
        foreach (var output in new[] { new DnsBlockService().BuildZeroIpList(config.BlockedDomains), new DnsBlockService().BuildAdGuardList(config.BlockedDomains), new DnsBlocklistExportService().ExportDomainsPlain(config.BlockedDomains), new DnsBlocklistExportService().ExportHostsStyle(config.BlockedDomains) })
            Check(output.Contains("dns.invalid") && output.Contains("both.invalid") && !output.Contains("hosts.invalid") && !output.Contains("neither.invalid"), "Export leaked policy");
    });

    await AsyncTest("DNS cache flush requires successful completed exit", async () =>
    {
        foreach (int? code in new int?[] { null, 1, -1, 0 })
            Check((await new DnsCacheFlushService(_ => Task.FromResult(code)).FlushAsync()).Success == (code == 0), "Launch mistaken for success");
        Check(!(await new DnsCacheFlushService(_ => throw new OperationCanceledException()).FlushAsync()).Success, "Timeout reported success");
        Check(!(await new DnsCacheFlushService(_ => throw new System.ComponentModel.Win32Exception()).FlushAsync()).Success, "Start failure reported success");
    });
    await ValidatedBindingTests.Run(Test, AsyncTest, fixtureRoot);
    await NetworkTopologyTests.Run(Test,AsyncTest);
    IntegratedPolicyTests.Run(Test, fixtureRoot);
    RoadmapPolicyTests.Run(Test, fixtureRoot);
    RoadmapDataTests.Run(Test, fixtureRoot);
    DeviceDiagnosticsTests.Run(Test, fixtureRoot);
    await FullPolicyClientTests.Run(AsyncTest);
    ArchitectureTests.Run(Test);
    await SecurityTests.Run(Test, AsyncTest, fixtureRoot);
    await PreparationTests.Run(Test, AsyncTest, fixtureRoot);
    await Phase5ATests.Run(Test, AsyncTest, fixtureRoot);
    await Phase5BTests.Run(Test, AsyncTest, fixtureRoot);
    await Phase5CTests.Run(Test, AsyncTest, fixtureRoot);
    await Phase5DTests.Run(Test, AsyncTest, fixtureRoot);
    await RoadmapRecoveryTests.Run(AsyncTest, fixtureRoot);
    await RoadmapNetworkTests.Run(AsyncTest, fixtureRoot);
    await Phase5ES1Tests.Run(Test, AsyncTest, fixtureRoot);
    await DiagnosticsTests.Run(Test, AsyncTest, fixtureRoot);
    await DualStackTests.Run(Test, AsyncTest, fixtureRoot);
    LanDiscoveryTests.Run(Test);
    Console.WriteLine($"{passed} regression groups passed. No system hosts, real DNS, or deployment service was changed.");
}
finally { Console.WriteLine("Isolated fixture directory: " + fixtureRoot); }

sealed class RecordingHandler : HttpMessageHandler
{
    public List<(HttpMethod method, string path, string body)> Requests { get; } = new();
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add((request.Method, request.RequestUri!.AbsolutePath, request.Content == null ? "" : await request.Content.ReadAsStringAsync(cancellationToken)));
        var selectedCount = 0;
        if (request.Method == HttpMethod.Post)
        {
            using var selected = JsonDocument.Parse(Requests.Last().body);
            selectedCount = selected.RootElement.GetProperty("blocked").GetArrayLength();
        }
        var body = request.RequestUri!.AbsolutePath == "/dns/status"
            ? JsonSerializer.Serialize(new DnsServiceStatus { Implementation = "HostsGuardian.DnsEngine", DnsPort = 53, TcpTargetPort = 53, ApiPort = 3000 })
            : request.RequestUri!.AbsolutePath == "/health" ? "{\"engine\":\"HostsGuardian.DnsEngine\",\"apiVersion\":1}" : JsonSerializer.Serialize(new { ok = true, blocked = Array.Empty<string>(), revision = 1, count = selectedCount });
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
    }
}
