using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

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
    new() { Domain = "hosts.invalid", HostsBlocked = true },
    new() { Domain = "dns.invalid", DnsBlocked = true },
    new() { Domain = "both.invalid", HostsBlocked = true, DnsBlocked = true }
} };

try
{
    Test("mechanism selection matrix", () =>
    {
        Check(DomainPolicySelection.ForHosts(config.BlockedDomains).SequenceEqual(new[] { "both.invalid", "hosts.invalid" }), "Hosts leaked unselected domains");
        Check(DomainPolicySelection.ForDns(config.BlockedDomains).SequenceEqual(new[] { "both.invalid", "dns.invalid" }), "DNS leaked unselected domains");
    });
    Test("missing flags do not authorize legacy filtering", () =>
    {
        var entry = JsonSerializer.Deserialize<DomainEntry>("{\"Domain\":\"legacy.invalid\"}")!;
        Check(!entry.HostsBlocked && !entry.DnsBlocked, "Implicit legacy authorization");
    });
    Test("selection notifications and JSON persistence", () =>
    {
        var entry = new DomainEntry { Domain = "selection.invalid" };
        var changes = new List<string?>();
        entry.PropertyChanged += (_, e) => changes.Add(e.PropertyName);
        entry.HostsBlocked = true; entry.DnsBlocked = true;
        var restored = JsonSerializer.Deserialize<DomainEntry>(JsonSerializer.Serialize(entry))!;
        Check(changes.SequenceEqual(new[] { "HostsBlocked", "DnsBlocked" }) && restored.HostsBlocked && restored.DnsBlocked, "Lost checkbox choices");
    });
    Test("normalization preserves selected subdomain and supports IDN", () =>
    {
        Check(DomainName.Normalize(" HTTPS://WWW.Example.invalid/path ") == "www.example.invalid", "Selection broadened");
        Check(DomainName.Normalize("bücher.invalid.") == "xn--bcher-kva.invalid", "IDN normalization failed");
        Check(DomainName.Normalize("bad name.invalid") == "" && DomainName.Normalize("a.invalid\nb.invalid") == "", "Injection accepted");
    });
    Test("hosts apply backs up bytes and emits selected IPv4/IPv6 only", () =>
    {
        var original = "# untouched\r\n127.0.0.1 localhost\r\n192.0.2.1 internal.invalid\r\n";
        var path = Fixture("apply-hosts", original);
        var service = new HostsService(path);
        var result = service.Apply(config);
        Check(result.ok, result.message);
        var output = File.ReadAllText(path);
        Check(output.StartsWith(original) && output.Contains("0.0.0.0 hosts.invalid") && output.Contains("::1 hosts.invalid"), "Preservation/address families failed");
        Check(!output.Contains("dns.invalid") && !output.Contains("neither.invalid"), "Hosts leaked policy");
        Check(File.ReadAllText(Directory.GetFiles(fixtureRoot, "apply-hosts.backup_*").Single()) == original, "Incorrect backup");
        Check(service.IsBlockPresent(), "Block undetected");
        Check(service.Revert().ok && File.ReadAllText(path) == original && !service.IsBlockPresent(), "Revert damaged unrelated bytes");
        Check(Directory.GetFiles(fixtureRoot, "apply-hosts.backup_*").Length == 2, "Revert backup missing");
    });
    Test("legacy/current duplicate blocks consolidate and revert", () =>
    {
        var prefix = "127.0.0.1 localhost\n";
        var suffix = "192.0.2.1 keep.invalid\n";
        var path = Fixture("markers", prefix + "# HOSTSGUARDIAN BEGIN\n0.0.0.0 old.invalid\n# HOSTSGUARDIAN END\n" +
            "# BEGIN HOSTSGUARDIAN\n0.0.0.0 second.invalid\n# END HOSTSGUARDIAN\n" + suffix);
        var service = new HostsService(path);
        Check(service.IsBlockPresent(), "Legacy not detected");
        Check(service.ReadCurrentBlockedDomains().Count == 2, "Legacy rules unreadable");
        Check(service.Apply(new[] { "new.invalid" }).ok, "Consolidation failed");
        var output = File.ReadAllText(path);
        Check(!output.Contains("old.invalid") && !output.Contains("second.invalid") && output.Split("# BEGIN HOSTSGUARDIAN").Length == 2, "Old block survived");
        Check(service.Revert().ok && File.ReadAllText(path) == prefix + suffix, "Unrelated content damaged");
    });
    Test("malformed ownership markers refuse writes", () =>
    {
        var malformed = new[] { "# BEGIN HOSTSGUARDIAN\n", "# END HOSTSGUARDIAN\n", "# BEGIN HOSTSGUARDIAN\n# HOSTSGUARDIAN END\n", "# BEGIN HOSTSGUARDIAN\n# BEGIN HOSTSGUARDIAN\n# END HOSTSGUARDIAN\n" };
        foreach (var content in malformed)
        {
            var path = Fixture(Guid.NewGuid().ToString("N"), content);
            var service = new HostsService(path);
            Check(!service.Apply(new[] { "new.invalid" }).ok && !service.Revert().ok, "Unsafe markers accepted");
            Check(File.ReadAllText(path) == content && Directory.GetFiles(fixtureRoot, Path.GetFileName(path) + ".backup_*").Length == 0, "Unsafe write occurred");
        }
    });
    Test("preview is full-file and non-destructive", () =>
    {
        var original = "127.0.0.1 localhost\n";
        var path = Fixture("preview", original);
        var output = new HostsService(path).PreviewResult(config);
        Check(output.StartsWith(original) && output.Contains("::1 hosts.invalid") && !output.Contains("dns.invalid"), "Preview policy mismatch");
        Check(File.ReadAllText(path) == original && Directory.GetFiles(fixtureRoot, "preview.backup_*").Length == 0, "Preview wrote files");
    });
    Test("empty selected hosts policy removes owned blocks only", () =>
    {
        var path = Fixture("empty", "127.0.0.1 localhost\n# HOSTSGUARDIAN BEGIN\n0.0.0.0 old.invalid\n# HOSTSGUARDIAN END\n");
        var service = new HostsService(path);
        Check(service.Apply(new AppConfig()).ok && File.ReadAllText(path) == "127.0.0.1 localhost\n" && !service.IsBlockPresent(), "Empty policy remained active");
    });
    Test("backup failure prevents hosts write", () =>
    {
        // Existing hosts name is valid, but its generated backup component exceeds NTFS's 255-character limit.
        var path = Fixture(new string('b', 220), "127.0.0.1 localhost\n");
        var original = File.ReadAllBytes(path);
        var result = new HostsService(path).Apply(new[] { "new.invalid" });
        Check(!result.ok && File.ReadAllBytes(path).SequenceEqual(original), "Write continued after failed backup");
        var missing = new HostsService(Path.Combine(fixtureRoot, "missing-hosts"));
        Check(!missing.Apply(new[] { "new.invalid" }).ok && !missing.Revert().ok, "Missing hosts falsely succeeded");
    });
    Test("hosts preserves BOM/encoding and unrelated non-ASCII entries", () =>
    {
        foreach (var encoding in new Encoding[] { new UTF8Encoding(true), Encoding.Unicode, Encoding.BigEndianUnicode, Encoding.UTF32 })
        {
            var path = Path.Combine(fixtureRoot, Guid.NewGuid().ToString("N"));
            File.WriteAllText(path, "# Árvíztűrő\r\n127.0.0.1 localhost\r\n", encoding);
            var original = File.ReadAllBytes(path);
            var service = new HostsService(path);
            Check(service.Apply(new[] { "encoding.invalid" }).ok && service.Revert().ok, "Encoded hosts failed");
            Check(File.ReadAllBytes(path).SequenceEqual(original), "Original encoding/content lost");
        }
    });
    Test("invalid selected input cannot clear existing hosts policy", () =>
    {
        var path = Fixture("invalid", "# BEGIN HOSTSGUARDIAN\n0.0.0.0 existing.invalid\n# END HOSTSGUARDIAN\n");
        var original = File.ReadAllText(path);
        var invalid = new AppConfig { BlockedDomains = new() { new() { Domain = "bad\nvalue.invalid", HostsBlocked = true } } };
        Check(!new HostsService(path).Apply(invalid).ok && File.ReadAllText(path) == original, "Invalid input changed policy");
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
    ArchitectureTests.Run(Test);
    await SecurityTests.Run(Test, AsyncTest, fixtureRoot);
    await PreparationTests.Run(Test, AsyncTest, fixtureRoot);
    await Phase5ATests.Run(Test, AsyncTest, fixtureRoot);
    await Phase5BTests.Run(Test, AsyncTest, fixtureRoot);
    await Phase5CTests.Run(Test, AsyncTest, fixtureRoot);
    Console.WriteLine($"{passed} regression groups passed. No system hosts, real DNS, or deployment service was changed.");
}
finally { Console.WriteLine("Isolated fixture directory: " + fixtureRoot); }

sealed class RecordingHandler : HttpMessageHandler
{
    public List<(HttpMethod method, string path, string body)> Requests { get; } = new();
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add((request.Method, request.RequestUri!.AbsolutePath, request.Content == null ? "" : await request.Content.ReadAsStringAsync(cancellationToken)));
        var body = request.RequestUri!.AbsolutePath == "/dns/status"
            ? JsonSerializer.Serialize(new DnsServiceStatus { Implementation = "HostsGuardian.DnsEngine", DnsPort = 53, TcpTargetPort = 53, ApiPort = 3000 })
            : request.RequestUri!.AbsolutePath == "/health" ? "{\"engine\":\"HostsGuardian.DnsEngine\",\"apiVersion\":1}" : "{\"ok\":true,\"blocked\":[]}";
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
    }
}
