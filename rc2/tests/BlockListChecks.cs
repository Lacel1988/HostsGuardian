using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

static class BlockListChecks
{
    public static async Task Run(PolicyApplicationService policy, Guid device, Guid other, string admin, string op, string observer,
        Func<string, string, string?, object?, bool, Task<HttpResponseMessage>> send, Action<string, bool> check, string directory)
    {
        var baseline = policy.ReadFullPolicy();
        string PathFor(Guid? id) => "/v1/access/block-list" + (id.HasValue ? "?deviceId=" + id : "");
        object Body(string name, bool enabled, bool delete = false) { var r = policy.ReadFullPolicy(); return new { expectedInstanceId = r.InstanceId, expectedRevision = r.Revision, domain = name, enabled, delete }; }
        async Task<int> Write(Guid? id, string session, string name, bool enabled, bool delete = false) { using var r = await send(PathFor(id), "POST", session, Body(name, enabled, delete), true); return (int)r.StatusCode; }
        async Task<JsonElement> Read(Guid? id, string session) { using var r = await send(PathFor(id), "GET", session, null, true); r.EnsureSuccessStatusCode(); using var doc = JsonDocument.Parse(await r.Content.ReadAsStringAsync()); return doc.RootElement.Clone(); }
        check("Block list observer mutation denied", await Write(null, observer, "list.invalid", true) == 403);
        check("Block list operator global mutation denied", await Write(null, op, "list.invalid", true) == 403);
        check("Block list operator cross-device read denied", (int)(await send(PathFor(other), "GET", op, null, true)).StatusCode == 403);
        check("Block list operator cross-device mutation denied", await Write(other, op, "list.invalid", true) == 403);
        check("Block list operator assigned device saved", await Write(device, op, "device.invalid", true) == 200 && policy.ReadFullPolicy().Policy.Overrides.Any(r => r.DeviceId == device && r.Domain == "device.invalid" && r.State == DeviceDomainRuleState.Block));
        check("Block list add global normalized", await Write(null, admin, "LIST.INVALID", true) == 200 && policy.ReadFullPolicy().Policy.GlobalBlockedDomains.Contains("list.invalid"));
        check("Block list disable succeeds", await Write(null, admin, "list.invalid", false) == 200);
        var off = await Read(null, admin);
        check("Block list disabled row remains engine-side", off.GetProperty("rows").EnumerateArray().Any(r => r.GetProperty("domain").GetString() == "list.invalid" && r.GetProperty("saved").GetBoolean() && !r.GetProperty("configuredBlocked").GetBoolean() && !r.GetProperty("effectiveBlocked").GetBoolean()));
        var restart = new PolicyPersistence(Path.Combine(directory, "policy.json")).Load();
        check("Block list disabled row survives persistence reload", restart.State == "Restored" && restart.Policy!.Policy!.SavedDomains!.Value.Any(e => e.DeviceId == null && e.Domain == "list.invalid"));
        check("Block list re-enable succeeds", await Write(null, admin, "list.invalid", true) == 200);
        check("Block list duplicate add idempotent membership", await Write(null, admin, "list.invalid", true) == 200 && DomainBlockList.Entries(policy.ReadFullPolicy().Policy).Count(e => e.Domain == "list.invalid" && e.DeviceId == null) == 1);
        check("Block list disabled device does not create Allow", await Write(device, op, "list.invalid", false) == 200 && !policy.ReadFullPolicy().Policy.Overrides.Any(r => r.DeviceId == device && r.Domain == "list.invalid"));
        var inherited = await Read(device, op);
        check("Block list operator sees inherited global block red", inherited.GetProperty("rows").EnumerateArray().Any(r => r.GetProperty("domain").GetString() == "list.invalid" && r.GetProperty("effectiveBlocked").GetBoolean() && !r.GetProperty("configuredBlocked").GetBoolean() && r.GetProperty("reason").GetString() == "GlobalBlock"));
        check("Block list absent validated binding is explicitly unknown", inherited.GetProperty("rows").EnumerateArray().All(r => !r.GetProperty("decisionKnown").GetBoolean()));
        check("Block list observer read allowed", (await Read(device, observer)).GetProperty("rows").GetArrayLength() > 0);
        var stale = Body("stale.invalid", true);
        await Write(null, admin, "advance.invalid", false);
        using (var r = await send(PathFor(null), "POST", admin, stale, true)) check("Block list stale revision rejected without rule", !r.IsSuccessStatusCode && !policy.ReadFullPolicy().Policy.GlobalBlockedDomains.Contains("stale.invalid"));
        var current = policy.ReadFullPolicy();
        using (var r = await send(PathFor(null), "POST", admin, new { expectedInstanceId = "wrong", expectedRevision = current.Revision, domain = "wrong.invalid", enabled = true, delete = false }, true)) check("Block list wrong instance rejected", !r.IsSuccessStatusCode && !policy.ReadFullPolicy().Policy.GlobalBlockedDomains.Contains("wrong.invalid"));
        check("Block list delete is separate", await Write(null, admin, "list.invalid", false, true) == 200 && !(await Read(null, admin)).GetProperty("rows").EnumerateArray().Any(r => r.GetProperty("domain").GetString() == "list.invalid"));
        current = policy.ReadFullPolicy();
        check("Block list schema downgrade rejected", !policy.ReplaceFull(new(current.Revision, baseline.Policy, current.InstanceId)).Success);
        var legacy = DomainBlockList.Change(baseline.Policy with { Overrides = [new(device, "parent.invalid", DeviceDomainRuleState.Allow)], GlobalBlockedDomains = ["parent.invalid"] }, device, "parent.invalid", false, false);
        check("Block list disabling preserves legacy Allow semantics", PolicyDecision.Explain(legacy, device, "parent.invalid", DateTimeOffset.UtcNow).Winner.State == DeviceDomainRuleState.Allow);
        check("Block list suffix matching preserves parent block", PolicyDecision.Explain(legacy, other, "child.parent.invalid", DateTimeOffset.UtcNow).Winner.State == DeviceDomainRuleState.Block);
        current = policy.ReadFullPolicy(); policy.ReplaceFull(new(current.Revision, baseline.Policy with { SchemaVersion = 4, SavedDomains = [] }, current.InstanceId));
        await DnsEnforcement(directory, device, other, check);
    }

    static async Task DnsEnforcement(string directory, Guid device, Guid other, Action<string, bool> check)
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int upstreamPort = ((IPEndPoint)upstream.Client.LocalEndPoint!).Port;
        var upstreamTask = Task.Run(async () => { try { while (!stop.IsCancellationRequested) { var packet = await upstream.ReceiveAsync(stop.Token); DnsProtocol.TryParseQuestion(packet.Buffer, out var q); var response = DnsProtocol.BuildBlockedResponse(packet.Buffer, q, IPAddress.Parse("203.0.113.23")); await upstream.SendAsync(response, packet.RemoteEndPoint, stop.Token); } } catch (OperationCanceledException) { } });
        var cfg = new EngineConfig { DnsListenPort = 15356, EnableIpv6Dns = false, UpstreamDnsIpv4 = "127.0.0.1", UpstreamDnsPort = upstreamPort, PolicyFilePath = Path.Combine(directory, "device-enforcement.json") };
        var settings = EngineSettings.FromConfig(cfg); var rules = new RuleStore("isolated-device-proof");
        await using var dns = new DnsProxyServer(rules, settings);
        var policy = new PolicyApplicationService(rules, new PolicyPersistence(cfg.PolicyFilePath), dns.PolicyState); policy.InitializeForStartup();
        var read = policy.ReadFullPolicy();
        var full = new FullDnsPolicy(4, [], [new(device, "Fixture TV", "02:00:00:00:00:02", "fixture", "isolated"), new(other, "Control", "02:00:00:00:00:03", "fixture", "isolated")], [new(device, "harmless.invalid", DeviceDomainRuleState.Block)]) { SavedDomains = [] };
        check("Device proof no global block", policy.ReplaceFull(new(read.Revision, full, read.InstanceId)).Success && policy.ReadFullPolicy().Policy.GlobalBlockedDomains.Length == 0);
        var now = DateTimeOffset.UtcNow;
        dns.RequestProcessor.Bindings.Replace(new(0, [new("127.0.0.2", null, device, "isolated validated fixture", now.AddSeconds(-1), now.AddMinutes(2), true), new("127.0.0.3", null, other, "isolated validated fixture", now.AddSeconds(-1), now.AddMinutes(2), true)]));
        // Real processor and UDP upstream, controlled client contexts; no production listener.
        byte[] Query(ushort type) { var b = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 }; foreach (var label in "harmless.invalid".Split('.')) { b.Add((byte)label.Length); b.AddRange(Encoding.ASCII.GetBytes(label)); } b.AddRange(new byte[] { 0, 0, (byte)type, 0, 1 }); return b.ToArray(); }
        async Task<byte[]> Ask(string address, ushort type) => (await dns.RequestProcessor.ProcessAsync(Query(type), new(DnsTransport.Udp, address, 40000, DateTimeOffset.UtcNow, null), stop.Token))!;
        var blocked = await Ask("127.0.0.2", 1); var allowed = await Ask("127.0.0.3", 1); var unknown = await Ask("127.0.0.4", 1); var aaaa = await Ask("127.0.0.2", 28);
        check("DEVICE ENFORCEMENT PASS isolated A blocked only for validated device", blocked[7] == 1 && blocked.TakeLast(4).SequenceEqual(new byte[] { 0, 0, 0, 0 }) && allowed.TakeLast(4).SequenceEqual(new byte[] { 203, 0, 113, 23 }));
        check("Device proof unknown source does not inherit another device block", unknown.TakeLast(4).SequenceEqual(new byte[] { 203, 0, 113, 23 }));
        check("Device proof AAAA suppressed only by device decision", aaaa[6] == 0 && aaaa[7] == 0 && (aaaa[3] & 15) == 0);
        var evidence = dns.RequestProcessor.Observations.Read();
        check("DEVICE IDENTIFIED and DeviceOverride decision recorded", evidence.Any(e => e.DeviceId == device && e.IdentityState == "Validated" && e.Blocked && e.Reason == "DeviceOverride") && evidence.Any(e => e.DeviceId == other && !e.Blocked));
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(directory)!, "device-enforcement-evidence.json"), JsonSerializer.Serialize(new { environment = "ISOLATED processor + loopback UDP upstream; not Samsung live acceptance", globalBlocks = 0, targetA = "0.0.0.0", controlA = "203.0.113.23", unknownA = "203.0.113.23", targetAaaaAnswers = 0, decisions = evidence.Select(e => new { e.DeviceId, e.IdentityState, e.Domain, e.Blocked, e.Reason }) }, new JsonSerializerOptions { WriteIndented = true }));
        stop.Cancel(); await upstreamTask;
    }
}
