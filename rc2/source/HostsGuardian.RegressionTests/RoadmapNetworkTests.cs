using System.Collections.Immutable;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class RoadmapNetworkTests
{
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    private static byte[] Query()
    {
        var bytes = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in "fixture.invalid".Split('.')) { bytes.Add((byte)label.Length); bytes.AddRange(Encoding.ASCII.GetBytes(label)); }
        bytes.AddRange(new byte[] { 0, 0, 1, 0, 1 }); return bytes.ToArray();
    }
    public static async Task Run(Func<string, Func<Task>, Task> test, string directory)
    {
        await test("Roadmap live HTTPS schema3 delivery, bound identity, UDP/TCP enforcement and explainable overrides", async () =>
        {
            await using var f = new Phase5DTests.Fixture(directory);
            Check(f.Policy.Replace([]).Success, "Fixture baseline failed");
            await using var api = new ApiServer(f.Policy, f.Settings, f.Dns.RuntimeStatus,
                f.Dns.RequestProcessor.Bindings, f.Dns.RequestProcessor.Observations, f.Dns.RequestProcessor.Activity);
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var lifetime = new EngineLifetime(api, f.Dns).RunAsync(stop.Token);
            var upstream = Task.Run(async () =>
            {
                try
                {
                    while (!stop.IsCancellationRequested)
                    {
                        var packet = await f.Upstream.ReceiveAsync(stop.Token);
                        packet.Buffer[2] |= 0x80; await f.Upstream.SendAsync(packet.Buffer, packet.RemoteEndPoint, stop.Token);
                    }
                }
                catch (OperationCanceledException) { }
            });
            try
            {
                while (f.Dns.RuntimeStatus.GetSnapshot().RuntimeState != "Running") await Task.Delay(10, stop.Token);
                var device = Guid.NewGuid(); var group = Guid.NewGuid(); var profile = Guid.NewGuid();
                var policy = PolicyCanonicalization.Canonicalize(new FullDnsPolicy(3, ["fixture.invalid"],
                    [new(device, "Loopback fixture", null, "fixture", "explicit")], []) { Program = new(
                    [new(group, "Fixture group", [device], [new(Guid.NewGuid(), "fixture.invalid", null, DeviceDomainRuleState.Block)])], [],
                    [new(profile, "Fixture profile", true, true, false, [device], [], [new(Guid.NewGuid(), "fixture.invalid", null, DeviceDomainRuleState.Allow)])], []) });
                var client = new DnsEngineService();
                var baseline = await client.ReadFullPolicyAsync(f.ClientConfig);
                var applied = await client.ReplaceFullPolicyAsync(f.ClientConfig, new(baseline.Policy!.Revision, policy, baseline.Policy.InstanceId));
                Check(applied.Confirmed && applied.Readback?.Policy.SchemaVersion == 3, "Real schema3 canonical readback failed");
                var now = DateTimeOffset.UtcNow;
                Check(f.Dns.RequestProcessor.Bindings.Replace(new(0, [new("127.0.0.1", null, device, "Explicit isolated binding", now.AddSeconds(-1), now.AddHours(1), true)])), "Binding fixture failed");
                var explanation = await client.ExplainPolicyAsync(f.ClientConfig, "127.0.0.1", "fixture.invalid");
                Check(explanation.Connection.Ok && explanation.Explanation?.Winner?.Layer == PolicyLayer.ActiveProfile &&
                    explanation.Explanation.DecisionChain.Any(r => r.Layer == PolicyLayer.DeviceGroup && r.State == DeviceDomainRuleState.Block), "Real explanation lost overridden Block evidence");
                async Task<int> Udp()
                {
                    using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                    await socket.SendAsync(Query(), new IPEndPoint(IPAddress.Loopback, f.Config.DnsListenPort), stop.Token);
                    var answer = (await socket.ReceiveAsync(stop.Token)).Buffer; return (answer[6] << 8) | answer[7];
                }
                async Task<int> Tcp()
                {
                    using var socket = new TcpClient(); await socket.ConnectAsync(IPAddress.Loopback, f.Config.DnsListenPort, stop.Token);
                    var query = Query(); var stream = socket.GetStream();
                    await stream.WriteAsync(new byte[] { (byte)(query.Length >> 8), (byte)query.Length }, stop.Token); await stream.WriteAsync(query, stop.Token);
                    var size = new byte[2]; await stream.ReadExactlyAsync(size, stop.Token);
                    var answer = new byte[(size[0] << 8) | size[1]]; await stream.ReadExactlyAsync(answer, stop.Token); return (answer[6] << 8) | answer[7];
                }
                Check(await Udp() == 0 && await Tcp() == 0, "Profile Allow did not override group/global Block on both transports");
                var blocked = policy with { Overrides = [new(device, "fixture.invalid", DeviceDomainRuleState.Block)] };
                applied = await client.ReplaceFullPolicyAsync(f.ClientConfig, new(applied.Readback!.Revision, blocked, applied.Readback.InstanceId));
                Check(applied.Confirmed && await Udp() == 1 && await Tcp() == 1, "Device Block did not override active profile Allow");
                explanation = await client.ExplainPolicyAsync(f.ClientConfig, "127.0.0.1", "fixture.invalid");
                Check(explanation.Explanation?.Winner?.Layer == PolicyLayer.DeviceOverride && explanation.Explanation.DecisionChain.Length == 4, "Winning/overridden live evidence incomplete");
                var activity = await client.ReadActivityAsync(f.ClientConfig);
                Check(activity.Activity?.Buckets.Sum(b => b.Allowed) == 2 && activity.Activity.Buckets.Sum(b => b.Blocked) == 2, "Actual DNS activity did not match decisions");
                var deviceEvidence = f.Dns.RuntimeStatus.Diagnostics!.Snapshot().Devices!.Devices.Single();
                Check(deviceEvidence.DeviceId == device && deviceEvidence.Window.Received == 4 && deviceEvidence.Window.Allowed == 2 &&
                    deviceEvidence.Window.PolicyBlocked == 2, "Actual UDP/TCP results were attributed to the wrong device");
                var audit = await client.ReadPolicyAuditAsync(f.ClientConfig);
                Check(audit.Audit?.Entries.Count(r => r.Operation == "PolicyCommit") == 3, "Revision-aware real API audit lost commits");
                var bytes = File.ReadAllBytes(f.Config.PolicyFilePath);
                Check((await client.EnterSafeModeAsync(f.ClientConfig)).Confirmed && (await client.ExitSafeModeAsync(f.ClientConfig)).Confirmed &&
                    bytes.SequenceEqual(File.ReadAllBytes(f.Config.PolicyFilePath)), "Safe Mode altered richer persisted policy");
            }
            finally { stop.Cancel(); Check(await lifetime == 0, "Fixture Engine did not stop cleanly"); await upstream; }
        });
    }
}
