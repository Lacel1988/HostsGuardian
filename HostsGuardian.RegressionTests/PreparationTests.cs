using System.Net;
using System.Net.Sockets;
using System.Text;
using HostsGuardian.DnsEngine;

internal static class PreparationTests
{
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static int UnusedUdpPort()
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
    }

    private static int UnusedApiPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static EngineConfig FixtureConfig(string directory) => new()
    {
        DnsListenPort = UnusedUdpPort(),
        ApiBindIp = "127.0.0.1",
        ApiPort = UnusedApiPort(),
        UpstreamDnsIpv4 = "127.0.0.1",
        UpstreamDnsPort = UnusedUdpPort(),
        UpstreamTimeoutMs = 100, UpstreamRetryCount = 0,
        PolicyFilePath = Path.Combine(directory, Guid.NewGuid().ToString("N"), "policy.json"),
        CredentialPath = Path.Combine(directory, "temporary-token"),
        CertificatePath = Path.Combine(directory, "temporary-cert.pem"),
        CertificateKeyPath = Path.Combine(directory, "temporary-key.pem")
    };

    private static byte[] Query(string domain, ushort type)
    {
        var bytes = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in domain.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.AddRange(new byte[] { 0, (byte)(type >> 8), (byte)type, 0, 1 });
        return bytes.ToArray();
    }

    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest, string directory)
    {
        test("Engine validated settings are stable and invalid configuration fails early", () =>
        {
            var config = FixtureConfig(directory);
            var settings = EngineSettings.FromConfig(config);
            config.DnsListenPort = 53;
            config.UpstreamDnsIpv4 = "1.1.1.1";
            Check(settings.DnsPort != 53 && settings.UpstreamAddress.Equals(IPAddress.Loopback), "Mutable configuration leaked into settings");
            foreach (var invalid in new EngineConfig[]
            {
                new() { DnsListenPort = 0 }, new() { ApiPort = 65536 }, new() { UpstreamDnsPort = -1 },
                new() { UpstreamDnsIpv4 = "invalid" }, new() { BlockedIpv4 = "::1" },
                new() { ApiBindIp = "invalid" }, new() { UpstreamTimeoutMs = -2 }
            })
            {
                try { EngineSettings.FromConfig(invalid); throw new Exception("Invalid configuration accepted"); }
                catch (InvalidOperationException) { }
            }
        });

        test("policy application results are durable and invalid updates remain atomic", () =>
        {
            var rules = new RuleStore("preparation");
            var policy = new PolicyApplicationService(rules, new PolicyPersistence(FixtureConfig(directory).PolicyFilePath));
            Check(policy.GetBlockedDomains().Length == 0, "Policy generated on construction");
            var committed = policy.Replace(new[] { "EXPLICIT.invalid", "explicit.invalid" });
            Check(committed.Success && committed.Count == 1 && committed.Revision == 1, "Normalization/commit changed");
            try { policy.Add(new[] { "new.invalid", "bad name" }); throw new Exception("Invalid policy accepted"); }
            catch (ArgumentException) { }
            Check(policy.GetBlockedDomains().SequenceEqual(new[] { "explicit.invalid" }), "Partial mutation");
            Check(policy.Remove("explicit.invalid").Removed && policy.GetBlockedDomains().Length == 0, "Remove failed");
        });

        await asyncTest("upstream forwarding owns requests and distinguishes all four outcomes", async () =>
        {
            using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var config = FixtureConfig(directory);
            config.UpstreamDnsPort = ((IPEndPoint)upstream.Client.LocalEndPoint!).Port;
            var forwarder = new UpstreamDnsForwarder(EngineSettings.FromConfig(config));
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var request = Query("allowed.invalid", 1);
            var exchange = forwarder.ForwardAsync(request, deadline.Token);
            var received = await upstream.ReceiveAsync(deadline.Token);
            var reply = (byte[])received.Buffer.Clone(); reply[2] |= 0x80; reply[3] |= 0x80;
            await upstream.SendAsync(reply, received.RemoteEndPoint, deadline.Token);
            var response = await exchange;
            Check(response.Outcome == UpstreamOutcome.Response && response.Response!.SequenceEqual(reply), "Forwarded bytes changed");
            var timeout = await forwarder.ForwardAsync(request, deadline.Token);
            Check(timeout.Outcome == UpstreamOutcome.Timeout, "Timeout misclassified");
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            Check((await forwarder.ForwardAsync(request, cancelled.Token)).Outcome == UpstreamOutcome.Cancelled, "Cancellation misclassified");
            Check((await forwarder.ForwardAsync(new byte[70000], deadline.Token)).Outcome == UpstreamOutcome.TransportFailure, "Transport failure misclassified");
        });

        await asyncTest("request processor preserves blocked bytes and supported forwarding behavior", async () =>
        {
            using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var config = FixtureConfig(directory);
            config.UpstreamDnsPort = ((IPEndPoint)upstream.Client.LocalEndPoint!).Port;
            var settings = EngineSettings.FromConfig(config);
            var rules = new RuleStore("processor"); rules.SetBlockedDomains(new[] { "explicit.invalid" });
            var policy = new PolicyApplicationService(rules, new PolicyPersistence(settings.PolicyFilePath));
            Check(policy.Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
            var processor = new DnsRequestProcessor(rules, settings, new UpstreamDnsForwarder(settings), policy.State);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            foreach (var type in new ushort[] { 1, 28 })
            {
                var request = Query("child.explicit.invalid", type);
                Check(DnsProtocol.TryParseQuestion(request, out var question), "Fixture malformed");
                var expected = DnsProtocol.BuildBlockedResponse(request, question, settings.BlockedAddress);
                Check((await processor.ProcessAsync(request, deadline.Token))!.SequenceEqual(expected), "Blocked response changed");
            }
            foreach (var request in new[] { Query("allowed.invalid", 1), Query("allowed.invalid", 15) })
            {
                var processing = processor.ProcessAsync(request, deadline.Token);
                var received = await upstream.ReceiveAsync(deadline.Token);
                Check(received.Buffer.SequenceEqual(request), "Forwarded request changed");
                var reply = (byte[])received.Buffer.Clone(); reply[2] |= 0x80; reply[3] |= 0x80;
                await upstream.SendAsync(reply, received.RemoteEndPoint, deadline.Token);
                Check((await processing)!.SequenceEqual(reply), "Forwarded response changed");
            }
            Check(await processor.ProcessAsync(Encoding.ASCII.GetBytes("unparsed"), deadline.Token) == null, "Malformed query was forwarded");
            Check(rules.GetBlockedDomains().SequenceEqual(new[] { "explicit.invalid" }), "Processing changed policy");
        });

        await asyncTest("UDP stop awaits pending upstream work and supports clean restart", async () =>
        {
            using var upstream = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var config = FixtureConfig(directory);
            config.UpstreamDnsPort = ((IPEndPoint)upstream.Client.LocalEndPoint!).Port;
            config.UpstreamTimeoutMs = 10000;
            await using var dns = new DnsProxyServer(new RuleStore("restart"), config);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await dns.StartAsync();
            using var client = new UdpClient();
            await client.SendAsync(Query("allowed.invalid", 1), new IPEndPoint(IPAddress.Loopback, config.DnsListenPort), deadline.Token);
            await upstream.ReceiveAsync(deadline.Token);
            await dns.StopAsync().WaitAsync(deadline.Token);
            Check(!dns.IsRunning, "Stop reported running");
            await dns.StartAsync();
            Check(dns.IsRunning && dns.RuntimeStatus.GetSnapshot().TcpImplemented && !dns.RuntimeStatus.GetSnapshot().TcpListening, "Restart/status failed");
            await dns.StopAsync().WaitAsync(deadline.Token);
            using var rebound = new UdpClient(config.DnsListenPort);
        });

        await asyncTest("lifetime startup failure rolls back HTTPS and returns failure", async () =>
        {
            using var occupied = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            var config = FixtureConfig(directory);
            config.DnsListenPort = ((IPEndPoint)occupied.Client.LocalEndPoint!).Port;
            var settings = EngineSettings.FromConfig(config);
            var rules = new RuleStore("failure");
            await using var dns = new DnsProxyServer(rules, settings);
            await using var api = new ApiServer(new PolicyApplicationService(rules, new PolicyPersistence(settings.PolicyFilePath), dns.PolicyState), settings, dns.RuntimeStatus);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var result = await new EngineLifetime(api, dns).RunAsync(deadline.Token);
            Check(result == 1 && !api.IsRunning && !dns.IsRunning, "Partial startup left components active");
            var rebound = new TcpListener(IPAddress.Loopback, config.ApiPort);
            rebound.Start(); rebound.Stop();
            Check(rules.GetBlockedDomains().Length == 0, "Startup generated policy");
        });

        await asyncTest("headless lifetime cancellation stops both listeners without policy mutation", async () =>
        {
            var config = FixtureConfig(directory);
            var settings = EngineSettings.FromConfig(config);
            var rules = new RuleStore("cancel"); rules.SetBlockedDomains(new[] { "explicit.invalid" });
            await using var dns = new DnsProxyServer(rules, settings);
            var policy = new PolicyApplicationService(rules, new PolicyPersistence(settings.PolicyFilePath), dns.PolicyState);
            Check(policy.Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
            await using var api = new ApiServer(policy, settings, dns.RuntimeStatus);
            using var cancellation = new CancellationTokenSource();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var lifetime = new EngineLifetime(api, dns).RunAsync(cancellation.Token);
            while (!dns.IsRunning) await Task.Delay(10, deadline.Token);
            cancellation.Cancel();
            Check(await lifetime.WaitAsync(deadline.Token) == 0, "Cancellation returned failure");
            Check(!api.IsRunning && !dns.IsRunning && rules.GetBlockedDomains().SequenceEqual(new[] { "explicit.invalid" }), "Shutdown changed state/policy");
        });
    }
}
