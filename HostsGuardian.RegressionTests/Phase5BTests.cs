using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class Phase5BTests
{
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static byte[] Query(string name, ushort type = 1)
    {
        var bytes = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.AddRange(new byte[] { 0, (byte)(type >> 8), (byte)type, 0, 1 });
        return bytes.ToArray();
    }

    private static byte[] Frame(byte[] payload)
    {
        var frame = new byte[payload.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame, checked((ushort)payload.Length));
        payload.CopyTo(frame, 2);
        return frame;
    }

    private static async Task<byte[]> ReadResponse(NetworkStream stream, CancellationToken token)
    {
        var prefix = new byte[2];
        await stream.ReadExactlyAsync(prefix, token);
        var length = BinaryPrimitives.ReadUInt16BigEndian(prefix);
        Check(length >= 12, "Invalid response frame length");
        var response = new byte[length];
        await stream.ReadExactlyAsync(response, token);
        return response;
    }

    private static int DualPort()
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            var tcp = new TcpListener(IPAddress.Loopback, 0);
            tcp.Start();
            var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
            try
            {
                using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
                return port;
            }
            catch (SocketException) { }
            finally { tcp.Stop(); }
        }
        throw new Exception("No isolated dual-transport port available");
    }

    private sealed class Fixture : IAsyncDisposable
    {
        public UdpClient Upstream { get; } = new(new IPEndPoint(IPAddress.Loopback, 0));
        public EngineSettings Settings { get; }
        public DnsProxyServer Udp { get; }
        public TcpDnsServer Tcp { get; }
        public ApiServer Api { get; }
        public PolicyApplicationService Policy { get; }
        public string PolicyPath { get; }

        public Fixture(string directory)
        {
            PolicyPath = Path.Combine(directory, "phase5b-" + Guid.NewGuid().ToString("N"), "policy.json");
            var config = new EngineConfig
            {
                DnsListenPort = DualPort(), ApiPort = DualPort(), ApiBindIp = "127.0.0.1",
                UpstreamDnsIpv4 = "127.0.0.1", UpstreamDnsPort = ((IPEndPoint)Upstream.Client.LocalEndPoint!).Port,
                UpstreamTimeoutMs = 1000, PolicyFilePath = PolicyPath,
                CredentialPath = Path.Combine(directory, "temporary-token"),
                CertificatePath = Path.Combine(directory, "temporary-cert.pem"),
                CertificateKeyPath = Path.Combine(directory, "temporary-key.pem")
            };
            Settings = EngineSettings.FromConfig(config);
            var rules = new RuleStore("phase5b-fixture");
            Udp = new DnsProxyServer(rules, Settings);
            Policy = new PolicyApplicationService(rules, new PolicyPersistence(PolicyPath), Udp.PolicyState);
            Check(Policy.Replace(new[] { "explicit.invalid" }).Success, "Isolated authorized fixture commit failed");
            Tcp = new TcpDnsServer(Settings, Udp.RequestProcessor, Udp.RuntimeStatus);
            Api = new ApiServer(Policy, Settings, Udp.RuntimeStatus);
        }

        public async Task StartAsync()
        {
            await Udp.StartAsync();
            await Tcp.StartAsync();
        }

        public async Task ReplyUpstream(byte[] query, CancellationToken token)
        {
            var received = await Upstream.ReceiveAsync(token);
            Check(received.Buffer.SequenceEqual(query), "Upstream received TCP prefix or changed DNS payload");
            Check(DnsProtocol.TryParseQuestion(query, out var question), "Malformed fixture query");
            var response = DnsProtocol.BuildBlockedResponse(query, question, IPAddress.Parse("192.0.2.42"));
            await Upstream.SendAsync(response, received.RemoteEndPoint, token);
        }

        public async ValueTask DisposeAsync()
        {
            try { await Tcp.StopAsync(); }
            finally
            {
                try { await Udp.StopAsync(); }
                finally { await Api.StopAsync(); Upstream.Dispose(); }
            }
        }
    }

    private static async Task<byte[]> Exchange(Fixture fixture, byte[] query, bool tcp, bool forwarded, CancellationToken token)
    {
        if (tcp)
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, token);
            var stream = client.GetStream();
            await stream.WriteAsync(Frame(query), token);
            if (forwarded) await fixture.ReplyUpstream(query, token);
            return await ReadResponse(stream, token);
        }
        using var udp = new UdpClient();
        await udp.SendAsync(query, new IPEndPoint(IPAddress.Loopback, fixture.Settings.DnsPort), token);
        if (forwarded) await fixture.ReplyUpstream(query, token);
        return (await udp.ReceiveAsync(token)).Buffer;
    }

    private static async Task CheckClosed(NetworkStream stream, CancellationToken token)
    {
        try { Check(await stream.ReadAsync(new byte[1], token) == 0, "Connection remained open or emitted invalid response"); }
        catch (IOException) { } // A peer reset is also a deterministic closed connection.
    }

    private sealed class FragmentedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public int Reads { get; private set; }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Reads++;
            return base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], cancellationToken);
        }
    }

    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest, string directory)
    {
        await asyncTest("Integrated real UDP and TCP source bindings apply device overrides and Safe Mode", async () =>
        {
            await using var fixture = new Fixture(directory);
            var id = Guid.NewGuid();
            var policy = new FullDnsPolicy(2, ["explicit.invalid"], [new(id, "Loopback fixture", null, "fixture", "explicit")],
                [new(id, "explicit.invalid", DeviceDomainRuleState.Allow), new(id, "allowed.invalid", DeviceDomainRuleState.Block)]);
            Check(fixture.Policy.ReplaceFull(new(fixture.Policy.ReadFullPolicy().Revision, policy)).Success, "Device policy commit failed");
            var now = DateTimeOffset.UtcNow;
            fixture.Udp.RequestProcessor.Bindings.Replace(new(0, [new("127.0.0.1", null, id, "fixture", now.AddSeconds(-1), now.AddMinutes(1), true)]));
            await fixture.StartAsync(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            foreach (var tcp in new[] { false, true })
            {
                Check((await Exchange(fixture, Query("explicit.invalid"), tcp, true, deadline.Token))[^4..].SequenceEqual(new byte[] {192,0,2,42}), "Source device Allow was ignored");
                Check((await Exchange(fixture, Query("allowed.invalid"), tcp, false, deadline.Token))[^4..].SequenceEqual(new byte[4]), "Source device Block was ignored");
                var observed = fixture.Udp.RequestProcessor.Observations.Read().Last();
                Check(observed.DeviceId == id && observed.Request.Transport == (tcp ? DnsTransport.Tcp : DnsTransport.Udp), "Actual source decision evidence missing");
            }
            var bytes = File.ReadAllBytes(fixture.PolicyPath); var revision = fixture.Policy.ReadFullPolicy().Revision;
            fixture.Policy.SetSafeMode(true);
            foreach (var tcp in new[] { false, true })
                Check((await Exchange(fixture, Query("allowed.invalid"), tcp, true, deadline.Token))[^4..].SequenceEqual(new byte[] {192,0,2,42}), "Safe Mode failed with device override");
            Check(File.ReadAllBytes(fixture.PolicyPath).SequenceEqual(bytes) && fixture.Policy.ReadFullPolicy().Revision == revision, "Bypass changed full policy");
        });
        await asyncTest("POST5E7 UDP and every TCP frame carry source context into the shared processor", async () =>
        {
            await using var fixture = new Fixture(directory);
            var observed = new System.Collections.Concurrent.ConcurrentQueue<DnsRequestContext>();
            fixture.Udp.RequestProcessor.ContextObserved = observed.Enqueue;
            await fixture.Udp.StartAsync(); await fixture.Tcp.StartAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var before = DateTimeOffset.UtcNow;
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var udpPeer = (IPEndPoint)udp.Client.LocalEndPoint!;
            await udp.SendAsync(Query("explicit.invalid"), new IPEndPoint(IPAddress.Loopback, fixture.Settings.DnsPort), deadline.Token);
            await udp.ReceiveAsync(deadline.Token);
            using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, deadline.Token);
            var tcpPeer = (IPEndPoint)tcp.Client.LocalEndPoint!;
            for (var i = 0; i < 2; i++)
            {
                await tcp.GetStream().WriteAsync(Frame(Query("explicit.invalid")), deadline.Token);
                await ReadResponse(tcp.GetStream(), deadline.Token);
            }
            var contexts = observed.ToArray();
            Check(contexts.Length == 3 && contexts[0].Transport == DnsTransport.Udp && contexts.Skip(1).All(c => c.Transport == DnsTransport.Tcp), "Transport missing");
            Check(contexts[0].SourcePort == udpPeer.Port && contexts.Skip(1).All(c => c.SourcePort == tcpPeer.Port), "Endpoint port missing");
            Check(contexts.All(c => c.SourceAddress == "127.0.0.1" && c.ReceivedAtUtc >= before && c.ReceivedAtUtc <= DateTimeOffset.UtcNow), "Source/timestamp missing");
        });

        await asyncTest("Phase5B framing reads fragmented prefix and payload exactly without leaking prefix", async () =>
        {
            var query = Query("explicit.invalid");
            using var input = new FragmentedStream(Frame(query));
            var decoded = await TcpDnsFraming.ReadAsync(input, CancellationToken.None);
            Check(decoded!.SequenceEqual(query) && input.Reads >= query.Length + 2, "Partial reads mishandled");
            Check(await TcpDnsFraming.ReadAsync(input, CancellationToken.None) == null, "Clean EOF misclassified");
            using var output = new MemoryStream();
            await TcpDnsFraming.WriteAsync(output, query, CancellationToken.None);
            Check(output.ToArray().SequenceEqual(Frame(query)), "Response framing not network order");
        });

        await asyncTest("Phase5B framing bounds zero short truncated and maximum length inputs", async () =>
        {
            foreach (var bytes in new[] { new byte[] { 0 }, new byte[] { 0, 0 }, new byte[] { 0, 1, 0 }, new byte[] { 0, 11 }, new byte[] { 0, 12, 1 }, new byte[] { 255, 255 } })
            {
                using var input = new FragmentedStream(bytes);
                try { await TcpDnsFraming.ReadAsync(input, CancellationToken.None); throw new Exception("Invalid/truncated frame accepted"); }
                catch (Exception exception) when (exception is EndOfStreamException or InvalidDataException) { }
            }
            var maximum = new byte[ushort.MaxValue];
            using var valid = new MemoryStream(Frame(maximum));
            Check((await TcpDnsFraming.ReadAsync(valid, CancellationToken.None))!.Length == ushort.MaxValue, "Unsigned maximum rejected");
            using var output = new MemoryStream();
            try { await TcpDnsFraming.WriteAsync(output, new byte[65536], CancellationToken.None); throw new Exception("Oversized response accepted"); }
            catch (InvalidDataException) { }
            Check(output.Length == 0, "Oversized output partially written");
        });

        await asyncTest("Phase5B TCP listener accepts split real stream writes and correctly framed A responses", async () =>
        {
            await using var fixture = new Fixture(directory); await fixture.StartAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, deadline.Token);
            var stream = client.GetStream(); var query = Query("explicit.invalid"); var frame = Frame(query);
            await stream.WriteAsync(frame.AsMemory(0, 1), deadline.Token);
            await Task.Delay(20, deadline.Token);
            for (var offset = 1; offset < frame.Length; offset++) await stream.WriteAsync(frame.AsMemory(offset, 1), deadline.Token);
            var response = await ReadResponse(stream, deadline.Token);
            Check(response[0] == query[0] && response[1] == query[1] && response[7] == 1 && response[^4..].SequenceEqual(new byte[4]), "Blocked A framing/answer wrong");
            Check(fixture.Udp.RuntimeStatus.GetSnapshot().UdpListening && fixture.Tcp.IsRunning, "Listener status false after startup");
        });

        await asyncTest("Phase5B TCP connection supports multiple sequential A and AAAA queries", async () =>
        {
            await using var fixture = new Fixture(directory); await fixture.StartAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, deadline.Token);
            var stream = client.GetStream();
            foreach (var type in new ushort[] { 1, 28, 1 })
            {
                var query = Query("child.explicit.invalid", type);
                await stream.WriteAsync(Frame(query), deadline.Token);
                var response = await ReadResponse(stream, deadline.Token);
                Check(response[7] == (type == 1 ? 1 : 0) && response[9] == 0 && response[11] == 0, "Sequential answer counts wrong");
                Check(response.Length == query.Length + (type == 1 ? 16 : 0), "AAAA omitted-section framing wrong");
            }
        });

        await asyncTest("Phase5B UDP and TCP agree on allowed blocked A AAAA and parent matching", async () =>
        {
            await using var fixture = new Fixture(directory); await fixture.StartAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            foreach (var sample in new[] { ("explicit.invalid", (ushort)1, false), ("explicit.invalid", (ushort)28, false), ("explicit.invalid", (ushort)15, false), ("explicit.invalid", (ushort)16, false), ("explicit.invalid", (ushort)65, false),
                ("child.explicit.invalid", (ushort)1, false), ("child.explicit.invalid", (ushort)28, false),
                ("allowed.invalid", (ushort)1, true), ("otherexplicit.invalid", (ushort)1, true) })
            {
                var query = Query(sample.Item1, sample.Item2);
                var udp = await Exchange(fixture, query, tcp: false, forwarded: sample.Item3, deadline.Token);
                var tcp = await Exchange(fixture, query, tcp: true, forwarded: sample.Item3, deadline.Token);
                Check(udp.SequenceEqual(tcp), "Transports disagree on filtering");
                if (sample.Item3) Check(tcp[^4..].SequenceEqual(new byte[] { 192, 0, 2, 42 }), "Allowed query not forwarded");
            }
        });

        await asyncTest("Phase5B Safe Mode bypass is identical and preserves committed file and revision", async () =>
        {
            await using var fixture = new Fixture(directory); await fixture.StartAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var before = File.ReadAllBytes(fixture.PolicyPath); var revision = fixture.Policy.State.GetSnapshot().Revision;
            var query = Query("explicit.invalid"); Check(fixture.Policy.SetSafeMode(true).Success, "Safe entry failed");
            var udp = await Exchange(fixture, query, false, true, deadline.Token);
            var tcp = await Exchange(fixture, query, true, true, deadline.Token);
            Check(udp.SequenceEqual(tcp) && tcp[^4..].SequenceEqual(new byte[] { 192, 0, 2, 42 }), "Safe Mode diverged");
            Check(before.SequenceEqual(File.ReadAllBytes(fixture.PolicyPath)) && fixture.Policy.State.GetSnapshot().Revision == revision, "TCP Safe Mode changed policy");
            fixture.Policy.SetSafeMode(false);
            Check((await Exchange(fixture, query, true, false, deadline.Token))[^4..].SequenceEqual(new byte[4]), "Safe exit failed over TCP");
        });

        await asyncTest("Phase5B malformed truncated and clean disconnects cannot fault listeners or mutate policy", async () =>
        {
            await using var fixture = new Fixture(directory); await fixture.StartAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var before = fixture.Policy.State.GetSnapshot(); var bytes = File.ReadAllBytes(fixture.PolicyPath);
            foreach (var input in new[] { Array.Empty<byte>(), new byte[] { 0 }, new byte[] { 0, 0 }, new byte[] { 0, 11 }, new byte[] { 0, 32, 1, 2 }, Encoding.ASCII.GetBytes("POST /safe-mode/enter") })
            {
                using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, deadline.Token);
                var stream = client.GetStream(); if (input.Length > 0) await stream.WriteAsync(input, deadline.Token);
                client.Client.Shutdown(SocketShutdown.Send);
                await CheckClosed(stream, deadline.Token);
            }
            Check(fixture.Tcp.IsRunning && fixture.Udp.IsRunning && fixture.Policy.State.GetSnapshot() == before && bytes.SequenceEqual(File.ReadAllBytes(fixture.PolicyPath)), "Malformed TCP changed Engine state");
            Check((await Exchange(fixture, Query("explicit.invalid"), true, false, deadline.Token))[7] == 1, "Listener failed after bad input");
        });

        await asyncTest("Phase5B TCP stop awaits blocked prefix and payload reads and permits restart", async () =>
        {
            await using var fixture = new Fixture(directory); await fixture.StartAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var first = new TcpClient(); using var second = new TcpClient();
            await first.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, deadline.Token);
            await second.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, deadline.Token);
            await first.GetStream().WriteAsync(new byte[] { 0 }, deadline.Token);
            await second.GetStream().WriteAsync(new byte[] { 0, 40, 1, 2 }, deadline.Token);
            await fixture.Tcp.StopAsync().WaitAsync(deadline.Token);
            await CheckClosed(first.GetStream(), deadline.Token); await CheckClosed(second.GetStream(), deadline.Token);
            Check(!fixture.Tcp.IsRunning && fixture.Udp.IsRunning, "TCP stop interfered with UDP");
            await fixture.Tcp.StartAsync();
            Check((await Exchange(fixture, Query("explicit.invalid"), true, false, deadline.Token))[7] == 1, "TCP restart failed");
        });

        await asyncTest("Phase5B TCP connection cap rejects excess peers without unlimited tasks", async () =>
        {
            await using var fixture = new Fixture(directory); await fixture.StartAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var clients = new List<TcpClient>();
            try
            {
                for (var index = 0; index < TcpDnsServer.MaximumConnections; index++)
                {
                    var client = new TcpClient(); clients.Add(client);
                    await client.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, deadline.Token);
                    await client.GetStream().WriteAsync(new byte[] { 0 }, deadline.Token);
                }
                using var extra = new TcpClient(); await extra.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, deadline.Token);
                await CheckClosed(extra.GetStream(), deadline.Token);
                Check(fixture.Tcp.IsRunning && fixture.Policy.State.GetSnapshot().Revision == 1, "Connection cap faulted/mutated Engine");
            }
            finally { foreach (var client in clients) client.Dispose(); }
        });

        await asyncTest("Phase5B Engine shutdown awaits active TCP connections and reports listeners stopped", async () =>
        {
            await using var fixture = new Fixture(directory);
            using var cancellation = new CancellationTokenSource(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var lifetime = new EngineLifetime(fixture.Api, fixture.Udp).RunAsync(cancellation.Token);
            try
            {
                while (fixture.Api.GetDnsStatus().RuntimeState != "Running") await Task.Delay(10, deadline.Token);
                using var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, fixture.Settings.DnsPort, deadline.Token);
                await client.GetStream().WriteAsync(new byte[] { 0, 40, 1 }, deadline.Token);
                cancellation.Cancel();
                Check(await lifetime.WaitAsync(deadline.Token) == 0, "Shutdown returned failure");
                await CheckClosed(client.GetStream(), deadline.Token);
                var status = fixture.Api.GetDnsStatus();
                Check(status.RuntimeState == "Stopped" && !status.UdpListening && !status.TcpListening && !status.ManagementListening && status.TcpImplemented, "Stopped status false");
                var rebound = new TcpListener(IPAddress.Loopback, fixture.Settings.DnsPort); rebound.Start(); rebound.Stop();
            }
            finally { cancellation.Cancel(); await lifetime.WaitAsync(deadline.Token); }
        });

        await asyncTest("Phase5B TCP startup conflict rolls back UDP and management without false availability", async () =>
        {
            await using var fixture = new Fixture(directory);
            var occupied = new TcpListener(IPAddress.Any, fixture.Settings.DnsPort); occupied.Start();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                Check(await new EngineLifetime(fixture.Api, fixture.Udp).RunAsync(deadline.Token) == 1, "TCP conflict reported success");
                var status = fixture.Api.GetDnsStatus();
                Check(status.RuntimeState == "Faulted" && !status.UdpListening && !status.TcpListening && !status.ManagementListening, "Partial Engine left running");
                using var rebound = new UdpClient(fixture.Settings.DnsPort);
                var apiRebound = new TcpListener(IPAddress.Loopback, fixture.Settings.ApiPort); apiRebound.Start(); apiRebound.Stop();
            }
            finally { occupied.Stop(); }
        });

        await asyncTest("Phase5B authenticated connection checks report both transports without mutation", async () =>
        {
            await using var fixture = new Fixture(directory); using var cancellation = new CancellationTokenSource();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var lifetime = new EngineLifetime(fixture.Api, fixture.Udp).RunAsync(cancellation.Token);
            try
            {
                while (fixture.Api.GetDnsStatus().RuntimeState != "Running") await Task.Delay(10, deadline.Token);
                using var certificate = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(File.ReadAllText(fixture.Settings.CertificatePath));
                var before = fixture.Policy.State.GetSnapshot(); var bytes = File.ReadAllBytes(fixture.PolicyPath);
                var config = new DnsEngineConfig
                {
                    Address = "127.0.0.1", ManagementPort = fixture.Settings.ApiPort,
                    ApiToken = File.ReadAllText(fixture.Settings.CredentialPath), TrustedCertificate = Convert.ToBase64String(certificate.RawData)
                };
                var result = await new DnsEngineService().TestConnectionAsync(config, deadline.Token);
                Check(result.Ok && result.Transport!.UdpListening && result.Transport.TcpListening && result.Transport.TcpImplemented, "Client transport report incorrect");
                Check(fixture.Policy.State.GetSnapshot() == before && bytes.SequenceEqual(File.ReadAllBytes(fixture.PolicyPath)), "Read-only management test changed policy");
            }
            finally { cancellation.Cancel(); await lifetime.WaitAsync(deadline.Token); }
        });
    }
}
