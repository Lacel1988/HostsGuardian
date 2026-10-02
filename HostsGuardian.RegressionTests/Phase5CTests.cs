using System.Net;
using System.Net.Sockets;
using System.Text;
using HostsGuardian.DnsEngine;

internal static class Phase5CTests
{
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static byte[] Query(string name = "allowed.invalid")
    {
        var bytes = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.AddRange(new byte[] { 0, 0, 1, 0, 1 });
        return bytes.ToArray();
    }

    private static byte[] Reply(byte[] query)
    {
        var response = (byte[])query.Clone();
        response[2] |= 0x80;
        response[3] |= 0x80;
        return response;
    }

    private static int FreePort()
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
    }

    private static int Port(UdpClient socket) => ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
    private static CancellationTokenSource Deadline() => new(TimeSpan.FromSeconds(10));

    private sealed class Fixture : IAsyncDisposable
    {
        public UdpClient Primary { get; } = new(new IPEndPoint(IPAddress.Loopback, 0));
        public UdpClient Fallback { get; } = new(new IPEndPoint(IPAddress.Loopback, 0));
        public EngineConfig Config { get; }
        public EngineSettings Settings => EngineSettings.FromConfig(Config);
        public Fixture(string directory, bool fallback = false)
        {
            Config = new EngineConfig
            {
                DnsListenPort = FreePort(), UpstreamDnsIpv4 = "127.0.0.1", UpstreamDnsPort = Port(Primary),
                UpstreamTimeoutMs = 150, UpstreamRetryCount = 1, MaxConcurrentUdpRequests = 2,
                FallbackDnsIpv4 = fallback ? "127.0.0.1" : "", FallbackDnsPort = Port(Fallback),
                PolicyFilePath = Path.Combine(directory, "phase5c-" + Guid.NewGuid().ToString("N"), "policy.json")
            };
        }
        public ValueTask DisposeAsync() { Primary.Dispose(); Fallback.Dispose(); return ValueTask.CompletedTask; }
    }

    private static async Task ReplyNext(UdpClient upstream, CancellationToken token)
    {
        var received = await upstream.ReceiveAsync(token);
        await upstream.SendAsync(Reply(received.Buffer), received.RemoteEndPoint, token);
    }

    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest, string directory)
    {
        test("Phase5C configuration rejects unbounded deadlines retries concurrency and invalid fallback", () =>
        {
            foreach (var config in new EngineConfig[]
            {
                new() { UpstreamTimeoutMs = -1 }, new() { UpstreamTimeoutMs = 0 }, new() { UpstreamTimeoutMs = 10001 },
                new() { UpstreamRetryCount = -1 }, new() { UpstreamRetryCount = 3 },
                new() { MaxConcurrentUdpRequests = 0 }, new() { MaxConcurrentUdpRequests = 65 },
                new() { FallbackDnsIpv4 = "invalid" }, new() { FallbackDnsPort = 0 },
                new() { FallbackDnsIpv4 = "1.1.1.1" }
            })
            {
                try { EngineSettings.FromConfig(config); throw new Exception("Invalid setting accepted"); }
                catch (InvalidOperationException) { }
            }
            var settings = EngineSettings.FromConfig(new EngineConfig());
            Check(settings.FallbackEndpoint == null && settings.MaxConcurrentUdpRequests == 16, "Unsafe defaults");
        });

        await asyncTest("Phase5C healthy primary succeeds once without fallback and records passive status", async () =>
        {
            await using var f = new Fixture(directory, true);
            using var deadline = Deadline();
            var state = new UpstreamRuntimeState();
            var forwarder = new UpstreamDnsForwarder(f.Settings, state);
            var exchange = forwarder.ForwardAsync(Query(), deadline.Token);
            await ReplyNext(f.Primary, deadline.Token);
            var result = await exchange;
            Check(result.Outcome == UpstreamOutcome.Response && result.Attempts == 1 && !result.UsedFallback, "Healthy primary fell back");
            Check(f.Fallback.Available == 0 && state.GetSnapshot().LastSuccessUtc != null, "False fallback/status");
            Check(result.Response!.SequenceEqual(Reply(Query())), "Valid response bytes changed");
        });

        test("Phase5C question correlation preserves wire octets boundaries and ASCII case semantics", () =>
        {
            var query = Query(); var response = Reply(query);
            response[13] = (byte)'A';
            Check(DnsProtocol.IsMatchingResponse(query, response), "ASCII case rejected");
            query[13] = 0xfe; response = Reply(query); response[13] = 0xff;
            Check(!DnsProtocol.IsMatchingResponse(query, response), "Lossy ASCII name comparison accepted");
            var labels = Query("a.b");
            var singleLabel = new byte[] { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 3, (byte)'a', (byte)'.', (byte)'b', 0, 0, 1, 0, 1 };
            Check(!DnsProtocol.IsMatchingResponse(labels, singleLabel), "Label boundaries lost");
            Check(DnsProtocol.TryParseQuestion(query, out var question), "Fixture question malformed");
            var failure = DnsProtocol.BuildServerFailure(query, question);
            Check(failure.AsSpan(12).SequenceEqual(query.AsSpan(12)) && failure[0] == query[0] && (failure[3] & 15) == 2, "Failure changed question octets");
        });

        await asyncTest("Phase5C UDP and sequential TCP failures return identical SERVFAIL through shared processor", async () =>
        {
            await using var f = new Fixture(directory); f.Config.UpstreamRetryCount = 0;
            using var deadline = Deadline();
            await using var dns = new DnsProxyServer(new RuleStore("failure-contract"), f.Settings);
            await using var tcp = new TcpDnsServer(f.Settings, dns.RequestProcessor, dns.RuntimeStatus);
            await dns.StartAsync(); await tcp.StartAsync();
            using var udpClient = new UdpClient();
            await udpClient.SendAsync(Query(), new IPEndPoint(IPAddress.Loopback, f.Settings.DnsPort), deadline.Token);
            var udpResponse = (await udpClient.ReceiveAsync(deadline.Token)).Buffer;
            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, f.Settings.DnsPort, deadline.Token);
            var stream = tcpClient.GetStream();
            for (var index = 0; index < 2; index++)
            {
                await TcpDnsFraming.WriteAsync(stream, Query(), deadline.Token);
                var tcpResponse = await TcpDnsFraming.ReadAsync(stream, deadline.Token);
                Check(tcpResponse != null && tcpResponse.SequenceEqual(udpResponse) && (tcpResponse[3] & 15) == 2, "Transport failure contract diverged");
            }
            await tcp.StopAsync(); await dns.StopAsync();
            Check(!dns.RuntimeStatus.GetSnapshot().TcpListening && !dns.IsRunning && dns.ActiveRequestCount == 0, "Failure leaked listeners/tasks");
        });

        await asyncTest("Phase5C primary timeout exhausts exactly configured attempts without invented fallback", async () =>
        {
            await using var f = new Fixture(directory);
            using var deadline = Deadline();
            var exchange = new UpstreamDnsForwarder(f.Settings).ForwardAsync(Query(), deadline.Token);
            await f.Primary.ReceiveAsync(deadline.Token);
            await f.Primary.ReceiveAsync(deadline.Token);
            var result = await exchange;
            Check(result.Outcome == UpstreamOutcome.Exhausted && result.LastFailure == UpstreamOutcome.Timeout && result.Attempts == 2 && !result.UsedFallback, "Timeout budget changed");
            Check(f.Primary.Available == 0 && f.Fallback.Available == 0, "Extra attempt or fallback");
        });

        await asyncTest("Phase5C transient transport failure retries then configured fallback succeeds", async () =>
        {
            await using var f = new Fixture(directory, true);
            using var deadline = Deadline();
            var endpoints = new List<int>();
            var forwarder = new UpstreamDnsForwarder(f.Settings, null, (query, endpoint, token) =>
            {
                endpoints.Add(endpoint.Port);
                return Task.FromResult(endpoint.Port == Port(f.Primary)
                    ? new UpstreamResult(UpstreamOutcome.TransportFailure)
                    : new UpstreamResult(UpstreamOutcome.Response, Reply(query)));
            });
            var result = await forwarder.ForwardAsync(Query(), deadline.Token);
            Check(result.Outcome == UpstreamOutcome.Response && result.Attempts == 3 && result.UsedFallback, "Transport retry/fallback incorrect");
            Check(endpoints.SequenceEqual(new[] { Port(f.Primary), Port(f.Primary), Port(f.Fallback) }), "Unexpected attempt ordering");
        });

        await asyncTest("Phase5C oversized UDP request is terminal transport failure without pointless retry", async () =>
        {
            await using var f = new Fixture(directory, true);
            using var deadline = Deadline();
            var query = new byte[70000]; Query().CopyTo(query, 0);
            var result = await new UpstreamDnsForwarder(f.Settings).ForwardAsync(query, deadline.Token);
            Check(result.Outcome == UpstreamOutcome.TransportFailure && result.Attempts == 1 && !result.UsedFallback, "Permanent transport failure retried");
        });

        await asyncTest("Phase5C real primary timeout activates only configured fallback and records use", async () =>
        {
            await using var f = new Fixture(directory, true);
            using var deadline = Deadline();
            var state = new UpstreamRuntimeState();
            var exchange = new UpstreamDnsForwarder(f.Settings, state).ForwardAsync(Query(), deadline.Token);
            await f.Primary.ReceiveAsync(deadline.Token); await f.Primary.ReceiveAsync(deadline.Token);
            await ReplyNext(f.Fallback, deadline.Token);
            var result = await exchange;
            Check(result.Outcome == UpstreamOutcome.Response && result.Attempts == 3 && result.UsedFallback, "Fallback did not recover");
            Check(state.GetSnapshot().LastFallbackUseUtc != null && state.GetSnapshot().LastRequestUsedFallback, "Fallback observation missing");
        });

        await asyncTest("Phase5C primary and fallback exhaustion remains bounded", async () =>
        {
            await using var f = new Fixture(directory, true);
            using var deadline = Deadline();
            f.Config.UpstreamRetryCount = 2;
            var exchange = new UpstreamDnsForwarder(f.Settings).ForwardAsync(Query(), deadline.Token);
            for (var attempt = 0; attempt < 3; attempt++) await f.Primary.ReceiveAsync(deadline.Token);
            for (var attempt = 0; attempt < 3; attempt++) await f.Fallback.ReceiveAsync(deadline.Token);
            var result = await exchange;
            Check(result.Outcome == UpstreamOutcome.Exhausted && result.Attempts == 6 && result.UsedFallback, "Total bound exceeded");
            Check(f.Primary.Available == 0 && f.Fallback.Available == 0, "Unexpected seventh attempt");
        });

        await asyncTest("Phase5C shutdown cancellation stops retries and leaves upstream observations unchanged", async () =>
        {
            await using var f = new Fixture(directory, true);
            using var deadline = Deadline(); using var cancel = new CancellationTokenSource();
            f.Config.UpstreamTimeoutMs = 10000;
            var state = new UpstreamRuntimeState(); var before = state.GetSnapshot();
            var forwarder = new UpstreamDnsForwarder(f.Settings, state);
            var exchange = forwarder.ForwardAsync(Query(), cancel.Token);
            await f.Primary.ReceiveAsync(deadline.Token); cancel.Cancel();
            var result = await exchange.WaitAsync(deadline.Token);
            Check(result.Outcome == UpstreamOutcome.Cancelled && result.Attempts == 1 && f.Fallback.Available == 0 && state.GetSnapshot() == before, "Cancellation retried or claimed failure");
            Check((await forwarder.ForwardAsync(Query(), cancel.Token)).Attempts == 0, "Already cancelled query sent");
        });

        foreach (var category in new[] { "wrong ID", "wrong sender", "malformed", "wrong question", "query instead of response", "invalid RR length" })
        {
            await asyncTest("Phase5C rejects " + category + " before accepting correlated response", async () =>
            {
                await using var f = new Fixture(directory);
                f.Config.UpstreamTimeoutMs = 1000;
                using var deadline = Deadline();
                var exchange = new UpstreamDnsForwarder(f.Settings).ForwardAsync(Query(), deadline.Token);
                var received = await f.Primary.ReceiveAsync(deadline.Token);
                var invalid = Reply(received.Buffer);
                if (category == "wrong ID") invalid[0] ^= 1;
                if (category == "malformed") invalid = new byte[5];
                if (category == "wrong question") invalid[13] ^= 1;
                if (category == "query instead of response") invalid[2] &= 0x7f;
                if (category == "invalid RR length") invalid[7] = 1;
                if (category == "wrong sender")
                    await f.Fallback.SendAsync(invalid, received.RemoteEndPoint, deadline.Token);
                else await f.Primary.SendAsync(invalid, received.RemoteEndPoint, deadline.Token);
                var valid = Reply(received.Buffer);
                await f.Primary.SendAsync(valid, received.RemoteEndPoint, deadline.Token);
                var result = await exchange;
                Check(result.Outcome == UpstreamOutcome.Response && result.Response!.SequenceEqual(valid) && result.Attempts == 1, "Unrelated response accepted or deadline reset");
            });
        }

        await asyncTest("Phase5C malformed-only response yields typed invalid failure within original deadline", async () =>
        {
            await using var f = new Fixture(directory); f.Config.UpstreamRetryCount = 0;
            using var deadline = Deadline();
            var exchange = new UpstreamDnsForwarder(f.Settings).ForwardAsync(Query(), deadline.Token);
            var received = await f.Primary.ReceiveAsync(deadline.Token);
            await f.Primary.SendAsync(new byte[3], received.RemoteEndPoint, deadline.Token);
            var result = await exchange;
            Check(result.Outcome == UpstreamOutcome.InvalidResponse && result.Response == null && result.Attempts == 1, "Invalid packet returned");
        });

        await asyncTest("Phase5C truncation is explicit terminal failure and produces SERVFAIL without policy mutation", async () =>
        {
            await using var f = new Fixture(directory, true);
            using var deadline = Deadline();
            var rules = new RuleStore("truncation");
            var policy = new PolicyApplicationService(rules, new PolicyPersistence(f.Settings.PolicyFilePath));
            Check(policy.Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
            var before = policy.ReadPolicy(); var bytes = File.ReadAllBytes(f.Settings.PolicyFilePath);
            var processor = new DnsRequestProcessor(rules, f.Settings, new UpstreamDnsForwarder(f.Settings), policy.State);
            var exchange = processor.ProcessAsync(Query(), deadline.Token);
            var received = await f.Primary.ReceiveAsync(deadline.Token);
            var truncated = Reply(received.Buffer); truncated[2] |= 2;
            await f.Primary.SendAsync(truncated, received.RemoteEndPoint, deadline.Token);
            var failure = await exchange;
            Check(failure != null && (failure[3] & 15) == 2 && (failure[2] & 2) == 0 && f.Fallback.Available == 0, "TC treated as complete or retried over UDP");
            Check(policy.ReadPolicy().Revision == before.Revision && File.ReadAllBytes(f.Settings.PolicyFilePath).SequenceEqual(bytes), "Failure changed policy");
        });

        await asyncTest("Phase5C upstream SERVFAIL is retried but NXDOMAIN remains a valid terminal answer", async () =>
        {
            await using var f = new Fixture(directory);
            using var deadline = Deadline();
            var exchange = new UpstreamDnsForwarder(f.Settings).ForwardAsync(Query(), deadline.Token);
            var first = await f.Primary.ReceiveAsync(deadline.Token);
            var failure = Reply(first.Buffer); failure[3] |= 2;
            await f.Primary.SendAsync(failure, first.RemoteEndPoint, deadline.Token);
            var second = await f.Primary.ReceiveAsync(deadline.Token);
            var negative = Reply(second.Buffer); negative[3] |= 3;
            await f.Primary.SendAsync(negative, second.RemoteEndPoint, deadline.Token);
            var result = await exchange;
            Check(result.Outcome == UpstreamOutcome.Response && result.Attempts == 2 && result.Response!.SequenceEqual(negative), "Negative answer incorrectly retried");
        });

        await asyncTest("Phase5C slow allowed UDP query cannot serialize fast local blocked response", async () =>
        {
            await using var f = new Fixture(directory); f.Config.UpstreamTimeoutMs = 10000;
            using var deadline = Deadline();
            var rules = new RuleStore("fast-block"); await using var dns = new DnsProxyServer(rules, f.Settings);
            var policy = new PolicyApplicationService(rules, new PolicyPersistence(f.Settings.PolicyFilePath), dns.PolicyState);
            Check(policy.Replace(new[] { "explicit.invalid" }).Success, "Fixture commit failed");
            await dns.StartAsync(); using var slow = new UdpClient(); using var blocked = new UdpClient();
            var endpoint = new IPEndPoint(IPAddress.Loopback, f.Settings.DnsPort);
            await slow.SendAsync(Query(), endpoint, deadline.Token); await f.Primary.ReceiveAsync(deadline.Token);
            await blocked.SendAsync(Query("explicit.invalid"), endpoint, deadline.Token);
            using var prompt = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            var response = await blocked.ReceiveAsync(prompt.Token);
            Check(response.Buffer[^4..].SequenceEqual(new byte[4]) && dns.ActiveRequestCount == 1, "Block waited for upstream");
            await dns.StopAsync().WaitAsync(deadline.Token);
            Check(dns.ActiveRequestCount == 0 && !dns.IsRunning, "Owned work survived stop");
        });

        await asyncTest("Phase5C UDP concurrency admits two queries drops overload and awaits cancellation", async () =>
        {
            await using var f = new Fixture(directory); f.Config.UpstreamTimeoutMs = 10000;
            using var deadline = Deadline(); await using var dns = new DnsProxyServer(new RuleStore("bound"), f.Settings);
            await dns.StartAsync(); using var client = new UdpClient();
            var endpoint = new IPEndPoint(IPAddress.Loopback, f.Settings.DnsPort);
            await client.SendAsync(Query("first.invalid"), endpoint, deadline.Token); await f.Primary.ReceiveAsync(deadline.Token);
            await client.SendAsync(Query("second.invalid"), endpoint, deadline.Token); await f.Primary.ReceiveAsync(deadline.Token);
            Check(dns.ActiveRequestCount == 2, "UDP globally serialized");
            for (var i = 0; i < 8; i++) await client.SendAsync(Query("overload.invalid"), endpoint, deadline.Token);
            using var silence = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            try { await f.Primary.ReceiveAsync(silence.Token); throw new Exception("Concurrency limit exceeded"); }
            catch (OperationCanceledException) when (silence.IsCancellationRequested) { }
            Check(dns.ActiveRequestCount == 2, "Unbounded work admitted");
            await dns.StopAsync().WaitAsync(deadline.Token);
            Check(dns.ActiveRequestCount == 0 && !dns.RuntimeStatus.GetSnapshot().UdpListening, "Stop left tasks/listener active");
            await dns.StartAsync(); Check(dns.IsRunning, "Restart failed"); await dns.StopAsync();
        });

        await asyncTest("Phase5C request exception is observed without terminating UDP listener", async () =>
        {
            await using var f = new Fixture(directory); using var deadline = Deadline();
            var calls = 0;
            await using var dns = new DnsProxyServer(new RuleStore("exception"), f.Settings, (query, token) =>
            {
                if (Interlocked.Increment(ref calls) == 1) throw new InvalidOperationException("isolated fixture failure");
                return Task.FromResult<byte[]?>(Reply(query));
            });
            await dns.StartAsync(); using var client = new UdpClient();
            var endpoint = new IPEndPoint(IPAddress.Loopback, f.Settings.DnsPort);
            await client.SendAsync(Query(), endpoint, deadline.Token);
            while (Volatile.Read(ref calls) != 1) await Task.Delay(5, deadline.Token);
            await client.SendAsync(Query(), endpoint, deadline.Token);
            var received = await client.ReceiveAsync(deadline.Token);
            Check(received.Buffer.SequenceEqual(Reply(Query())) && dns.IsRunning, "Exception killed listener");
            await dns.StopAsync(); Check(dns.ActiveRequestCount == 0, "Exception leaked owned task");
        });

        foreach (var useFallback in new[] { false, true })
        {
            await asyncTest("Phase5C Safe Mode uses " + (useFallback ? "fallback" : "healthy primary") + " without changing committed policy", async () =>
            {
                await using var f = new Fixture(directory, useFallback); using var deadline = Deadline();
                var rules = new RuleStore("safe-reliability"); await using var dns = new DnsProxyServer(rules, f.Settings);
                var policy = new PolicyApplicationService(rules, new PolicyPersistence(f.Settings.PolicyFilePath), dns.PolicyState);
                Check(policy.Replace(new[] { "explicit.invalid" }).Success && policy.SetSafeMode(true).Success, "Fixture authorization failed");
                var before = policy.State.GetSnapshot(); var bytes = File.ReadAllBytes(f.Settings.PolicyFilePath);
                var exchange = dns.RequestProcessor.ProcessAsync(Query("explicit.invalid"), deadline.Token);
                if (useFallback) { await f.Primary.ReceiveAsync(deadline.Token); await f.Primary.ReceiveAsync(deadline.Token); }
                await ReplyNext(useFallback ? f.Fallback : f.Primary, deadline.Token);
                Check((await exchange)!.SequenceEqual(Reply(Query("explicit.invalid"))), "Safe Mode locally blocked");
                var snapshot = dns.RuntimeStatus.GetSnapshot();
                Check(snapshot.LastUpstreamOutcome == "Response" && snapshot.LastUpstreamRequestUsedFallback == useFallback && snapshot.UpstreamHealth == "NotMeasured", "Passive status not truthful");
                for (var i = 0; i < 10; i++) dns.RuntimeStatus.GetSnapshot();
                Check(before == policy.State.GetSnapshot() && bytes.SequenceEqual(File.ReadAllBytes(f.Settings.PolicyFilePath)), "Reliability/status mutated Safe Mode policy");
            });
        }

        await asyncTest("Phase5C Safe Mode timeout returns SERVFAIL preserving revision and committed bytes", async () =>
        {
            await using var f = new Fixture(directory); using var deadline = Deadline();
            var rules = new RuleStore("safe-timeout"); await using var dns = new DnsProxyServer(rules, f.Settings);
            var policy = new PolicyApplicationService(rules, new PolicyPersistence(f.Settings.PolicyFilePath), dns.PolicyState);
            Check(policy.Replace(new[] { "explicit.invalid" }).Success && policy.SetSafeMode(true).Success, "Fixture authorization failed");
            var before = policy.State.GetSnapshot(); var bytes = File.ReadAllBytes(f.Settings.PolicyFilePath);
            var result = await dns.RequestProcessor.ProcessAsync(Query("explicit.invalid"), deadline.Token);
            Check(result != null && (result[3] & 15) == 2 && policy.State.GetSnapshot() == before && bytes.SequenceEqual(File.ReadAllBytes(f.Settings.PolicyFilePath)), "Failure mutated committed policy");
            var status = dns.RuntimeStatus.GetSnapshot();
            Check(status.LastUpstreamOutcome == "Exhausted" && status.LastUpstreamFailure == "Timeout" && status.LastUpstreamSuccessUtc == null && status.LastUpstreamFailureUtc != null, "False healthy status");
        });
    }
}
