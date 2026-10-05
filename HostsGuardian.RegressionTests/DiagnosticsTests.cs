using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class DiagnosticsTests
{
    private static void Check(bool value, string text) { if (!value) throw new Exception(text); }
    private static EngineSettings Settings() => EngineSettings.FromConfig(new EngineConfig { UpstreamRetryCount = 1, MaxConcurrentUdpRequests = 2 });
    private static byte[] Query(string name = "allowed.invalid")
    {
        var data = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.')) { data.Add((byte)label.Length); data.AddRange(Encoding.ASCII.GetBytes(label)); }
        data.AddRange(new byte[] { 0, 0, 1, 0, 1 }); return data.ToArray();
    }
    private static DnsServiceStatus Ready() => new() { RuntimeState = "Running", UdpState = "Listening", TcpState = "Listening",
        ManagementState = "Listening", UdpListening = true, TcpListening = true, ManagementListening = true, PolicyLoaded = true };
    public static async Task Run(Action<string, Action> test, Func<string, Func<Task>, Task> asyncTest, string directory)
    {
        test("Diagnostics API disappearance observation persists deduplicates and requires confirmed recovery", () =>
        {
            var now = DateTimeOffset.UtcNow; var observer = new OperationalConnectionObserver(() => now);
            Check(observer.Observe(false, true) == OperationalAvailabilityTransition.None, "Single read failure alerted");
            now = now.AddSeconds(16); Check(observer.Observe(false, true) == OperationalAvailabilityTransition.Unavailable, "Sustained disappearance missing");
            now = now.AddSeconds(16); Check(observer.Observe(false, true) == OperationalAvailabilityTransition.None, "Read outage spam");
            Check(observer.Observe(false, false) == OperationalAvailabilityTransition.None, "Unsupported contract invented recovery");
            Check(observer.Observe(true, false) == OperationalAvailabilityTransition.None, "First success falsely recovered");
            now = now.AddSeconds(31); Check(observer.Observe(true, false) == OperationalAvailabilityTransition.Recovered, "Confirmed API recovery missing");
        });
        test("Diagnostics advanced-default foundation rejects unbounded or contradictory configuration", () =>
        {
            foreach (var defaults in new[] { new HealthDefaults(WindowSeconds: 100000), new HealthDefaults(RecoveryFailureRatio: .5), new HealthDefaults(CriticalSeconds: 1), new HealthDefaults(SlowP95Ms: double.NaN) })
            { try { _ = new OperationalHealth("invalid", defaults); throw new Exception("Unsafe defaults accepted"); } catch (ArgumentException) { } }
        });
        test("Diagnostics zero traffic is calm and no latency or incident is invented", () =>
        {
            var telemetry = new DnsTelemetry(Settings()); var health = new OperationalHealth("zero");
            health.Evaluate(Ready(), telemetry.Counters(), telemetry.UpstreamLatency.Snapshot(), DateTimeOffset.UtcNow);
            Check(telemetry.Counters().Received == 0 && telemetry.UpstreamLatency.Snapshot().P95Ms == null && health.Overall == "Healthy" && health.Read().Events.Length == 0, "Idle health fabricated");
        });
        await asyncTest("Diagnostics allowed blocked mixed UDP TCP outcomes preserve filtering", async () =>
        {
            var settings = Settings(); var telemetry = new DnsTelemetry(settings); var rules = new RuleStore("counts");
            var state = new EnginePolicyState(); state.Publish(new("Restored", true, 1, 1, false, "", "")); rules.SetBlockedDomains(["blocked.invalid"]);
            var upstream = new UpstreamDnsForwarder(settings, null, (q, _, _) => { var response = q.ToArray(); response[2] |= 0x80; return Task.FromResult(new UpstreamResult(UpstreamOutcome.Response, response)); }, telemetry);
            var processor = new DnsRequestProcessor(rules, settings, upstream, state, telemetry);
            for (var i = 0; i < 20; i++)
            {
                var response = await processor.ProcessAsync(Query(i % 2 == 0 ? "blocked.invalid" : "allowed.invalid"), new(i % 2 == 0 ? DnsTransport.Udp : DnsTransport.Tcp, "", 0, DateTimeOffset.UtcNow, null), default);
                Check(response != null && (response[3] & 15) == 0, "Filtering response changed");
            }
            var counts = telemetry.Counters();
            Check(counts.Received == 20 && counts.Udp == 10 && counts.Tcp == 10 && counts.PolicyBlocked == 10 && counts.Allowed == 10 && counts.Failed == 0 && counts.Completed == counts.Received, "Blocked classified as failure or transport lost");
            Check(telemetry.Pressure().CurrentRequests == 0 && telemetry.UpstreamLatency.Snapshot().Samples == 10 && telemetry.ProcessingLatency.Snapshot().Samples == 20, "Concurrency/latency accounting wrong");
        });
        await asyncTest("Diagnostics malformed requests rejected and cancellation remains separate", async () =>
        {
            var settings = Settings(); var t = new DnsTelemetry(settings); var state = new EnginePolicyState();
            var p = new DnsRequestProcessor(new("reject"), settings, new(settings), state, t);
            Check(await p.ProcessAsync(new byte[2], default) == null, "Malformed answered");
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            Check(await p.ProcessAsync(Query(), cancelled.Token) == null && t.Counters().Rejected == 1 && t.Counters().Cancelled == 1 && t.Counters().Failed == 0, "Reject/cancel conflated with failure");
        });
        await asyncTest("Diagnostics timeouts retries fallback and SERVFAIL count real attempts", async () =>
        {
            var settings = Settings() with { FallbackEndpoint = new(IPAddress.Loopback, 45678) }; var t = new DnsTelemetry(settings);
            var forwarder = new UpstreamDnsForwarder(settings, null, (_, _, _) => Task.FromResult(new UpstreamResult(UpstreamOutcome.Timeout)), t);
            var p = new DnsRequestProcessor(new("timeout"), settings, forwarder, new(), t);
            var response = await p.ProcessAsync(Query(), default);
            var c = t.Counters();
            Check(response != null && (response[3] & 15) == 2 && c.Failed == 1 && c.Servfail == 1 && c.UpstreamAttempts == 4 && c.UpstreamTimeouts == 4 && c.UpstreamRetries == 3 && c.FallbackAttempts == 2, "Attempt counts incorrect");
            Check(t.Resolvers().Length == 2 && t.Resolvers().All(x => x.Timeouts == 2 && x.State == "RecentFailure"), "Per-resolver evidence lost");
        });
        await asyncTest("Diagnostics current concurrency tracks awaited upstream and releases on completion", async () =>
        {
            var settings = Settings(); var t = new DnsTelemetry(settings); var release = new TaskCompletionSource<UpstreamResult>();
            var upstream = new UpstreamDnsForwarder(settings, null, (_, _, _) => release.Task, t);
            var p = new DnsRequestProcessor(new("concurrent"), settings, upstream, new(), t);
            var requests = Enumerable.Range(0, 8).Select(_ => p.ProcessAsync(Query(), default)).ToArray();
            Check(t.Pressure().CurrentRequests == 8 && t.Pressure().PeakRequests == 8, "Awaiting work not tracked");
            release.SetResult(new(UpstreamOutcome.Response, Query())); await Task.WhenAll(requests);
            Check(t.Pressure().CurrentRequests == 0, "In-flight requests leaked");
        });
        test("Diagnostics rolling percentiles bound storage expire and resist single latency spike", () =>
        {
            var samples = new RollingLatency(); var ticks = Stopwatch.GetTimestamp();
            for (var i = 0; i < 10000; i++) samples.Record(20, ticks);
            samples.Record(800, ticks);
            var latency = samples.Snapshot(ticks);
            Check(latency.Samples <= 2048 && latency.P50Ms == 20 && latency.P95Ms == 20 && latency.RecentMs == 800, "Percentiles unbounded or spike dominant");
            Check(samples.Snapshot(ticks + 61 * Stopwatch.Frequency).Samples == 0, "Latency retained indefinitely");
            var health = new OperationalHealth("spike"); var c = new DnsTelemetry(Settings()).Counters(); var now = DateTimeOffset.UtcNow;
            for (var i = 0; i < 70; i++) health.Evaluate(Ready(), c with { UpstreamAttempts = i * 10 }, latency, now.AddSeconds(i));
            Check(health.Read().Events.Length == 0, "One slow query became incident");
        });
        test("Diagnostics sustained failure escalation dedup hysteresis and recovery relationship", () =>
        {
            var health = new OperationalHealth("incident"); var zero = new DnsTelemetry(Settings()).Counters(); var now = DateTimeOffset.UtcNow;
            for (var i = 0; i < 90; i++) health.Evaluate(Ready(), zero with { Received = i * 10, Failed = i * 10, UpstreamAttempts = i * 10, UpstreamFailures = i * 10 }, new(0, null, null, null, 0), now.AddSeconds(i));
            var events = health.Read().Events;
            Check(events.Count(e => e.Component == "Upstream") == 1 && events.Count(e => e.Component == "Processing") == 2 && health.Overall == "Critical", "Repeated failure spam or missing critical");
            var incident = events.First(e => e.Component == "Upstream").IncidentId;
            for (var i = 90; i < 180; i++) health.Evaluate(Ready(), zero with { Received = i * 10, Allowed = (i - 89) * 10, Failed = 890, UpstreamAttempts = i * 10, UpstreamFailures = 890 }, new(20, 20, 20, 20, 0), now.AddSeconds(i));
            Check(health.Overall == "Healthy" && health.Read().Events.Count(e => e.Severity == "Recovery") == 2 && health.Read().Events.Any(e => e.RecoveryOf == incident), "Recovery missing or unrelated");
        });
        test("Diagnostics absent upstream evidence cannot fabricate recovery", () =>
        {
            var health = new OperationalHealth("idle-after-failure"); var zero = new DnsTelemetry(Settings()).Counters(); var now = DateTimeOffset.UtcNow;
            for (var i = 0; i < 60; i++) health.Evaluate(Ready(), zero with { UpstreamAttempts = i * 10, UpstreamFailures = i * 10 }, new(0, null, null, null, 0), now.AddSeconds(i));
            for (var i = 60; i < 150; i++) health.Evaluate(Ready(), zero with { UpstreamAttempts = 590, UpstreamFailures = 590 }, new(0, null, null, null, 0), now.AddSeconds(i));
            Check(health.Components().Single(c => c.Component == "Upstream").State == "Degraded" && !health.Read().Events.Any(e => e.Severity == "Recovery"), "Idle invented upstream recovery");
        });
        test("Diagnostics listener faults immediate recovery persistent and bounded cursor gap truthful", () =>
        {
            var defaults = new HealthDefaults(RecoverySeconds: 1, EventCapacity: 4); var health = new OperationalHealth("listener", defaults);
            var zero = new DnsTelemetry(Settings()).Counters(); var now = DateTimeOffset.UtcNow;
            for (var i = 0; i < 9; i++)
            {
                var status = Ready(); status.UdpState = "Faulted"; status.UdpListening = false;
                health.Evaluate(status, zero, new(0,null,null,null,0), now.AddSeconds(i * 4));
                health.Evaluate(Ready(), zero, new(0,null,null,null,0), now.AddSeconds(i * 4 + 1));
                health.Evaluate(Ready(), zero, new(0,null,null,null,0), now.AddSeconds(i * 4 + 2));
            }
            Check(health.Read().Events.Length == 4 && health.Read().CursorGap && health.Read(health.Read().LatestSequence).Events.Length == 0, "Bounded events/cursor broken");
            Check(health.Overall == "Healthy", "Listener recovery missing");
        });
        test("Diagnostics capacity incidents depend on real drops and host resources do not drive health", () =>
        {
            var t = new DnsTelemetry(Settings()); t.Received(DnsTransport.Udp); t.Rejected(true); t.RejectConnection();
            Check(t.Counters().CapacityDropped == 1 && t.Counters().TcpConnectionsRejected == 1 && t.Pressure().UdpCapacity == 2 && t.Pressure().TcpConnectionCapacity == 16, "Invented capacity");
            var health = new OperationalHealth("capacity"); var now = DateTimeOffset.UtcNow; var zero = t.Counters();
            for (var i = 0; i < 70; i++) health.Evaluate(Ready(), zero with { CapacityDropped = i * 10 }, new(0,null,null,null,0), now.AddSeconds(i));
            Check(health.Read().Events.Count(e => e.Component == "Capacity") == 1 && health.Overall == "Degraded", "Capacity incident missing or spammed");
        });
        test("Diagnostics concurrent snapshots remain bounded and outcome totals are derived", () =>
        {
            var t = new DnsTelemetry(Settings());
            Parallel.For(0, 20000, _ => { t.Received(DnsTransport.Udp); t.Enter(DnsTransport.Udp); t.Blocked(); t.ProcessingLatency.Record(1); t.Exit(DnsTransport.Udp); var c = t.Counters(); Check(c.Completed <= c.Received && c.Received == c.Udp + c.Tcp && c.Servfail <= c.Failed && c.CapacityDropped <= c.Rejected && c.UpstreamTimeouts <= c.UpstreamAttempts, "Torn completed total"); });
            var c = t.Counters(); Check(c.Received == 20000 && c.Completed == 20000 && t.Pressure().CurrentRequests == 0 && t.ProcessingLatency.Snapshot().Samples <= 2048, "Concurrent accounting lost updates");
        });
        await asyncTest("Diagnostics authenticated HTTPS endpoints deny missing token and polling has no policy effects", async () =>
        {
            await using var f = new Phase5DTests.Fixture(directory); await f.Api.StartAsync();
            var before = f.Policy.ReadFullPolicy(); var client = new DnsEngineService();
            var read = await client.ReadOperationalEventsAsync(f.ClientConfig);
            Check(read.Connection.Ok && read.Batch?.SchemaVersion == 1 && read.Batch.Components.Length == 6, "Authenticated events unavailable");
            using var certificate = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(File.ReadAllText(f.Config.CertificatePath));
            using var http = new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, cert, _, errors) => ManagementSecurity.ValidateCertificate(cert, f.ClientConfig.TrustedCertificate, errors) });
            var uri = $"https://127.0.0.1:{f.Config.ApiPort}";
            foreach (var endpoint in new[] { "/v2/diagnostics", "/v2/operational-events" })
            {
                using var denied = await http.GetAsync(uri + endpoint); Check(denied.StatusCode == HttpStatusCode.Unauthorized, "Unauthenticated telemetry exposed");
                using var request = new HttpRequestMessage(HttpMethod.Get, uri + endpoint); request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", f.ClientConfig.ApiToken);
                using var response = await http.SendAsync(request); Check(response.IsSuccessStatusCode, "Telemetry endpoint failed");
                var text = await response.Content.ReadAsStringAsync(); Check(!text.Contains(f.ClientConfig.ApiToken) && !text.Contains("PRIVATE KEY") && !text.Contains(f.Config.CredentialPath), "Secret metadata leaked");
            }
            Check(f.Policy.ReadFullPolicy() == before, "Read mutated policy");
        });
        await asyncTest("Diagnostics safe high-port UDP load measures activity blocks timeouts and real capacity drops", async () =>
        {
            await using var f = new Phase5DTests.Fixture(directory); f.Policy.Replace(["blocked.invalid"]); await f.Dns.StartAsync();
            using var client = new UdpClient(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var target = new IPEndPoint(IPAddress.Loopback, f.Config.DnsListenPort); var query = Query("blocked.invalid");
            var latencies = new List<double>(); var watch = Stopwatch.StartNew();
            for (var i = 0; i < 1000; i++)
            {
                var start = Stopwatch.GetTimestamp(); await client.SendAsync(query, target, deadline.Token); var response = await client.ReceiveAsync(deadline.Token);
                Check((response.Buffer[3] & 15) == 0, "Blocked load failed"); latencies.Add(Stopwatch.GetElapsedTime(start).TotalMilliseconds);
            }
            latencies.Sort(); Console.WriteLine($"LOAD loopback blocked: 1000 requests, {1000 / watch.Elapsed.TotalSeconds:F0} q/s, P50 {latencies[499]:F3}ms, P95 {latencies[949]:F3}ms");
            // An intentionally silent loopback fixture fills real UDP capacity, without public DNS.
            for (var i = 0; i < 200; i++) await client.SendAsync(Query(), target, deadline.Token);
            while (f.Dns.Telemetry.Counters().Received < 1200) await Task.Delay(10, deadline.Token);
            await Task.Delay(150, deadline.Token);
            var counts = f.Dns.Telemetry.Counters();
            Check(counts.PolicyBlocked == 1000 && counts.CapacityDropped > 0 && counts.UpstreamTimeouts > 0 && counts.Failed > 0, "Real drop/timeout/blocked accounting not proved");
            Console.WriteLine($"LOAD saturation: received {counts.Received}, blocked {counts.PolicyBlocked}, failed {counts.Failed}, drops {counts.CapacityDropped}, timeouts {counts.UpstreamTimeouts}");
            await f.Dns.StopAsync(); Check(f.Dns.Telemetry.Pressure().CurrentRequests == 0, "Load shutdown leaked concurrency");
        });
        await asyncTest("Diagnostics real TCP connection capacity and framed query accounting are separate", async () =>
        {
            await using var f = new Phase5DTests.Fixture(directory); f.Policy.Replace(["blocked.invalid"]);
            await using var tcp = new TcpDnsServer(f.Settings, f.Dns.RequestProcessor, f.Dns.RuntimeStatus); await tcp.StartAsync();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10)); var clients = new List<TcpClient>();
            try
            {
                for (var i = 0; i < TcpDnsServer.MaximumConnections; i++) { var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, f.Config.DnsListenPort, deadline.Token); clients.Add(client); }
                while (f.Dns.Telemetry.Pressure().TcpConnections < TcpDnsServer.MaximumConnections) await Task.Delay(10, deadline.Token);
                Check(f.Dns.Telemetry.Counters().Received == 0 && f.Dns.Telemetry.Pressure().CurrentRequests == 0, "Idle connections invented DNS queries");
                using var extra = new TcpClient(); await extra.ConnectAsync(IPAddress.Loopback, f.Config.DnsListenPort, deadline.Token);
                while (f.Dns.Telemetry.Counters().TcpConnectionsRejected == 0) await Task.Delay(10, deadline.Token);
                await TcpDnsFraming.WriteAsync(clients[0].GetStream(), Query("blocked.invalid"), deadline.Token);
                var response = await TcpDnsFraming.ReadAsync(clients[0].GetStream(), deadline.Token);
                Check(response != null && f.Dns.Telemetry.Counters().Tcp == 1 && f.Dns.Telemetry.Counters().PolicyBlocked == 1 && f.Dns.Telemetry.Counters().Failed == 0, "Real framed TCP query accounting failed");
            }
            finally { foreach (var client in clients) client.Dispose(); await tcp.StopAsync(); }
            Check(f.Dns.Telemetry.Pressure().TcpConnections == 0, "TCP connection pressure leaked");
        });
        test("Diagnostics hot-path primitive updates allocate no per-observation storage", () =>
        {
            var t = new DnsTelemetry(Settings());
            for (var i = 0; i < 1000; i++) { t.Received(DnsTransport.Udp); t.Blocked(); t.ProcessingLatency.Record(1); }
            var start = GC.GetAllocatedBytesForCurrentThread(); var watch = Stopwatch.StartNew();
            for (var i = 0; i < 100000; i++) { t.Received(DnsTransport.Udp); t.Enter(DnsTransport.Udp); t.Blocked(); t.ProcessingLatency.Record(1); t.Exit(DnsTransport.Udp); }
            var bytes = GC.GetAllocatedBytesForCurrentThread() - start;
            Console.WriteLine($"PERF instrumentation 100000 iterations: {watch.Elapsed.TotalMilliseconds:F2}ms, {bytes} total allocated bytes (Stopwatch included)");
            Check(bytes < 1024, "Telemetry hot path allocates per observation");
        });
    }
}
