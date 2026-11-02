using System.Net.Sockets;
using HostsGuardian.DnsEngine;

internal static class RoadmapRecoveryTests
{
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    public static async Task Run(Func<string, Func<Task>, Task> test, string directory)
    {
        await test("Roadmap transient listener startup recovers with bounded backoff and no policy/security writes", async () =>
        {
            var attempts = 0; var delays = new List<TimeSpan>();
            await BoundedListenerRecovery.StartAsync(() =>
            {
                if (++attempts < 3) throw new SocketException((int)SocketError.AddressAlreadyInUse);
                return Task.CompletedTask;
            }, "fixture", CancellationToken.None, (delay, _) => { delays.Add(delay); return Task.CompletedTask; });
            Check(attempts == 3 && delays.SequenceEqual(new[] { TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2) }), "Recovery budget/backoff incorrect");
        });
        await test("Roadmap exhausted startup recovery escalates after three attempts and never loops", async () =>
        {
            var attempts = 0; var rejected = false;
            try { await BoundedListenerRecovery.StartAsync(() => { attempts++; throw new SocketException((int)SocketError.AddressAlreadyInUse); },
                "fixture", CancellationToken.None, (_, _) => Task.CompletedTask); }
            catch (SocketException) { rejected = true; }
            Check(rejected && attempts == 3, "Exhaustion concealed or retry loop unbounded");
        });
        await test("Roadmap permission/security failures and cancellation are never retried", async () =>
        {
            foreach (var failure in new Exception[] { new UnauthorizedAccessException(), new InvalidOperationException("invalid credential"), new SocketException((int)SocketError.AccessDenied) })
            {
                var attempts = 0;
                try { await BoundedListenerRecovery.StartAsync(() => { attempts++; throw failure; }, "fixture", CancellationToken.None, (_, _) => throw new Exception("Unsafe retry")); }
                catch (Exception e) when (e == failure) { }
                Check(attempts == 1, "Security failure retried");
            }
            using var stop = new CancellationTokenSource(); stop.Cancel(); var dispatched = false;
            try { await BoundedListenerRecovery.StartAsync(() => { dispatched = true; return Task.CompletedTask; }, "fixture", stop.Token); }
            catch (OperationCanceledException) { }
            Check(!dispatched, "Cancelled recovery dispatched work");
        });
        await test("Roadmap real startup retry releases a temporary occupied port while preserving committed policy", async () =>
        {
            await using var fixture = new Phase5DTests.Fixture(directory);
            Check(fixture.Policy.Replace(["explicit.invalid"]).Success, "Fixture policy commit failed");
            var before = File.ReadAllBytes(fixture.Config.PolicyFilePath);
            using var blocker = new UdpClient(new System.Net.IPEndPoint(System.Net.IPAddress.Any, fixture.Config.DnsListenPort));
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            var lifetime = new EngineLifetime(fixture.Api, fixture.Dns).RunAsync(stop.Token);
            await Task.Delay(300); blocker.Dispose();
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (fixture.Dns.RuntimeStatus.GetSnapshot().RuntimeState != "Running" && DateTimeOffset.UtcNow < deadline) await Task.Delay(20);
            Check(fixture.Dns.RuntimeStatus.GetSnapshot().RuntimeState == "Running", "Real listener failed to recover");
            stop.Cancel(); Check(await lifetime == 0 && before.SequenceEqual(File.ReadAllBytes(fixture.Config.PolicyFilePath)), "Recovery changed policy or failed shutdown");
        });
    }
}
