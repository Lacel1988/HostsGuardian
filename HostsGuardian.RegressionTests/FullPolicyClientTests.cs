using System.Net;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
internal static class FullPolicyClientTests
{
    public static async Task Run(Func<string, Func<Task>, Task> test)
    {
        var id = Guid.NewGuid();
        var full = PolicyCanonicalization.Canonicalize(new(2, ["one.invalid"], [new(id, "TV", null, "fixture", "review")],
            [new(id, "one.invalid", DeviceDomainRuleState.Allow)]));
        var cfg = new DnsEngineConfig { Address = "fixture.invalid", ApiToken = new string('A', 64) };
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        foreach (var mismatch in new[] { "global", "override", "registry", "instance" })
        await test("Integrated same-count full readback rejects " + mismatch + " mismatch", async () =>
        {
            var changed = mismatch switch
            {
                "global" => full with { GlobalBlockedDomains = ["two.invalid"] },
                "override" => full with { Overrides = [new(id, "one.invalid", DeviceDomainRuleState.Block)] },
                "registry" => full with { Devices = [full.Devices[0] with { Name = "Changed" }] },
                _ => full
            };
            var service = new DnsEngineService(() => new HttpClient(new Handler(request => request.RequestUri!.AbsolutePath switch
            {
                "/v2/capabilities" => JsonSerializer.Serialize(new { policySchemaVersion = 2, fullPolicyReadback = true, optimisticConcurrency = true }),
                "/v2/policy/replace" => "{\"ok\":true,\"revision\":2,\"count\":1}",
                "/v2/policy" => JsonSerializer.Serialize(new FullPolicyRead(2, changed, mismatch == "instance" ? "other" : "fixture"), options),
                _ => throw new Exception("Mismatched full readback must not reach status confirmation")
            })));
            var result = await service.ReplaceFullPolicyAsync(cfg, new(1, full, "fixture"));
            if (result.Confirmed || result.CanonicalMatch || result.AcknowledgedRevision != 2) throw new Exception("Count-only synchronization accepted");
        });
    }
    private sealed class Handler(Func<HttpRequestMessage, string> body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body(request)) });
    }
}
