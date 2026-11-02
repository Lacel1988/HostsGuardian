using System.Text.Json;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public static class HealthSummary
{
    public static string Export(ConnectionResult result, bool synchronized)
    {
        var status = new EngineStatusPresentation(); status.Complete(result);
        return JsonSerializer.Serialize(new
        {
            schemaVersion = 1, observedAtUtc = DateTimeOffset.UtcNow,
            engine = status.EngineHost, management = status.Management, dns = status.DnsService,
            coverage = status.Coverage, coverageEvidence = result.Transport?.Coverage, coverageGuidance = status.CoverageGuidance,
            filtering = status.Filtering, policy = synchronized && result.Ok && result.Transport != null ? "Confirmed by caller readback" : "Unknown/unconfirmed",
            upstream = status.Upstream, safeMode = status.SafeMode,
            network = NetworkContextService.Read(),
            limitation = "Read-only summary; no credentials, endpoint, raw DNS or policy bodies. Connection alone is not policy synchronization."
        }, new JsonSerializerOptions { WriteIndented = true });
    }
}
