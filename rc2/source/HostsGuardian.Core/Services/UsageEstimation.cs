using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public static class UsageEstimation
{
    /// <summary>Activity-window estimate, never screen time or an enforcement input.</summary>
    public static UsageEstimate[] Estimate(ProductActivityRead read)
    {
        if (read.SchemaVersion != 1 || read.Buckets.Length > 256) throw new ArgumentException("Invalid activity contract");
        return read.Buckets.Where(b => b.Allowed > 0).GroupBy(b => (b.DeviceId, b.ServiceId, b.ServiceName))
            .Select(g => new UsageEstimate(g.Key.DeviceId, g.Key.ServiceId, g.Key.ServiceName,
                g.Select(b => b.WindowStartUtc).Distinct().Count(), g.Select(b => b.WindowStartUtc).Distinct().Count() * 5,
                g.Any(b => b.AmbiguousService) || g.Key.ServiceId == null ? "Ambiguous" : "DNS activity estimate; not screen time"))
            .ToArray();
    }
}
