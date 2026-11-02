using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;

namespace HostsGuardian.DnsEngine;

/// <summary>24h, 256-bucket in-memory product aggregates; never modifies policy.</summary>
public sealed class ProductActivityStore
{
    public const int RetentionHours = 24;
    public const int MaximumBuckets = 256;
    private readonly object _gate = new();
    private readonly Dictionary<(Guid?, Guid?, DateTimeOffset), ServiceActivity> _buckets = new();
    public void Record(FullDnsPolicy policy, EffectivePolicyExplanation decision, string outcome, DateTimeOffset now)
    {
        var services = policy.Program?.Services.Where(s => s.Domains.Any(d => PolicyDecision.Matches(decision.Domain, d))).ToArray() ?? [];
        var targets = services.Length == 0 ? new CatalogService?[] { null } : services.Cast<CatalogService?>().ToArray();
        var start = new DateTimeOffset(now.UtcDateTime.Year, now.UtcDateTime.Month, now.UtcDateTime.Day,
            now.UtcDateTime.Hour, now.UtcDateTime.Minute / 5 * 5, 0, TimeSpan.Zero);
        lock (_gate)
        {
            Purge(now);
            foreach (var service in targets)
            {
                var key = (decision.DeviceId, service?.ServiceId, start);
                if (!_buckets.TryGetValue(key, out var bucket))
                    bucket = new(decision.DeviceId, service?.ServiceId, service?.Name ?? "Unclassified", start, 0, 0, 0, services.Length > 1);
                int Count(int count,string kind) => count == int.MaxValue ? count : count + (outcome == kind ? 1 : 0);
                _buckets[key] = bucket with
                { Allowed = Count(bucket.Allowed,"Allowed"), Blocked = Count(bucket.Blocked,"Blocked"), Failed = Count(bucket.Failed,"Failed") };
            }
            while (_buckets.Count > MaximumBuckets) _buckets.Remove(_buckets.MinBy(b => b.Value.WindowStartUtc).Key);
        }
    }
    private void Purge(DateTimeOffset now)
    { foreach (var key in _buckets.Where(b => b.Value.WindowStartUtc < now.AddHours(-RetentionHours)).Select(b => b.Key).ToArray()) _buckets.Remove(key); }
    public ProductActivityRead Read(DateTimeOffset now)
    {
        lock (_gate) { Purge(now); return new(1, now, RetentionHours, MaximumBuckets, _buckets.Values.OrderByDescending(b => b.WindowStartUtc).ToArray()); }
    }
}
