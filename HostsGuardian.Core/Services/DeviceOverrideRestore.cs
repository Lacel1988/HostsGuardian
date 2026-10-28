using System.Collections.Immutable;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

// Null Original means ABSENT, never an implicit Inherit rule.
public sealed record DeviceOverrideRestorePoint(Guid DeviceId, string Domain, DeviceDomainOverride? Original);

public static class DeviceOverrideRestore
{
    public static FullDnsPolicy Apply(FullDnsPolicy current, IEnumerable<DeviceOverrideRestorePoint> points)
    {
        var scope = points.ToArray();
        if (scope.Length > 16384 || scope.Select(p => (p.DeviceId, p.Domain)).Distinct().Count() != scope.Length)
            throw new ArgumentException("Invalid restore scope");
        foreach (var p in scope)
            if (!current.Devices.Any(d => d.DeviceId == p.DeviceId) || DomainName.Normalize(p.Domain) != p.Domain ||
                p.Domain == "" || p.Original is {} original &&
                (original.DeviceId != p.DeviceId || original.Domain != p.Domain || !Enum.IsDefined(original.State)))
                throw new ArgumentException("Invalid restore reference");
        var keys = scope.Select(p => (p.DeviceId, p.Domain)).ToHashSet();
        return PolicyCanonicalization.Canonicalize(current with
        {
            Overrides = current.Overrides.Where(o => !keys.Contains((o.DeviceId, o.Domain)))
                .Concat(scope.Where(p => p.Original != null).Select(p => p.Original!)).ToImmutableArray()
        });
    }
}
