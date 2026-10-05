using System.Collections.Immutable;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
namespace HostsGuardian.Core.Services;

public static class PolicyCanonicalization
{
    public static FullDnsPolicy Canonicalize(FullDnsPolicy candidate)
    {
        if (candidate == null || candidate.SchemaVersion != 2 || candidate.GlobalBlockedDomains.IsDefault
            || candidate.Devices.IsDefault || candidate.Overrides.IsDefault || candidate.Devices.Length > 4096
            || candidate.Overrides.Length > 16384) throw new ArgumentException("Invalid policy schema");
        var domains = candidate.GlobalBlockedDomains.Select(Normalize).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToImmutableArray();
        var devices = candidate.Devices.Select(d =>
        {
            if (d == null || d.DeviceId == Guid.Empty || string.IsNullOrWhiteSpace(d.Name) || d.Name.Length > 128
                || string.IsNullOrWhiteSpace(d.Scope) || d.Scope.Length > 128 || string.IsNullOrWhiteSpace(d.Provenance)
                || d.Provenance.Length > 128) throw new ArgumentException("Invalid device registry");
            var mac = d.Mac == null ? null : DevicePolicyIdentity.NormalizeMac(d.Mac);
            if (mac == "") throw new ArgumentException("Invalid MAC evidence");
            return d with { Mac = mac };
        }).OrderBy(d => d.DeviceId).ToImmutableArray();
        if (devices.Select(d => d.DeviceId).Distinct().Count() != devices.Length) throw new ArgumentException("Duplicate DeviceId");
        var overrides = candidate.Overrides.Select(o =>
        {
            if (o == null || !Enum.IsDefined(o.State) || !devices.Any(d => d.DeviceId == o.DeviceId))
                throw new ArgumentException("Invalid policy reference");
            return o with { Domain = Normalize(o.Domain) };
        }).OrderBy(o => o.DeviceId).ThenBy(o => o.Domain, StringComparer.Ordinal).ToImmutableArray();
        if (overrides.Select(o => (o.DeviceId, o.Domain)).Distinct().Count() != overrides.Length)
            throw new ArgumentException("Duplicate device override");
        return new(2, domains, devices, overrides);
    }
    private static string Normalize(string value)
    {
        var normalized = DomainName.Normalize(value);
        if (normalized.Length == 0) throw new ArgumentException("Invalid domain");
        return normalized;
    }
}
