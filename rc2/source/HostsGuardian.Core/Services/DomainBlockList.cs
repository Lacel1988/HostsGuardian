using System.Collections.Immutable;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

// Membership is persisted; enforcement continues to use the existing policy rules.
public static class DomainBlockList
{
    public static ImmutableArray<SavedDomain> Entries(FullDnsPolicy policy) =>
        (policy.SavedDomains ?? []).Concat(policy.GlobalBlockedDomains.Select(d => new SavedDomain(null, d)))
        .Concat(policy.Overrides.Where(r => r.State != DeviceDomainRuleState.Inherit).Select(r => new SavedDomain(r.DeviceId, r.Domain)))
        .Distinct().OrderBy(r => r.DeviceId).ThenBy(r => r.Domain, StringComparer.Ordinal).ToImmutableArray();

    public static FullDnsPolicy Change(FullDnsPolicy policy, Guid? device, string domain, bool enabled, bool delete)
    {
        domain = DomainName.Normalize(domain);
        if (domain.Length == 0 || device == Guid.Empty || device.HasValue && !policy.Devices.Any(d => d.DeviceId == device))
            throw new ArgumentException("Invalid domain or scope");
        var entries = Entries(policy).Where(r => r.DeviceId != device || r.Domain != domain);
        if (!delete) entries = entries.Append(new(device, domain));
        var globals = policy.GlobalBlockedDomains;
        var overrides = policy.Overrides;
        if (device == null)
        {
            globals = globals.Where(d => d != domain).ToImmutableArray();
            if (enabled && !delete) globals = globals.Add(domain);
        }
        else
        {
            // Disabling means removing this block, never creating an Allow exception.
            // A pre-existing Allow remains unless the user explicitly replaces/deletes it.
            overrides = overrides.Where(r => r.DeviceId != device || r.Domain != domain || !delete && !enabled && r.State == DeviceDomainRuleState.Allow).ToImmutableArray();
            if (enabled && !delete) overrides = overrides.Add(new(device.Value, domain, DeviceDomainRuleState.Block));
        }
        return PolicyCanonicalization.Canonicalize(policy with { SchemaVersion = 4, GlobalBlockedDomains = globals, Overrides = overrides, SavedDomains = entries.ToImmutableArray() });
    }
}
