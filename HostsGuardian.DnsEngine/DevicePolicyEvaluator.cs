using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

public static class DevicePolicyEvaluator
{
    public static EffectivePolicyExplanation Explain(PolicyStateSnapshot snapshot, FullDnsPolicy policy,
        BindingRead bindings, DnsRequestContext context, string domain, DateTimeOffset now)
    {
        var name = DomainName.Normalize(domain);
        var identity = AddressBindingStore.Resolve(bindings, policy, context, now);
        if (!snapshot.FilteringEnabled)
            return new(snapshot.Revision, bindings.Generation, identity.DeviceId, identity.State, name,
                DeviceDomainRuleState.Inherit, false, snapshot.SafeMode ? "SafeModeBypass" : "FilteringDisabled");
        if (identity.DeviceId is Guid id)
        {
            var rule = policy.Overrides.Where(o => o.DeviceId == id && Matches(name, o.Domain))
                .OrderByDescending(o => o.Domain.Length).FirstOrDefault();
            if (rule != null && rule.State != DeviceDomainRuleState.Inherit)
                return new(snapshot.Revision, bindings.Generation, id, identity.State, name, rule.State,
                    rule.State == DeviceDomainRuleState.Block, "DeviceOverride");
        }
        var blocked = policy.GlobalBlockedDomains.Any(d => Matches(name, d));
        return new(snapshot.Revision, bindings.Generation, identity.DeviceId, identity.State, name,
            DeviceDomainRuleState.Inherit, blocked, blocked ? "GlobalBlock" : "GlobalAllow");
    }
    private static bool Matches(string name, string rule) => name == rule || name.EndsWith("." + rule, StringComparison.Ordinal);
}
