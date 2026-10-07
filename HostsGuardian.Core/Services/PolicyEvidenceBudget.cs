using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

/// <summary>Conservative schema-3 bound keeps complete decision chains within the private API envelope.</summary>
public static class PolicyEvidenceBudget
{
    public const int MaximumCandidates = 128;
    public static void Validate(FullDnsPolicy policy)
    {
        if (policy.SchemaVersion != 3) return;
        var program = policy.Program!;
        long DomainCount(ProgramRule rule) => rule.State == DeviceDomainRuleState.Inherit ? 0 :
            rule.Domain != null ? 1 : program.Services.Single(s => s.ServiceId == rule.ServiceId).Domains.Length;
        // A device cannot acquire another device's overrides; other layers conservatively count all paths.
        long total = Math.Max(1, policy.GlobalBlockedDomains.Length) +
            policy.Overrides.GroupBy(o => o.DeviceId).Select(g => g.LongCount(o => o.State != DeviceDomainRuleState.Inherit)).DefaultIfEmpty().Max();
        total += program.Groups.Sum(g => g.Rules.Sum(DomainCount));
        foreach (var profile in program.Profiles)
        {
            var scopes = profile.AppliesGlobally || profile.DeviceIds.Length > 0 ? Math.Max(1, profile.GroupIds.Length) : profile.GroupIds.Length;
            var paths = (profile.AlwaysActive ? 1 : 0) + program.Schedules.Count(s => s.ProfileId == profile.ProfileId);
            total += profile.Rules.Sum(DomainCount) * scopes * paths;
        }
        if (total > MaximumCandidates) throw new ArgumentException("Policy exceeds complete explanation budget (128 potential candidates)");
    }
}
