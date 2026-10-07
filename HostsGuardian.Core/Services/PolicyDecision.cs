using System.Collections.Immutable;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

/// <summary>Pure user-policy decision calculation; never writes policy or identity.</summary>
public static class PolicyDecision
{
    public static bool Matches(string domain, string rule) => domain == rule || domain.EndsWith("." + rule, StringComparison.Ordinal);
    public static bool Active(PolicySchedule schedule, DateTimeOffset utc)
    {
        if (!schedule.Enabled) return false;
        var local = TimeZoneInfo.ConvertTime(utc, TimeZoneInfo.FindSystemTimeZoneById(schedule.TimeZoneId));
        var minute = local.Hour * 60 + local.Minute;
        if (schedule.StartMinute < schedule.EndMinute)
            return schedule.Days.Contains(local.DayOfWeek) && minute >= schedule.StartMinute && minute < schedule.EndMinute;
        var previous = (DayOfWeek)(((int)local.DayOfWeek + 6) % 7);
        return minute >= schedule.StartMinute && schedule.Days.Contains(local.DayOfWeek) ||
            minute < schedule.EndMinute && schedule.Days.Contains(previous);
    }
    public static (DecisionEvidence Winner, ImmutableArray<DecisionEvidence> Chain) Explain(FullDnsPolicy policy, Guid? device, string domain, DateTimeOffset utc)
    {
        domain = DomainName.Normalize(domain);
        var candidates = new List<DecisionEvidence>();
        foreach (var rule in policy.GlobalBlockedDomains.Where(r => Matches(domain, r)))
            candidates.Add(new(PolicyLayer.Global, DeviceDomainRuleState.Block, "GlobalBlock", rule));
        if (!candidates.Any()) candidates.Add(new(PolicyLayer.Global, DeviceDomainRuleState.Allow, "GlobalAllow", domain));
        if (policy.Program is { } program)
        {
            var groups = device == null ? [] : program.Groups.Where(g => g.DeviceIds.Contains(device.Value)).ToArray();
            IEnumerable<string> Domains(ProgramRule rule) => rule.Domain != null ? [rule.Domain] :
                program.Services.Single(s => s.ServiceId == rule.ServiceId).Domains;
            void Add(ProgramRule rule, PolicyLayer layer, string source, Guid? group = null, Guid? profile = null, Guid? schedule = null)
            {
                if (rule.State == DeviceDomainRuleState.Inherit) return;
                foreach (var match in Domains(rule).Where(r => Matches(domain, r)))
                    candidates.Add(new(layer, rule.State, source, match, rule.RuleId, group, profile, schedule, rule.ServiceId));
            }
            foreach (var group in groups)
                foreach (var rule in group.Rules) Add(rule, PolicyLayer.DeviceGroup, "GroupRule", group.GroupId);
            foreach (var profile in program.Profiles.Where(p => p.Enabled && (p.AppliesGlobally ||
                         device != null && (p.DeviceIds.Contains(device.Value) || p.GroupIds.Any(id => groups.Any(g => g.GroupId == id))))))
            {
                var matchedGroups = groups.Where(g => profile.GroupIds.Contains(g.GroupId)).Select(g => (Guid?)g.GroupId).ToArray();
                var scopes = profile.AppliesGlobally || device != null && profile.DeviceIds.Contains(device.Value)
                    ? new Guid?[] { null } : matchedGroups;
                var active = program.Schedules.Where(s => s.ProfileId == profile.ProfileId && Active(s, utc)).ToArray();
                if (profile.AlwaysActive)
                    foreach (var group in scopes)
                        foreach (var rule in profile.Rules) Add(rule, PolicyLayer.ActiveProfile, "ActiveProfile", group, profile.ProfileId);
                foreach (var schedule in active)
                    foreach (var group in scopes)
                        foreach (var rule in profile.Rules) Add(rule, PolicyLayer.ActiveProfile, "ActiveSchedule", group, profile.ProfileId, schedule.ScheduleId);
            }
        }
        if (device is Guid id)
            foreach (var rule in policy.Overrides.Where(r => r.DeviceId == id && r.State != DeviceDomainRuleState.Inherit && Matches(domain, r.Domain)))
                candidates.Add(new(PolicyLayer.DeviceOverride, rule.State, "DeviceOverride", rule.Domain));
        // v2 keeps its accepted most-specific device-domain semantics. New v3 uses
        // user-confirmed same-layer Block-wins and retains all overridden evidence.
        var ordered = policy.SchemaVersion == 2
            ? candidates.OrderByDescending(c => c.Layer).ThenByDescending(c => c.Domain.Length)
            : candidates.OrderByDescending(c => c.Layer).ThenByDescending(c => c.State == DeviceDomainRuleState.Block).ThenByDescending(c => c.Domain.Length);
        var chain = ordered.ThenBy(c => c.Source, StringComparer.Ordinal)
            .ThenBy(c => c.RuleId).ThenBy(c => c.GroupId).ThenBy(c => c.ProfileId)
            .ThenBy(c => c.ScheduleId).ThenBy(c => c.ServiceId)
            .ThenBy(c => c.Domain, StringComparer.Ordinal).ToImmutableArray();
        return (chain[0], chain);
    }
}
