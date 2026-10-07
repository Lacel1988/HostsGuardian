using System.Collections.Immutable;

namespace HostsGuardian.Core.Models;

/// <summary>User-authored policy only. Catalog definitions are not active block rules.</summary>
public sealed record DeviceMetadata(string Alias, string Owner, string Type, string Location);
public sealed record CatalogService(Guid ServiceId, string Name, string DefinitionRevision, ImmutableArray<string> Domains);
public sealed record ProgramRule(Guid RuleId, string? Domain, Guid? ServiceId, DeviceDomainRuleState State);
public sealed record DeviceGroup(Guid GroupId, string Name, ImmutableArray<Guid> DeviceIds, ImmutableArray<ProgramRule> Rules);
public sealed record PolicyProfile(Guid ProfileId, string Name, bool Enabled, bool AlwaysActive, bool AppliesGlobally,
    ImmutableArray<Guid> DeviceIds, ImmutableArray<Guid> GroupIds, ImmutableArray<ProgramRule> Rules);
public sealed record PolicySchedule(Guid ScheduleId, Guid ProfileId, string Name, bool Enabled, string TimeZoneId,
    ImmutableArray<DayOfWeek> Days, int StartMinute, int EndMinute);
public sealed record PolicyProgram(ImmutableArray<DeviceGroup> Groups, ImmutableArray<CatalogService> Services,
    ImmutableArray<PolicyProfile> Profiles, ImmutableArray<PolicySchedule> Schedules)
{
    public static PolicyProgram Empty { get; } = new([], [], [], []);
}
public enum PolicyLayer { Global, DeviceGroup, ActiveProfile, DeviceOverride }
public sealed record DecisionEvidence(PolicyLayer Layer, DeviceDomainRuleState State, string Source,
    string Domain, Guid? RuleId = null, Guid? GroupId = null, Guid? ProfileId = null,
    Guid? ScheduleId = null, Guid? ServiceId = null);
