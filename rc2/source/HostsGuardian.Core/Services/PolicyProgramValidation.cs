using System.Collections.Immutable;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public static class PolicyProgramValidation
{
    private static string Label(string value)
        => !string.IsNullOrWhiteSpace(value) && value.Length <= 128 && !value.Any(char.IsControl)
            ? value.Trim() : throw new ArgumentException("Invalid policy label");
    public static DeviceMetadata? Metadata(DeviceMetadata? value)
    {
        if (value == null) return null;
        string Field(string text) => text != null && text.Length <= 128 && !text.Any(char.IsControl)
            ? text.Trim() : throw new ArgumentException("Invalid device metadata");
        return new(Field(value.Alias), Field(value.Owner), Field(value.Type), Field(value.Location));
    }
    public static PolicyProgram Canonicalize(PolicyProgram value, ImmutableArray<DeviceRegistration> devices)
    {
        if (value.Groups.IsDefault || value.Services.IsDefault || value.Profiles.IsDefault || value.Schedules.IsDefault ||
            value.Groups.Length > 128 || value.Services.Length > 256 || value.Profiles.Length > 128 || value.Schedules.Length > 512 ||
            value.Groups.Any(x => x == null) || value.Services.Any(x => x == null) || value.Profiles.Any(x => x == null) || value.Schedules.Any(x => x == null))
            throw new ArgumentException("Invalid or oversized policy program");
        static void Unique(IEnumerable<Guid> ids)
        {
            var values = ids.ToArray();
            if (values.Any(x => x == Guid.Empty) || values.Distinct().Count() != values.Length)
                throw new ArgumentException("Empty/duplicate stable policy ID");
        }
        Unique(value.Groups.Select(x => x.GroupId)); Unique(value.Services.Select(x => x.ServiceId));
        Unique(value.Profiles.Select(x => x.ProfileId)); Unique(value.Schedules.Select(x => x.ScheduleId));
        var ids = devices.Select(x => x.DeviceId).ToHashSet();
        ImmutableArray<Guid> References(ImmutableArray<Guid> source, HashSet<Guid> known)
        {
            if (source.IsDefault || source.Length > 4096 || source.Any(x => !known.Contains(x)))
                throw new ArgumentException("Invalid stable policy reference");
            Unique(source); return source.Order().ToImmutableArray();
        }
        var services = value.Services.Select(s =>
        {
            if (s.Domains.IsDefault || s.Domains.Length is < 1 or > 128) throw new ArgumentException("Invalid catalog domains");
            var domains = s.Domains.Select(d => DomainName.Normalize(d)).ToArray();
            if (domains.Any(d => d.Length == 0)) throw new ArgumentException("Invalid catalog domain");
            return s with { Name = Label(s.Name), DefinitionRevision = Label(s.DefinitionRevision),
                Domains = domains.Distinct().Order(StringComparer.Ordinal).ToImmutableArray() };
        }).OrderBy(s => s.ServiceId).ToImmutableArray();
        var serviceIds = services.Select(s => s.ServiceId).ToHashSet();
        ImmutableArray<ProgramRule> Rules(ImmutableArray<ProgramRule> source)
        {
            if (source.IsDefault || source.Length > 512 || source.Any(x => x == null)) throw new ArgumentException("Invalid program rules");
            Unique(source.Select(x => x.RuleId));
            return source.Select(rule =>
            {
                if (!Enum.IsDefined(rule.State) || (rule.Domain == null) == (rule.ServiceId == null) ||
                    rule.ServiceId is Guid id && !serviceIds.Contains(id)) throw new ArgumentException("Invalid program rule");
                var domain = rule.Domain == null ? null : DomainName.Normalize(rule.Domain);
                if (domain == "") throw new ArgumentException("Invalid program domain");
                return rule with { Domain = domain };
            }).OrderBy(r => r.RuleId).ToImmutableArray();
        }
        var groups = value.Groups.Select(g => g with { Name = Label(g.Name), DeviceIds = References(g.DeviceIds, ids), Rules = Rules(g.Rules) })
            .OrderBy(g => g.GroupId).ToImmutableArray();
        var groupIds = groups.Select(g => g.GroupId).ToHashSet();
        var profiles = value.Profiles.Select(p =>
        {
            var d = References(p.DeviceIds, ids); var g = References(p.GroupIds, groupIds);
            if (p.AppliesGlobally ? d.Length + g.Length != 0 : d.Length + g.Length == 0)
                throw new ArgumentException("Profile scope must be explicit");
            return p with { Name = Label(p.Name), DeviceIds = d, GroupIds = g, Rules = Rules(p.Rules) };
        }).OrderBy(p => p.ProfileId).ToImmutableArray();
        var profileIds = profiles.Select(p => p.ProfileId).ToHashSet();
        var schedules = value.Schedules.Select(s =>
        {
            if (!profileIds.Contains(s.ProfileId) || s.Days.IsDefault || s.Days.Length is < 1 or > 7 ||
                s.Days.Any(d => !Enum.IsDefined(d)) || s.StartMinute is < 0 or > 1439 || s.EndMinute is < 0 or > 1439 ||
                s.StartMinute == s.EndMinute) throw new ArgumentException("Invalid schedule");
            TimeZoneInfo zone;
            try { zone = TimeZoneInfo.FindSystemTimeZoneById(s.TimeZoneId); }
            catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException or ArgumentNullException)
            { throw new ArgumentException("Invalid schedule time zone", e); }
            var zoneId = TimeZoneInfo.TryConvertWindowsIdToIanaId(zone.Id, out var iana) ? iana : zone.Id;
            return s with { Name = Label(s.Name), TimeZoneId = zoneId, Days = s.Days.Distinct().Order().ToImmutableArray() };
        }).OrderBy(s => s.ScheduleId).ToImmutableArray();
        return new(groups, services, profiles, schedules);
    }
}
