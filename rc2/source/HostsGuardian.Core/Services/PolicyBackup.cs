using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public sealed record PolicyBackupDocument(int BackupSchema, string Product, FullDnsPolicy Policy, string Sha256);
public static class PolicyBackup
{
    private static readonly JsonSerializerOptions Options = new()
    { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private static string Digest(FullDnsPolicy policy) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(policy, Options)));
    public static string Export(FullDnsPolicy policy)
    {
        policy = PolicyCanonicalization.Canonicalize(policy);
        return JsonSerializer.Serialize(new PolicyBackupDocument(1, "HostsGuardian policy", policy, Digest(policy)), Options);
    }
    public static FullDnsPolicy Import(string json)
    {
        if (System.Text.Encoding.UTF8.GetByteCount(json) > 1048576) throw new ArgumentException("Backup exceeds size limit");
        using var document = JsonDocument.Parse(json);
        void Unique(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                { if (!names.Add(property.Name)) throw new ArgumentException("Duplicate backup property"); Unique(property.Value); }
            }
            else if (element.ValueKind == JsonValueKind.Array) foreach (var item in element.EnumerateArray()) Unique(item);
        }
        Unique(document.RootElement);
        var backup = JsonSerializer.Deserialize<PolicyBackupDocument>(json, Options);
        if (backup == null || backup.BackupSchema != 1 || backup.Product != "HostsGuardian policy" || backup.Policy == null)
            throw new ArgumentException("Unsupported backup schema");
        var canonical = PolicyCanonicalization.Canonicalize(backup.Policy);
        if (Digest(canonical) != backup.Sha256) throw new ArgumentException("Backup hash mismatch");
        return canonical;
    }
    public static string Preview(FullDnsPolicy before, FullDnsPolicy after, Func<string, object[], string>? format = null)
    {
        before = PolicyCanonicalization.Canonicalize(before); after = PolicyCanonicalization.Canonicalize(after);
        string Text(string template, params object[] values) => format?.Invoke(template, values) ?? string.Format(System.Globalization.CultureInfo.InvariantCulture, template, values);
        var lines = new List<string> { Text("Policy schema: {0} -> {1}", before.SchemaVersion, after.SchemaVersion) };
        foreach (var domain in after.GlobalBlockedDomains.Except(before.GlobalBlockedDomains)) lines.Add(Text("Global block added: {0}", domain));
        foreach (var domain in before.GlobalBlockedDomains.Except(after.GlobalBlockedDomains)) lines.Add(Text("Global block removed: {0}", domain));
        lines.Add(Text("Devices: {0} -> {1}; overrides: {2} -> {3}", before.Devices.Length, after.Devices.Length, before.Overrides.Length, after.Overrides.Length));
        lines.Add(Text("Groups: {0} -> {1}; services: {2} -> {3}", before.Program?.Groups.Length ?? 0, after.Program?.Groups.Length ?? 0, before.Program?.Services.Length ?? 0, after.Program?.Services.Length ?? 0));
        lines.Add(Text("Profiles: {0} -> {1}; schedules: {2} -> {3}", before.Program?.Profiles.Length ?? 0, after.Program?.Profiles.Length ?? 0, before.Program?.Schedules.Length ?? 0, after.Program?.Schedules.Length ?? 0));
        foreach (var device in after.Devices)
            if (JsonSerializer.Serialize(device,Options) != JsonSerializer.Serialize(before.Devices.FirstOrDefault(x => x.DeviceId == device.DeviceId),Options))
                lines.Add(Text("Device added/metadata changed: {0} ({1})", device.Name, device.DeviceId));
        foreach (var removed in before.Devices.Where(d => !after.Devices.Any(a => a.DeviceId == d.DeviceId)))
            lines.Add(Text("Device removed: {0} ({1})", removed.Name, removed.DeviceId));
        if (JsonSerializer.Serialize(before.Program,Options) != JsonSerializer.Serialize(after.Program,Options))
            lines.Add(Text("Group/catalog/profile/schedule definitions changed; use decision preview for a selected device/domain/time."));
        if (JsonSerializer.Serialize(before.Overrides,Options) != JsonSerializer.Serialize(after.Overrides,Options))
            lines.Add(Text("Device overrides changed; affected device IDs: {0}", string.Join(", ", before.Overrides.Select(x=>x.DeviceId).Concat(after.Overrides.Select(x=>x.DeviceId)).Distinct())));
        void Definitions<T>(IEnumerable<T> previous, IEnumerable<T> next, Func<T, Guid> identity, Func<T, string> name, string kind)
        {
            var oldValues = previous.ToDictionary(identity); var newValues = next.ToDictionary(identity);
            foreach (var id in oldValues.Keys.Union(newValues.Keys).Order())
            {
                var had = oldValues.TryGetValue(id, out var oldValue); var has = newValues.TryGetValue(id, out var newValue);
                if (had && has && JsonSerializer.Serialize(oldValue, Options) == JsonSerializer.Serialize(newValue, Options)) continue;
                lines.Add(Text("{0}: {1} ({2}); {3}", Text(kind), name(has ? newValue! : oldValue!), id,
                    Text(!had ? "Added" : !has ? "Removed" : "Changed")));
            }
        }
        var oldProgram = before.Program ?? PolicyProgram.Empty; var newProgram = after.Program ?? PolicyProgram.Empty;
        Definitions(oldProgram.Groups, newProgram.Groups, g => g.GroupId, g => g.Name, "Device Group");
        Definitions(oldProgram.Services, newProgram.Services, s => s.ServiceId, s => s.Name + " / " + s.DefinitionRevision, "Service catalog");
        Definitions(oldProgram.Profiles, newProgram.Profiles, p => p.ProfileId, p => p.Name, "Profiles");
        Definitions(oldProgram.Schedules, newProgram.Schedules, s => s.ScheduleId, s => s.Name + " / " + s.TimeZoneId + " / " + s.StartMinute + "-" + s.EndMinute, "Schedules");
        if (JsonSerializer.Serialize(oldProgram, Options) != JsonSerializer.Serialize(newProgram, Options))
        {
            var potential = oldProgram.Groups.Concat(newProgram.Groups).SelectMany(g => g.DeviceIds)
                .Concat(oldProgram.Profiles.Concat(newProgram.Profiles).SelectMany(p => p.DeviceIds));
            if (oldProgram.Profiles.Concat(newProgram.Profiles).Any(p => p.AppliesGlobally))
                potential = potential.Concat(before.Devices.Concat(after.Devices).Select(d => d.DeviceId));
            lines.Add(Text("Potentially affected DeviceIds: {0}. Review the selected domain/time decision before delivery.", string.Join(", ", potential.Distinct().Order())));
        }
        lines.Add(Text("This is a local draft preview, not confirmed Engine policy. DNS catalog mappings are incomplete service evidence."));
        return string.Join(Environment.NewLine,lines);
    }
}
