using System.IO;
using System.Security.Cryptography;
using System.Text;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using L = HostsGuardian.Wpf.Localization.LocalizationService;
namespace HostsGuardian.Wpf.Services;

public sealed record ScheduleWarning(string Key, Guid DeviceId, Guid ServiceId, string DeviceName,
    string ServiceName, DateTimeOffset TransitionUtc, string LocalTime, int Minutes);

/// <summary>Read-only prediction from a coherent authenticated Engine snapshot, never a local draft.</summary>
public sealed class ScheduleNotificationFeed
{
    private DateTimeOffset _next;
    private bool _pending;
    private readonly HashSet<string> _active = new();
    public static IReadOnlyList<ScheduleWarning> Find(FullPolicyRead read, BindingRead bindings,
        DnsServiceStatus before, DnsServiceStatus after, DateTimeOffset now)
    {
        if (read.Policy.SchemaVersion != 3 || read.Policy.Program is not { } program || read.Revision == null ||
            before.InstanceId != read.InstanceId || after.InstanceId != read.InstanceId || string.IsNullOrEmpty(read.InstanceId) ||
            before.PolicyRevision != read.Revision || after.PolicyRevision != read.Revision ||
            !before.FilteringEnabled || !after.FilteringEnabled || before.EmergencySafeMode || after.EmergencySafeMode ||
            before.SnapshotUtc is not { } first || after.SnapshotUtc is not { } last || last < first ||
            last - first > TimeSpan.FromSeconds(15) || (now - last).Duration() > TimeSpan.FromSeconds(30)) return [];
        var result = new List<ScheduleWarning>();
        var start = new DateTimeOffset(last.Year, last.Month, last.Day, last.Hour, last.Minute, 0, last.Offset).ToUniversalTime();
        foreach (var device in read.Policy.Devices.Where(d => bindings.Observations.Any(b => b.DeviceId == d.DeviceId && b.Validated && b.ObservedAtUtc <= last && b.ExpiresAtUtc > last)))
        foreach (var service in program.Services.Where(s => !s.Domains.IsEmpty))
        {
            var current = service.Domains.Select(domain => PolicyDecision.Explain(read.Policy, device.DeviceId, domain, last).Winner).ToArray();
            if (current.Any(w => w.State != DeviceDomainRuleState.Allow) || !current.Any(w => w.ScheduleId != null)) continue;
            for (var minute = 1; minute <= 10; minute++)
            {
                var transition = start.AddMinutes(minute);
                if (service.Domains.Any(domain => PolicyDecision.Explain(read.Policy, device.DeviceId, domain, transition).Winner.State != DeviceDomainRuleState.Block)) continue;
                var scheduleId = current.First(w => w.ScheduleId != null).ScheduleId;
                var zone = TimeZoneInfo.FindSystemTimeZoneById(program.Schedules.Single(s => s.ScheduleId == scheduleId).TimeZoneId);
                var name = string.IsNullOrWhiteSpace(device.Metadata?.Alias) ? device.Name : device.Metadata.Alias;
                result.Add(new($"schedule.{device.DeviceId}.{service.ServiceId}.{transition.ToUnixTimeSeconds()}",
                    device.DeviceId, service.ServiceId, name, service.Name, transition,
                    TimeZoneInfo.ConvertTime(transition, zone).ToString("HH:mm"), (int)Math.Ceiling((transition - last).TotalMinutes)));
                break;
            }
        }
        return result;
    }
    public async Task PollAsync(DnsEngineService engine, DnsEngineConfig config, NotificationCenter center, Func<bool> current)
    {
        if (_pending || DateTimeOffset.UtcNow < _next) return;
        _pending = true; _next = DateTimeOffset.UtcNow.AddSeconds(30);
        IReadOnlyList<ScheduleWarning> warnings = [];
        try
        {
            var before = await engine.TestConnectionAsync(config);
            if (before.Ok && before.Transport?.FilteringEnabled == true)
            {
                var policy = await engine.ReadFullPolicyAsync(config);
                if (policy.Policy?.Policy.SchemaVersion == 3)
                {
                    var bindings = await engine.ReadBindingsAsync(config);
                    var after = await engine.TestConnectionAsync(config);
                    if (bindings.Bindings != null && after.Transport != null)
                        warnings = Find(policy.Policy, bindings.Bindings, before.Transport, after.Transport, DateTimeOffset.UtcNow);
                }
            }
        }
        catch { /* Missing/incoherent evidence cannot produce a prediction. */ }
        finally { _pending = false; }
        if (!current()) warnings = [];
        var keys = warnings.Select(w => w.Key).ToHashSet();
        foreach (var stale in _active.Where(k => !keys.Contains(k)).ToArray()) { center.Withdraw(stale); _active.Remove(stale); }
        foreach (var warning in warnings)
        {
            if (!_active.Add(warning.Key)) continue;
            center.Publish(new(warning.Key, NotificationCategory.Policy, NotificationSeverity.Warning,
                "Scheduled access ending", "{0}: {1} DNS policy changes to Block at {2} (about {3} minutes), if the Engine policy remains unchanged.",
                    "Devices") { ExpiresAtUtc = warning.TransitionUtc,
                    MessageArguments = [warning.DeviceName, warning.ServiceName, warning.LocalTime, warning.Minutes] });
        }
    }
}
