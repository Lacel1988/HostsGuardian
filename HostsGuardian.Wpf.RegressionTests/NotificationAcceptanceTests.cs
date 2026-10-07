using System.IO;
using HostsGuardian.Core.Models;
using HostsGuardian.Wpf.Services;
using System.Collections.Immutable;

internal static class NotificationAcceptanceTests
{
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    private sealed class Sink : IDesktopNotificationSink
    {
        public bool Available => true;
        public int Count; public int Removed;
        public void Show(NotificationItem notification) { Count++; }
        public void Remove(string key) { Removed++; }
    }
    public static void Run()
    {
        var now = new DateTimeOffset(2026, 10, 6, 17, 50, 1, TimeSpan.Zero);
        var device = Guid.NewGuid(); var service = Guid.NewGuid(); var profile = Guid.NewGuid(); var schedule = Guid.NewGuid();
        var rule = new ProgramRule(Guid.NewGuid(), null, service, DeviceDomainRuleState.Allow);
        var policy = new FullDnsPolicy(3, ["fixture.invalid"], [new(device, "Device", null, "fixture", "explicit") { Metadata = new("Gabó", "", "Laptop", "") }], [])
        { Program = new([], [new(service, "Fixture service", "1", ["fixture.invalid"])],
            [new(profile, "Evening", true, false, false, [device], [], [rule])],
            [new(schedule, profile, "Evening", true, "UTC", [DayOfWeek.Tuesday], 17*60, 18*60)]) };
        var read = new FullPolicyRead(5, policy, "fixture");
        var status = new DnsServiceStatus { SnapshotUtc = now, InstanceId = "fixture", PolicyRevision = 5, FilteringEnabled = true };
        var bindings = new BindingRead(1, [new("192.0.2.1", "fixture", device, "explicit", now.AddMinutes(-1), now.AddMinutes(20), true)]);
        var warning = ScheduleNotificationFeed.Find(read, bindings, status, status, now).Single();
        Check(warning.DeviceName == "Gabó" && warning.Minutes == 10 && warning.LocalTime == "18:00" && warning.TransitionUtc == new DateTimeOffset(2026,10,6,18,0,0,TimeSpan.Zero), "Wrong affected identity or transition timing");
        Check(ScheduleNotificationFeed.Find(read, bindings, status, status, now.AddSeconds(31)).Count == 0, "Stale status forecast");
        Check(ScheduleNotificationFeed.Find(read, bindings, status, new() { InstanceId="fixture", PolicyRevision=6, FilteringEnabled=true, SnapshotUtc=now }, now).Count == 0, "Mixed revision forecast");
        Check(ScheduleNotificationFeed.Find(read, new(1, []), status, status, now).Count == 0, "Unvalidated device predicted");
        Check(ScheduleNotificationFeed.Find(read with { Policy = policy with { Overrides = [new(device,"fixture.invalid",DeviceDomainRuleState.Allow)] } }, bindings,status,status,now).Count == 0,"Device override incorrectly predicted Block");
        Check(ScheduleNotificationFeed.Find(read with { Policy = policy with { Program = policy.Program with { Schedules = [] } } },bindings,status,status,now).Count == 0,"Cancelled schedule warned");
        status.EmergencySafeMode=true;
        Check(ScheduleNotificationFeed.Find(read,bindings,status,status,now).Count == 0,"Safe Mode wrongly warned enforcement");
        status.EmergencySafeMode=false;
        var early = now.AddSeconds(-2); var earlyStatus = new DnsServiceStatus { SnapshotUtc=early,InstanceId="fixture",PolicyRevision=5,FilteringEnabled=true };
        Check(ScheduleNotificationFeed.Find(read,bindings,earlyStatus,earlyStatus,early).Count == 0,"Warning more than 10 minutes early");
        Console.WriteLine("PASS effective scheduled warning timing, bound identity, override/Safe Mode, cancellation and coherent readback gates");

        var temporary=Path.Combine(Path.GetTempPath(),"HostsGuardian-notifications-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        var journalPath=Path.Combine(temporary,"delivery.json");
        var journal=new NotificationDeliveryJournal(journalPath);
        Check(journal.Reserve(warning.Key,warning.TransitionUtc,now),"First warning suppressed");
        Check(!new NotificationDeliveryJournal(journalPath).Reserve(warning.Key,warning.TransitionUtc,now),"Restart duplicate delivered");
        Check(!File.ReadAllText(journalPath).Contains("Gabó") && !File.ReadAllText(journalPath).Contains("192.0.2.1"),"Journal identity leak");
        File.WriteAllText(journalPath,"corrupt");
        Check(!new NotificationDeliveryJournal(journalPath).Reserve("new",now.AddMinutes(1),now),"Corrupt journal reset caused spam");
        Console.WriteLine("PASS bounded durable notification suppression across restart, privacy and fail-quiet corrupt-state handling");
        var sink=new Sink(); var prefs=new UiPreferences(Path.Combine(temporary,"preferences.json"));
        var center=new NotificationCenter(prefs,sink,()=>false);
        center.Observe("health",true,NotificationCategory.EngineDns,NotificationSeverity.Critical,"Engine unavailable","", "Router");
        center.Observe("health",true,NotificationCategory.EngineDns,NotificationSeverity.Critical,"Engine unavailable","", "Router");
        center.Observe("health",false,NotificationCategory.EngineDns,NotificationSeverity.Critical,"","","Router");
        Check(sink.Count==2,"Meaningful recovery suppressed or repeated health spam");
        center.Publish(new(warning.Key,NotificationCategory.Policy,NotificationSeverity.Warning,"Scheduled access ending","", "Devices") { ExpiresAtUtc=warning.TransitionUtc });
        center.Withdraw(warning.Key); Check(sink.Removed==2 && center.Items.Last().Resolved,"Cancelled warning not withdrawn");
        Console.WriteLine("PASS native transport routing for health/recovery and cancelled warning removal without policy actions");
    }
}
