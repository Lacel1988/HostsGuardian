using System.Collections.Immutable;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.Wpf.Services;
using L = HostsGuardian.Wpf.Localization.LocalizationService;

internal static class RoadmapUxTests
{
    public static void Run()
    {
        var device = Guid.NewGuid(); var group = Guid.NewGuid();
        var policy = new FullDnsPolicy(3, [], [new(device, "Fixture", null, "fixture", "explicit")], [])
        { Program = new([new(group, "Work", [device], [])], [], [], []) };
        var session = new PolicyDraftSession(policy); var before = PolicyBackup.Export(session.Policy);
        foreach (var invalid in new[] { "{}", "corrupt" })
        {
            try { session.Restore(invalid); throw new Exception("Invalid restore accepted"); }
            catch (Exception e) when (e is ArgumentException or System.Text.Json.JsonException) { }
            if (before != PolicyBackup.Export(session.Policy)) throw new Exception("Invalid restore changed valid draft");
        }
        try { session.Replace(policy with { Program = policy.Program! with { Groups = [policy.Program.Groups[0] with { DeviceIds = [Guid.NewGuid()] }] } }); throw new Exception("Invalid group reference accepted"); }
        catch (ArgumentException) { }
        var writes = 0; session.Save(_ => writes++);
        if (writes != 1 || before != PolicyBackup.Export(session.Policy)) throw new Exception("Authoring silently delivered or changed policy");
        Console.WriteLine("PASS WPF authoring session rejects invalid restore/reference edits and requires explicit local save");

        var previous = L.Instance.Language;
        try
        {
            L.Instance.ChangeLanguage("hu", false);
            var preview = PolicyBackup.Preview(FullDnsPolicy.Empty, policy, (text, values) => L.F(text, values));
            if (!preview.Contains("Szabályzatséma") || !preview.Contains("Csoportok") || !preview.Contains(device.ToString())) throw new Exception("Preview localization/provenance missing");
        }
        finally { L.Instance.ChangeLanguage(previous, false); }
        Console.WriteLine("PASS Hungarian policy diff preview preserves technical identity and local/unconfirmed semantics");

        var center = new NotificationCenter();
        HealthComponent[] Components(string state) => new[] { "Listeners", "Management", "Upstream", "Processing", "Capacity", "Persistence" }
            .Select(c => new HealthComponent(c, c == "Upstream" ? state : "Healthy", state == "Healthy" ? null : "incident", DateTimeOffset.UtcNow)).ToArray();
        void Observe(string state) => OperationalNotificationObserver.Observe(center, new(1, "fixture", 1, false, [], Components(state)));
        Observe("Degraded"); Observe("Degraded");
        if (center.Items.Count != 1) throw new Exception("Component refresh flooded notifications");
        Observe("Critical"); if (!center.HasCritical || center.Items.Count != 2) throw new Exception("Critical escalation concealed");
        Observe("Healthy"); if (center.HasCritical) throw new Exception("Confirmed recovery did not resolve banner");
        var count = center.Items.Count; Observe("Critical"); Observe("Critical");
        if (!center.HasCritical || center.Items.Count != count) throw new Exception("Repeated flap was hidden or flooded history");
        Console.WriteLine("PASS actionable component notification deduplication, escalation, confirmed recovery and flap rate control");
    }
}
