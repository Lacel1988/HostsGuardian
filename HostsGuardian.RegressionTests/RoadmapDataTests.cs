using System.Collections.Immutable;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class RoadmapDataTests
{
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    public static void Run(Action<string, Action> test, string directory)
    {
        var device = Guid.NewGuid(); var service = Guid.NewGuid();
        var policy = PolicyCanonicalization.Canonicalize(new FullDnsPolicy(3, ["fixture.invalid"],
            [new(device, "Fixture", null, "fixture", "explicit") { Metadata = new("Alias", "Owner", "IoT", "Room") }], [])
            { Program = new([], [new(service, "Fixture service", "user-1", ["fixture.invalid"])], [], []) });
        var now = DateTimeOffset.UtcNow;
        var decision = new EffectivePolicyExplanation(2, 1, device, "Validated", "fixture.invalid", DeviceDomainRuleState.Allow, false, "DeviceOverride");
        test("Roadmap backup roundtrip retains schema, stable identities and user catalog without credentials", () =>
        {
            var backup = PolicyBackup.Export(policy); var restored = PolicyBackup.Import(backup);
            Check(PolicyBackup.Export(restored) == backup && restored.Devices[0].DeviceId == device, "Backup lost canonical policy");
            Check(!backup.Contains("credential", StringComparison.OrdinalIgnoreCase) && !backup.Contains("certificate", StringComparison.OrdinalIgnoreCase), "Backup contains security configuration");
        });
        test("Roadmap corrupt incompatible duplicate and tampered backups never overwrite valid policy", () =>
        {
            var backup = PolicyBackup.Export(policy); var path = Path.Combine(directory, "backup-preservation.json");
            new PolicyPersistence(path).Commit(new(2, policy.GlobalBlockedDomains.ToArray()) { Policy = policy }, false);
            var before = File.ReadAllBytes(path);
            foreach (var invalid in new[] { "{", "{}", backup.Replace("\"backupSchema\":1", "\"backupSchema\":9"),
                backup.Replace("Fixture service", "Tampered service"), backup.Replace("\"backupSchema\":1", "\"backupSchema\":1,\"backupSchema\":1"),
                backup.Replace("\"product\":", "\"unknownField\":0,\"product\":") })
            {
                var rejected = false;
                try { PolicyBackup.Import(invalid); } catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException) { rejected = true; }
                Check(rejected && before.SequenceEqual(File.ReadAllBytes(path)), "Invalid backup accepted or valid policy changed");
            }
        });
        test("Roadmap local schema3 configuration roundtrip preserves richer policy without Engine delivery", () =>
        {
            var path = Path.Combine(directory, "roadmap-config.json"); var config = new ConfigService(path);
            config.Save(new AppConfig { DeviceDomainPolicy = policy });
            Check(PolicyBackup.Export(config.Load().DeviceDomainPolicy) == PolicyBackup.Export(policy), "Configuration lost policy program");
        });
        test("Roadmap activity counts successful blocked and failed outcomes separately without raw addresses", () =>
        {
            var store = new ProductActivityStore();
            store.Record(policy, decision, "Allowed", now); store.Record(policy, decision, "Blocked", now); store.Record(policy, decision, "Failed", now);
            var read = store.Read(now); Check(read.Buckets.Length == 1, "Unexpected bucket duplication");
            var bucket = read.Buckets[0];
            Check(bucket.Allowed == 1 && bucket.Blocked == 1 && bucket.Failed == 1 && bucket.DeviceId == device && bucket.ServiceId == service, "Outcome/identity aggregation lost");
            var estimate = UsageEstimation.Estimate(read).Single(); Check(estimate.EstimatedActivityMinutes == 5, "Estimate fabricated screen time");
            var wire = JsonSerializer.Serialize(read); Check(!wire.Contains("fixture.invalid") && !wire.Contains("Address"), "Raw DNS/address telemetry leaked to product aggregates");
        });
        test("Roadmap blocked and failed DNS alone never count as usage or mutate policy", () =>
        {
            var store = new ProductActivityStore(); var before = PolicyBackup.Export(policy);
            store.Record(policy, decision, "Blocked", now); store.Record(policy, decision, "Failed", now);
            Check(UsageEstimation.Estimate(store.Read(now)).Length == 0 && PolicyBackup.Export(policy) == before, "Estimate became punitive policy or counted blocked requests as usage");
        });
        test("Roadmap activity TTL and cardinality remain bounded and restart clears activity", () =>
        {
            var store = new ProductActivityStore();
            for (var i = 0; i < 300; i++) store.Record(policy, decision with { DeviceId = Guid.NewGuid() }, "Allowed", now);
            Check(store.Read(now).Buckets.Length == 256, "Activity cardinality unbounded");
            Check(store.Read(now.AddHours(25)).Buckets.Length == 0 && new ProductActivityStore().Read(now).Buckets.Length == 0, "Ephemeral activity survived TTL/restart");
        });
        test("Roadmap overlapping service definitions expose uncertain usage without summing it as screen time", () =>
        {
            var overlapping = policy with { Program = policy.Program! with { Services = policy.Program.Services.Add(new(Guid.NewGuid(), "Other", "user-2", ["fixture.invalid"])) } };
            var store = new ProductActivityStore(); store.Record(overlapping, decision, "Allowed", now);
            var read = store.Read(now); Check(read.Buckets.Length == 2 && read.Buckets.All(b => b.AmbiguousService), "Overlapping attribution hidden");
            Check(UsageEstimation.Estimate(read).All(e => e.Confidence == "Ambiguous"), "Overlapping service usage falsely certain");
        });
        test("Roadmap audit keeps revision/outcome/hash evidence and bounds durable history", () =>
        {
            var path = Path.Combine(directory, "roadmap-audit.jsonl");
            var record = new PolicyAuditRecord(now, "PolicyCommit", "Management boundary; user identity unavailable", 1, 2, "Success", new string('A', 64));
            File.WriteAllLines(path, Enumerable.Range(0, 1000).Select(i => JsonSerializer.Serialize(record with { PreviousRevision = i, EffectiveRevision = i + 1 })));
            var audit = new PolicyAuditStore(path); audit.Record(record with { EffectiveRevision = 1001 });
            var read = new PolicyAuditStore(path).Read();
            Check(read.Length == 1000 && read[0].PreviousRevision == 1 && read[^1].EffectiveRevision == 1001, "Audit history bound/order or restart lost");
        });
        test("Roadmap unreadable audit preserves damaged evidence and does not block valid user policy", () =>
        {
            var path = Path.Combine(directory, "roadmap-corrupt-audit-policy.json");
            File.WriteAllText(path + ".audit.jsonl", "corrupt preserved evidence");
            var app = new PolicyApplicationService(new RuleStore("audit-fixture"), new PolicyPersistence(path));
            Check(app.ReplaceFull(new(0, policy)).Success, "Audit availability incorrectly prevented policy commit");
            Check(!app.Audit.Available && File.ReadAllText(path + ".audit.jsonl") == "corrupt preserved evidence", "Damaged audit overwritten or concealed");
        });
        test("Roadmap unchanged-count preview identifies affected definitions and stable device scope", () =>
        {
            var group = Guid.NewGuid();
            var before = policy with { Program = policy.Program! with { Groups = [new(group, "Fixture group", [device], [new(Guid.NewGuid(), "fixture.invalid", null, DeviceDomainRuleState.Allow)])] } };
            var after = before with { Program = before.Program! with { Groups = [before.Program.Groups[0] with { Rules = [before.Program.Groups[0].Rules[0] with { State = DeviceDomainRuleState.Block }] }] } };
            var preview = PolicyBackup.Preview(before, after);
            Check(preview.Contains(group.ToString()) && preview.Contains(device.ToString()) && preview.Contains("Changed"), "Same-count policy change hidden in preview");
        });
        test("Roadmap actual DNS evidence retains winning and overridden rules and clearly marks bounded truncation", () =>
        {
            var chain = Enumerable.Range(0, 6).Select(i => new DecisionEvidence(PolicyLayer.DeviceGroup, i == 0 ? DeviceDomainRuleState.Block : DeviceDomainRuleState.Allow, "GroupRule", "fixture.invalid", Guid.NewGuid())).ToImmutableArray();
            var evidence = new DnsObservationStore();
            var context = new DnsRequestContext(DnsTransport.Udp, "192.0.2.1", 10000, now, null);
            evidence.Record(context, decision with { DecisionChain = chain });
            var read = evidence.Read().Single();
            Check(read.EvidenceTruncated && read.DecisionChain.SequenceEqual(chain.Take(4)) && read.PolicyRevision == decision.Revision, "Request explanation provenance lost or truncation concealed");
            var expired = new DnsObservationStore(); expired.Record(context with { ReceivedAtUtc = now.AddMinutes(-16) }, decision);
            Check(expired.Read().Length == 0, "Raw DNS evidence exceeded retention");
        });
        test("Roadmap network context and health export are read-only and do not claim policy synchronization", () =>
        {
            var network = NetworkContextService.Read(); Check(network.WifiIdentity == "Unknown" && network.State is "Unknown" or "BestEffort", "Fabricated Wi-Fi identity");
            var result = new ConnectionResult(ConnectionState.Unreachable, "sanitized");
            var summary = HealthSummary.Export(result, true);
            Check(summary.Contains("Unknown/unconfirmed") && !summary.Contains("ApiToken") && !summary.Contains("TrustedCertificate"), "False synchronization or credential export");
        });
    }
}
