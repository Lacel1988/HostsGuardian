using System.Collections.Immutable;
using System.Net;
using HostsGuardian.Core.Models;
using HostsGuardian.DnsEngine;

internal static class IntegratedPolicyTests
{
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    public static void Run(Action<string, Action> test, string directory)
    {
        var deviceA = Guid.Parse("00000000-0000-0000-0000-000000000001");
        var deviceB = Guid.Parse("00000000-0000-0000-0000-000000000002");
        var now = DateTimeOffset.UtcNow;
        var full = FullPolicyValidation.Canonicalize(new(2, ["blocked.invalid"],
            [new(deviceA, "TV", "02-aa-bb-cc-dd-01", "lan", "explicit-review"), new(deviceB, "Phone", null, "lan", "explicit-review")],
            [new(deviceA, "blocked.invalid", DeviceDomainRuleState.Allow), new(deviceB, "allowed.invalid", DeviceDomainRuleState.Block),
             new(deviceA, "child.blocked.invalid", DeviceDomainRuleState.Block), new(deviceA, "inherit.child.blocked.invalid", DeviceDomainRuleState.Inherit)]));
        var bindings = new AddressBindingStore();
        AddressBindingObservation Binding(string ip, Guid id, bool valid = true) => new(ip, null, id, "fixture", now.AddMinutes(-1), now.AddMinutes(5), valid);
        bindings.Replace(new(0, [Binding("192.0.2.1", deviceA), Binding("192.0.2.2", deviceB), Binding("192.0.2.3", deviceA)]));
        var state = new PolicyStateSnapshot("Restored", true, 1, 1, false, "", "") { Policy = full };
        EffectivePolicyExplanation Explain(string ip, string domain, int port = 1000, PolicyStateSnapshot? snapshot = null)
            => DevicePolicyEvaluator.Explain(snapshot ?? state, full, bindings.Read(), new(DnsTransport.Udp, ip, port, now, null), domain, now);
        test("Integrated WPF operational states distinguish evidence and expire authentication/upstream", () =>
        {
            var clock = now;
            var view = new HostsGuardian.Core.Services.EngineStatusPresentation(() => clock);
            Check(view.EngineHost == "UNKNOWN" && view.Management == "UNKNOWN" && view.DnsService == "UNKNOWN", "Initial evidence invented");
            view.Complete(new(ConnectionState.AuthenticationFailed, "Auth error"));
            Check(view.EngineHost == "ONLINE" && view.Management == "AUTH ERROR" && view.Filtering == "Unknown", "Auth error inferred DNS");
            clock += TimeSpan.FromSeconds(31);
            Check(view.EngineHost == "UNKNOWN" && view.Management == "UNKNOWN", "Failure observation never expired");
            var status = new DnsServiceStatus { PolicyLoaded = true, PolicyRevision = 1, FilteringEnabled = true,
                UdpListening = true, TcpListening = false, InstanceId = "fixture", LastUpstreamOutcome = "Response", LastUpstreamSuccessUtc = clock };
            view.Complete(new(ConnectionState.Authenticated, "OK", status), 1);
            Check(view.DnsService == "DEGRADED" && view.PolicyStatus == "SYNCHRONIZED" && view.Upstream == "HEALTHY", "Evidence lost");
            view.InvalidateSelection(); Check(view.PolicyStatus == "CHANGES NOT SENT", "Draft not shown");
            view.BeginRequest(); Check(view.PolicyStatus == "PENDING" && view.DnsService == "UNKNOWN", "Pending assumed current");
        });
        test("Integrated local monitor status is bounded credential-free metadata and has no policy effects", () =>
        {
            var rules = new RuleStore("monitor-fixture");
            var engine = new DnsProxyServer(rules, new EngineConfig());
            var path = Path.Combine(directory, "local-monitor.json");
            var publisher = new LocalMonitorStatusPublisher(engine.RuntimeStatus, path);
            var before = engine.PolicyState.GetSnapshot();
            publisher.PublishOnce();
            using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(path));
            Check(document.RootElement.GetProperty("schemaVersion").GetInt32() == 1 &&
                document.RootElement.GetProperty("processId").GetInt32() == Environment.ProcessId &&
                document.RootElement.GetProperty("events").GetArrayLength() <= 64 && engine.PolicyState.GetSnapshot() == before, "Monitor mutated policy or metadata invalid");
            Check(!File.ReadAllText(path).Contains("credential", StringComparison.OrdinalIgnoreCase), "Monitor exported credential metadata");
        });
        test("Unified Monitor local feed preserves incident identity and recovery without policy effects", () =>
        {
            var engine = new DnsProxyServer(new RuleStore("unified-monitor-fixture"), new EngineConfig());
            var diagnostics = engine.RuntimeStatus.Diagnostics!;
            var before = engine.PolicyState.GetSnapshot();
            var at = DateTimeOffset.UtcNow;
            diagnostics.Health.Evaluate(new DnsServiceStatus { UdpState = "Faulted" }, engine.Telemetry.Counters(), engine.Telemetry.UpstreamLatency.Snapshot(), at);
            var path = Path.Combine(directory, "unified-monitor.json");
            var publisher = new LocalMonitorStatusPublisher(engine.RuntimeStatus, path);
            publisher.PublishOnce();
            using (var document = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(path)))
            {
                var batch = document.RootElement.GetProperty("operationalEvents");
                var events = batch.GetProperty("events");
                Check(batch.GetProperty("instanceId").GetString() == "unified-monitor-fixture" && events.GetArrayLength() == 1,
                    "Local feed lost instance or incident");
                Check(events[0].GetProperty("severity").GetString() == "Critical" &&
                    events[0].GetProperty("occurredAtUtc").GetDateTimeOffset() == at, "Occurrence/severity lost");
            }
            diagnostics.Health.Evaluate(new DnsServiceStatus(), engine.Telemetry.Counters(), engine.Telemetry.UpstreamLatency.Snapshot(), at.AddSeconds(1));
            diagnostics.Health.Evaluate(new DnsServiceStatus(), engine.Telemetry.Counters(), engine.Telemetry.UpstreamLatency.Snapshot(), at.AddSeconds(32));
            publisher.PublishOnce();
            using var recovered = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(path));
            var retained = recovered.RootElement.GetProperty("operationalEvents").GetProperty("events");
            Check(retained.GetArrayLength() == 2 && retained[1].GetProperty("severity").GetString() == "Recovery" &&
                retained[1].GetProperty("recoveryOf").GetString() == retained[0].GetProperty("incidentId").GetString(), "Recovery relationship lost");
            Check(engine.PolicyState.GetSnapshot() == before && new FileInfo(path).Length <= 131072, "Local feed mutated policy or exceeded bound");
        });
        test("Integrated config migration preserves DNS selections credential references and legacy unassigned preferences", () =>
        {
            var path = Path.Combine(directory, "integrated-config.json");
            File.WriteAllText(path, "{\"BlockedDomains\":[{\"Domain\":\"legacy.invalid\",\"HostsBlocked\":true},{\"Domain\":\"dns.invalid\",\"DnsBlocked\":true}],\"DevicePolicies\":[{\"Ip\":\"192.0.2.1\",\"IsBlocked\":true}],\"DnsEngine\":{\"CredentialId\":\"retained-reference\",\"TrustedCertificate\":\"retained-trust\"}}");
            var service = new HostsGuardian.Core.Services.ConfigService(path); var config = service.Load();
            Check(!config.BlockedDomains[0].DnsBlocked && config.BlockedDomains[1].DnsBlocked && config.DeviceDomainPolicy.Overrides.IsEmpty, "Legacy filtering auto-authorized");
            service.Save(config); var restored = service.Load();
            Check(restored.DevicePolicies.Single().IsBlocked && restored.DeviceDomainPolicy.Devices.IsEmpty &&
                restored.DnsEngine.CredentialId == "retained-reference" && restored.DnsEngine.TrustedCertificate == "retained-trust", "Migration lost unassigned preferences or security config");
            const string bad = "{corrupt"; File.WriteAllText(path, bad);
            try { service.Load(); throw new Exception("Invalid config silently reset"); } catch (InvalidDataException) { }
            Check(File.ReadAllText(path) == bad, "Configuration evidence erased");
        });
        test("Integrated unknown clients inherit global and devices have isolated allow/block overrides", () =>
        {
            Check(Explain("192.0.2.99", "blocked.invalid").Blocked, "Unknown bypassed global");
            Check(!Explain("192.0.2.1", "blocked.invalid").Blocked && Explain("192.0.2.2", "blocked.invalid").Blocked, "Allow isolation failed");
            Check(!Explain("192.0.2.1", "allowed.invalid").Blocked && Explain("192.0.2.2", "allowed.invalid").Blocked, "Block isolation failed");
            Check(Explain("192.0.2.1", "blocked.invalid").DeviceId == Explain("192.0.2.3", "blocked.invalid").DeviceId, "Multiple addresses failed");
            Check(Explain("192.0.2.1", "blocked.invalid", 9999) == Explain("192.0.2.1", "blocked.invalid", 1), "Port used as identity");
        });
        test("Integrated most specific override, inherit and parent boundary semantics", () =>
        {
            Check(!Explain("192.0.2.1", "api.blocked.invalid").Blocked, "Parent allow failed");
            Check(Explain("192.0.2.1", "api.child.blocked.invalid").Blocked, "Specific block lost");
            Check(Explain("192.0.2.1", "inherit.child.blocked.invalid").Reason == "GlobalBlock", "Inherit failed");
            Check(!Explain("192.0.2.99", "otherblocked.invalid").Blocked, "Suffix boundary failed");
        });
        test("Integrated Safe Mode bypass preserves full device policy", () =>
        {
            Check(!Explain("192.0.2.2", "allowed.invalid", snapshot: state with { SafeMode = true }).Blocked, "Device rule bypass failed");
            Check(state.Policy == full && state.Revision == 1, "Safe mode erased snapshot");
        });
        test("Integrated concurrent device evaluation is isolated", () =>
        {
            Parallel.For(0, 2000, i => Check(Explain(i % 2 == 0 ? "192.0.2.1" : "192.0.2.2", "blocked.invalid").Blocked == (i % 2 != 0), "Cross-device decision"));
        });
        test("Integrated mapping expiry conflict scope reassignment and unregistered addresses fail unknown", () =>
        {
            var store = new AddressBindingStore();
            store.Replace(new(0, [Binding("192.0.2.1", deviceA), Binding("192.0.2.1", deviceB)]));
            var context = new DnsRequestContext(DnsTransport.Tcp, "192.0.2.1", 100, now, null);
            Check(AddressBindingStore.Resolve(store.Read(), full, context, now).DeviceId == null, "Conflict picked device");
            Check(!store.Replace(new(0, [])), "Stale generation accepted");
            store.Replace(new(1, [Binding("192.0.2.1", deviceB)]));
            Check(AddressBindingStore.Resolve(store.Read(), full, context, now).DeviceId == deviceB, "Reassignment failed");
            Check(AddressBindingStore.Resolve(store.Read(), full, context, now.AddMinutes(6)).DeviceId == null, "Stale identity reused");
            Check(AddressBindingStore.Resolve(store.Read(), full, context with { NetworkScope = "another" }, now).DeviceId == null, "Scope leaked");
            Check(AddressBindingStore.Resolve(store.Read(), full, context with { SourceAddress = "::1" }, now).DeviceId == null, "IPv6 enforcement claimed");
            store.Replace(new(2, [Binding("192.0.2.1", Guid.NewGuid())]));
            Check(AddressBindingStore.Resolve(store.Read(), full, context, now).DeviceId == null, "Unregistered device selected");
        });
        test("Integrated duplicate MAC evidence is ambiguous rather than arbitrarily assigned", () =>
        {
            var duplicate = full with { Devices = full.Devices.SetItem(1, full.Devices[1] with { Mac = full.Devices[0].Mac }) };
            Check(AddressBindingStore.Resolve(bindings.Read(), duplicate, new(DnsTransport.Udp, "192.0.2.1", 0, now, null), now).DeviceId == null, "Duplicate MAC selected");
        });
        test("Integrated durable full policy readback revisions restore and legacy edits preserve overrides", () =>
        {
            var path = Path.Combine(directory, "integrated-policy.json");
            var policy = new PolicyApplicationService(new("integrated"), new(path));
            Check(policy.ReplaceFull(new(0, full)).Success, "Full commit failed");
            Check(!policy.ReplaceFull(new(0, FullDnsPolicy.Empty)).Success && policy.ReadFullPolicy().Revision == 1, "Lost optimistic concurrency");
            var bytes = File.ReadAllBytes(path); policy.SetSafeMode(true);
            Check(File.ReadAllBytes(path).SequenceEqual(bytes) && policy.ReadFullPolicy().Revision == 1, "Safe Mode persisted");
            Check(policy.Replace(["new.invalid"]).Success && policy.ReadFullPolicy().Policy.Overrides.SequenceEqual(full.Overrides), "Legacy replace erased overrides");
            Check(policy.Add(["added.invalid"]).Success && policy.Remove("new.invalid").Success, "Legacy edits failed");
            var restored = new PolicyApplicationService(new("restart"), new(path));
            Check(restored.ReadFullPolicy().Revision == 4 && restored.ReadFullPolicy().Policy.Devices.SequenceEqual(full.Devices)
                && restored.ReadFullPolicy().Policy.Overrides.SequenceEqual(full.Overrides), "Restart lost device policy");
            Check(bindings.Read().Generation == 1 && restored.ReadFullPolicy().Revision == 4, "Mapping advanced policy revision");
        });
        test("Integrated schema1 restore migrates in memory without rewriting evidence", () =>
        {
            var path = Path.Combine(directory, "integrated-schema1.json");
            const string old = "{\"schemaVersion\":1,\"revision\":7,\"domains\":[\"blocked.invalid\"]}";
            File.WriteAllText(path, old);
            var policy = new PolicyApplicationService(new("migration"), new(path));
            Check(policy.ReadFullPolicy().Policy.SchemaVersion == 2 && policy.ReadFullPolicy().Revision == 7 && File.ReadAllText(path) == old, "Migration mutated restore");
            Check(policy.Add(["new.invalid"]).Revision == 8 && File.ReadAllText(path).Contains("\"schemaVersion\":2"), "Next commit not migrated");
        });
        test("Integrated invalid device policy validates before mutation and failed storage retains full policy", () =>
        {
            var path = Path.Combine(directory, "integrated-failure.json");
            var policy = new PolicyApplicationService(new("failure"), new(path));
            policy.ReplaceFull(new(0, full));
            var before = policy.ReadFullPolicy();
            foreach (var invalid in new[] { full with { SchemaVersion = 99 }, full with { Devices = [full.Devices[0], full.Devices[0]] }, full with { Overrides = [new(Guid.NewGuid(), "example.invalid", DeviceDomainRuleState.Block)] } })
            {
                try { policy.ReplaceFull(new(1, invalid)); throw new Exception("Invalid policy accepted"); } catch (ArgumentException) { }
                Check(policy.ReadFullPolicy() == before, "Validation changed full policy");
            }
            using var locked = new PolicyWriteFailureFixture(path);
            Check(!policy.ReplaceFull(new(1, FullDnsPolicy.Empty)).Success && policy.ReadFullPolicy() == before, "Failed persistence lost full policy");
        });
    }
}
