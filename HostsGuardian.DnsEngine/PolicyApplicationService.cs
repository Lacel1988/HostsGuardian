using System.Collections.Immutable;
using HostsGuardian.Core.Models;

namespace HostsGuardian.DnsEngine;

public sealed record PolicyApplicationResult(bool Success, long? Revision, int Count,
    bool Removed = false, string FailureCategory = "", string Message = "");
public sealed record PolicyReadSnapshot(long? Revision, string[] Domains);

/// <summary>Single management mutation boundary: persist first, then publish in memory.</summary>
public sealed class PolicyApplicationService
{
    private readonly RuleStore _rules;
    private readonly PolicyPersistence _persistence;
    private readonly object _mutationGate = new();
    private bool _initialized;
    public EnginePolicyState State { get; }
    public PolicyAuditStore Audit { get; }

    public PolicyApplicationService(RuleStore rules, PolicyPersistence persistence, EnginePolicyState? state = null)
    {
        _rules = rules;
        _persistence = persistence;
        State = state ?? new EnginePolicyState();
        Audit = new PolicyAuditStore(persistence.AuditPath);
    }

    public void InitializeForStartup()
    {
        lock (_mutationGate)
        {
            if (_initialized) return;
            var loaded = _persistence.Load();
            if (loaded.Policy != null)
            {
                _rules.SetBlockedDomains(loaded.Policy.Domains);
                State.Publish(new PolicyStateSnapshot(loaded.State, true, loaded.Policy.Revision,
                    loaded.Policy.Domains.Length, false, "", "") { Policy = loaded.Policy.Policy ?? FullDnsPolicy.Empty with { GlobalBlockedDomains = loaded.Policy.Domains.ToImmutableArray() } });
            }
            else
            {
                _rules.SetBlockedDomains(Array.Empty<string>());
                State.Publish(new PolicyStateSnapshot(loaded.State, false, null, 0, true, "UntrustedPolicy", loaded.Fault) { Policy = FullDnsPolicy.Empty });
                EngineLog.Failure("Policy", "Restore failed; Safe Mode bypass is active");
            }
            _initialized = true;
        }
    }

    public string[] GetBlockedDomains() => ReadPolicy().Domains;

    public PolicyReadSnapshot ReadPolicy()
    {
        lock (_mutationGate)
            return new PolicyReadSnapshot(State.GetSnapshot().Revision, _rules.GetBlockedDomains());
    }

    public PolicyApplicationResult Replace(IEnumerable<string> domains)
    {
        lock (_mutationGate)
        {
            InitializeForStartup();
            return Commit(Normalize(domains), removed: false);
        }
    }

    public PolicyApplicationResult Add(IEnumerable<string> domains)
    {
        lock (_mutationGate)
        {
            InitializeForStartup();
            if (!State.GetSnapshot().Loaded) return Failure("RestoreFault", "Replace authorized policy before adding rules");
            var candidate = _rules.GetBlockedDomains().Concat(Normalize(domains)).Distinct(StringComparer.Ordinal).OrderBy(domain => domain, StringComparer.Ordinal).ToArray();
            return Commit(candidate, removed: false);
        }
    }

    public PolicyApplicationResult Remove(string domain)
    {
        lock (_mutationGate)
        {
            InitializeForStartup();
            if (!State.GetSnapshot().Loaded) return Failure("RestoreFault", "Replace authorized policy before removing rules");
            var normalized = Normalize(new[] { domain })[0];
            var current = _rules.GetBlockedDomains();
            var candidate = current.Where(value => value != normalized).OrderBy(value => value, StringComparer.Ordinal).ToArray();
            return Commit(candidate, candidate.Length != current.Length);
        }
    }

    public PolicyApplicationResult SetSafeMode(bool enabled)
    {
        lock (_mutationGate)
        {
            if (!_initialized) return Failure("NotLoaded", "Policy has not been initialized");
            var current = State.GetSnapshot();
            if (!enabled && !current.Loaded) return Failure("RestoreFault", "Replace authorized policy before leaving Safe Mode");
            State.Publish(current with { SafeMode = enabled, SafeModeReason = enabled ? "ManagementRequested" : "" });
            Audit.Record(new(DateTimeOffset.UtcNow, enabled ? "SafeModeEnter" : "SafeModeExit", "Management boundary; user identity unavailable",
                current.Revision, current.Revision, "Success", Hash(current.Policy)));
            return new PolicyApplicationResult(true, current.Revision, current.RuleCount);
        }
    }

    public FullPolicyRead ReadFullPolicy()
    {
        lock (_mutationGate)
        {
            InitializeForStartup();
            var current = State.GetSnapshot();
            return new(current.Revision, current.Policy ?? FullDnsPolicy.Empty, _rules.InstanceId);
        }
    }

    public PolicyApplicationResult ReplaceFull(FullPolicyReplace request)
    {
        var candidate = FullPolicyValidation.Canonicalize(request.Policy); // validate before any mutation
        lock (_mutationGate)
        {
            InitializeForStartup();
            if (request.ExpectedInstanceId != null && request.ExpectedInstanceId != _rules.InstanceId)
                return Failure("InstanceConflict", "Engine instance changed; read and review before retrying");
            if (State.GetSnapshot().Revision != request.ExpectedRevision)
                return Failure("RevisionConflict", "Policy changed; read and review before retrying");
            return Commit(candidate, false);
        }
    }

    private PolicyApplicationResult Commit(string[] domains, bool removed)
    {
        // Legacy global edits preserve the entire registry and all richer overrides.
        var full = State.GetSnapshot().Policy ?? FullDnsPolicy.Empty;
        return Commit(full with { GlobalBlockedDomains = domains.ToImmutableArray() }, removed);
    }

    private PolicyApplicationResult Commit(FullDnsPolicy candidate, bool removed)
    {
        var current = State.GetSnapshot();
        if (current.Revision == long.MaxValue) return Failure("RevisionExhausted", "Policy revision limit reached");
        var revision = (current.Revision ?? 0) + 1;
        try { _persistence.Commit(new CommittedPolicy(revision, candidate.GlobalBlockedDomains.ToArray()) { Policy = candidate }, preserveUntrustedFile: !current.Loaded); }
        catch (ArgumentException) { return Failure("InvalidPolicy", "Policy exceeds storage constraints"); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            State.Publish(current with { PersistenceFault = "PolicyWriteFailed" });
            EngineLog.Failure("Policy", "Commit failed; previous policy retained");
            return Failure("PersistenceFailure", "Policy could not be committed");
        }
        _rules.SetBlockedDomains(candidate.GlobalBlockedDomains);
        State.Publish(current with
        {
            Loaded = true, Revision = revision, RuleCount = candidate.GlobalBlockedDomains.Length, PersistenceFault = "", Policy = candidate,
            SafeModeReason = current.SafeMode ? "ManagementRequested" : ""
        });
        Audit.Record(new(DateTimeOffset.UtcNow, "PolicyCommit", "Management boundary; user identity unavailable",
            current.Revision, revision, "Success", Hash(candidate)) { Changes = Changes(current.Policy, candidate) });
        return new PolicyApplicationResult(true, revision, candidate.GlobalBlockedDomains.Length, removed);
    }

    private PolicyApplicationResult Failure(string category, string message)
    {
        var current = State.GetSnapshot();
        Audit.Record(new(DateTimeOffset.UtcNow, category, "Management boundary; user identity unavailable",
            current.Revision, current.Revision, "Rejected", Hash(current.Policy)));
        return new PolicyApplicationResult(false, current.Revision, current.RuleCount, FailureCategory: category, Message: message);
    }
    private static string Changes(FullDnsPolicy? before, FullDnsPolicy after)
    {
        before ??= FullDnsPolicy.Empty;
        var changes = new List<string>();
        if (!before.GlobalBlockedDomains.SequenceEqual(after.GlobalBlockedDomains)) changes.Add("Global domains changed");
        if (!before.Devices.SequenceEqual(after.Devices)) changes.Add("Registry or metadata changed");
        if (!before.Overrides.SequenceEqual(after.Overrides)) changes.Add("Device overrides changed");
        if (System.Text.Json.JsonSerializer.Serialize(before.Program) != System.Text.Json.JsonSerializer.Serialize(after.Program)) changes.Add("Groups/catalog/profiles/schedules changed");
        return changes.Count == 0 ? "Semantically unchanged policy delivery" : string.Join("; ", changes);
    }
    private static string Hash(FullDnsPolicy? policy) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(policy ?? FullDnsPolicy.Empty, PolicyPersistence.JsonOptions)));

    private static string[] Normalize(IEnumerable<string> domains)
    {
        var normalized = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var domain in domains)
        {
            var value = DomainName.Normalize(domain);
            if (value.Length == 0) throw new ArgumentException("Invalid selected DNS domain");
            normalized.Add(value);
        }
        return normalized.ToArray();
    }
}
