using System.Collections.Immutable;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public sealed record GlobalDomainChange(FullPolicyConfirmation Confirmation, bool AlreadyCurrent, bool Blocked)
{
    public bool Stored => Confirmation.Confirmed;
    public bool Applied => Stored && Confirmation.Connection.Transport is
        { PolicyLoaded: true, FilteringEnabled: true, EmergencySafeMode: false, PersistenceFault: "" };
    // Policy readback is not an end-to-end DNS or application test.
}

public sealed partial class DnsEngineService
{
    /// <summary>Only one explicit global intention. Fresh authoritative policy preserves all unrelated state.</summary>
    public async Task<GlobalDomainChange> SetGlobalDomainAsync(DnsEngineConfig config, string domain, bool blocked,
        CancellationToken cancellationToken = default)
    {
        var name = DomainName.Normalize(domain);
        if (name.Length == 0) return new(new(new(ConnectionState.InvalidSettings, "Invalid domain"), null, false), false, blocked);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(40));
        for (var attempt = 0; attempt < 2; attempt++)
        {
            deadline.Token.ThrowIfCancellationRequested();
            var read = await ReadFullPolicyAsync(config, deadline.Token);
            if (!read.Connection.Ok || read.Policy is null) return new(new(read.Connection, null, false), false, blocked);
            var current = read.Policy;
            if (current.Policy.GlobalBlockedDomains.Contains(name) == blocked)
            {
                var status = await TestConnectionAsync(config, deadline.Token);
                return new(new(status, current, true, current.Revision), true, blocked);
            }
            var domains = current.Policy.GlobalBlockedDomains.Where(d => d != name);
            if (blocked) domains = domains.Append(name);
            var outgoing = PolicyCanonicalization.Canonicalize(current.Policy with { GlobalBlockedDomains = domains.ToImmutableArray() });
            var result = await ReplaceFullPolicyAsync(config, new(current.Revision, outgoing, current.InstanceId), deadline.Token);
            // Only a definite rejected CAS may be retried. Never replay an uncertain write/timeout/readback failure.
            if (result.Connection.HttpStatusCode == 409 && attempt == 0) continue;
            return new(result, false, blocked);
        }
        throw new InvalidOperationException("Bounded policy reconciliation exhausted");
    }
}
