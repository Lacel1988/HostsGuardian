using System.Collections.Immutable;
using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

public sealed record DnsDecisionObservation(DnsRequestContext Request, Guid? DeviceId, string IdentityState,
    string Domain, long? PolicyRevision, long MappingGeneration, bool Blocked, string Reason)
{
    public ImmutableArray<DecisionEvidence> DecisionChain { get; init; } = [];
    public bool EvidenceTruncated { get; init; }
}

/// <summary>Bounded diagnostic evidence of actual received DNS requests, never identity discovery.</summary>
public sealed class DnsObservationStore
{
    private readonly object _gate = new();
    private readonly Queue<DnsDecisionObservation> _recent = new();
    public void Record(DnsRequestContext context, EffectivePolicyExplanation decision)
    {
        lock (_gate)
        {
            Purge();
            if (_recent.Count == 64) _recent.Dequeue();
            _recent.Enqueue(new(context, decision.DeviceId, decision.IdentityState, decision.Domain,
                decision.Revision, decision.MappingGeneration, decision.Blocked, decision.Reason)
            { DecisionChain = decision.DecisionChain.Take(4).ToImmutableArray(), EvidenceTruncated = decision.DecisionChain.Length > 4 });
        }
    }
    private void Purge() { while (_recent.TryPeek(out var item) && item.Request.ReceivedAtUtc < DateTimeOffset.UtcNow.AddMinutes(-15)) _recent.Dequeue(); }
    public DnsDecisionObservation[] Read() { lock (_gate) { Purge(); return _recent.ToArray(); } }
}
