using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

public sealed record DnsDecisionObservation(DnsRequestContext Request, Guid? DeviceId, string IdentityState,
    string Domain, long? PolicyRevision, long MappingGeneration, bool Blocked, string Reason);

/// <summary>Bounded diagnostic evidence of actual received DNS requests, never identity discovery.</summary>
public sealed class DnsObservationStore
{
    private readonly object _gate = new();
    private readonly Queue<DnsDecisionObservation> _recent = new();
    public void Record(DnsRequestContext context, EffectivePolicyExplanation decision)
    {
        lock (_gate)
        {
            if (_recent.Count == 64) _recent.Dequeue();
            _recent.Enqueue(new(context, decision.DeviceId, decision.IdentityState, decision.Domain,
                decision.Revision, decision.MappingGeneration, decision.Blocked, decision.Reason));
        }
    }
    public DnsDecisionObservation[] Read() { lock (_gate) return _recent.ToArray(); }
}
