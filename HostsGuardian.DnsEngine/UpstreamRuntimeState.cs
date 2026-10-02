namespace HostsGuardian.DnsEngine;

public sealed record UpstreamSnapshot(
    DateTimeOffset? LastSuccessUtc, DateTimeOffset? LastFailureUtc,
    string LastOutcome, string LastFailure, bool LastRequestUsedFallback,
    DateTimeOffset? LastFallbackUseUtc);

/// <summary>Passive completed-request observations. Reading never probes or changes policy.</summary>
public sealed class UpstreamRuntimeState
{
    private readonly object _gate = new();
    private UpstreamSnapshot _snapshot = new(null, null, "NotObserved", "", false, null);

    public UpstreamSnapshot GetSnapshot()
    {
        lock (_gate) return _snapshot;
    }

    internal void Record(UpstreamResult result)
    {
        if (result.Outcome == UpstreamOutcome.Cancelled) return;
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            var success = result.Outcome == UpstreamOutcome.Response;
            _snapshot = new UpstreamSnapshot(
                success ? now : _snapshot.LastSuccessUtc,
                success ? _snapshot.LastFailureUtc : now,
                result.Outcome.ToString(),
                success ? _snapshot.LastFailure : (result.LastFailure ?? result.Outcome).ToString(),
                result.UsedFallback,
                result.UsedFallback ? now : _snapshot.LastFallbackUseUtc);
        }
    }
}
