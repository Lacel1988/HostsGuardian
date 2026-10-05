namespace HostsGuardian.Core.Services;

public enum OperationalAvailabilityTransition { None, Unavailable, Recovered }
public sealed record OperationalReadDefaults(int FailureSeconds = 15, int RecoverySeconds = 30);

/// <summary>The client observes API reachability; an Engine cannot report its own disappearance.</summary>
public sealed class OperationalConnectionObserver
{
    private readonly Func<DateTimeOffset> _clock;
    private readonly OperationalReadDefaults _defaults;
    private DateTimeOffset? _failureSince, _recoverySince;
    private bool _reported;
    public OperationalConnectionObserver(Func<DateTimeOffset>? clock = null, OperationalReadDefaults? defaults = null)
    {
        _clock = clock ?? (() => DateTimeOffset.UtcNow); _defaults = defaults ?? new();
        if (_defaults.FailureSeconds is < 1 or > 300 || _defaults.RecoverySeconds is < 1 or > 300) throw new ArgumentException("Invalid read-health defaults");
    }
    public OperationalAvailabilityTransition Observe(bool validResponse, bool networkFailure)
    {
        var now = _clock();
        if (networkFailure)
        {
            _recoverySince = null; _failureSince ??= now;
            if (!_reported && (now - _failureSince.Value).TotalSeconds >= _defaults.FailureSeconds)
            { _reported = true; return OperationalAvailabilityTransition.Unavailable; }
        }
        else if (validResponse)
        {
            _failureSince = null;
            if (_reported)
            {
                _recoverySince ??= now;
                if ((now - _recoverySince.Value).TotalSeconds >= _defaults.RecoverySeconds)
                { _reported = false; _recoverySince = null; return OperationalAvailabilityTransition.Recovered; }
            }
        }
        else { _failureSince = null; _recoverySince = null; } // Unsupported/invalid reads prove neither failure nor recovery.
        return OperationalAvailabilityTransition.None;
    }
}
