namespace HostsGuardian.Core.Models;

/// <summary>An acknowledgement is historical; only a matching authenticated snapshot confirms the transition.</summary>
public sealed record SafeModeTransitionResult(ConnectionResult Connection, bool RequestedSafeMode,
    long? AcknowledgedRevision, int? AcknowledgedCount)
{
    public bool Confirmed => Connection.Ok && Connection.Transport is { } status &&
        AcknowledgedCount.HasValue && status.PolicyRevision == AcknowledgedRevision &&
        status.CommittedRuleCount == AcknowledgedCount && status.EmergencySafeMode == RequestedSafeMode &&
        (RequestedSafeMode ? !status.FilteringEnabled : status.PolicyLoaded && status.FilteringEnabled);
}
