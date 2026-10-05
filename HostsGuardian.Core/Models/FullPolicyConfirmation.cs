namespace HostsGuardian.Core.Models;

public sealed record FullPolicyConfirmation(ConnectionResult Connection, FullPolicyRead? Readback, bool CanonicalMatch, long? AcknowledgedRevision = null)
{
    public bool Confirmed => CanonicalMatch && Connection.Ok && Readback?.Revision != null
        && Connection.Transport?.PolicyRevision == Readback.Revision && Readback.InstanceId != ""
        && Connection.Transport.InstanceId == Readback.InstanceId;
}
