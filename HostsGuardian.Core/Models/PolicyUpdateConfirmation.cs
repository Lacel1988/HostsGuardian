namespace HostsGuardian.Core.Models;

/// <summary>Acknowledged commit and subsequent authenticated status are separate confirmations.</summary>
public sealed record PolicyUpdateConfirmation(ConnectionResult Connection, long? CommittedRevision, int Count)
{
    public bool Confirmed => Connection.Ok && Connection.Transport?.PolicyRevision == CommittedRevision && CommittedRevision != null;
}
