namespace HostsGuardian.Core.Models;

/// <summary>Ephemeral aggregate diagnostic context. No raw query/domain history or separate identity registry.</summary>
public sealed record DeviceDnsCounters(long Received, long Allowed, long PolicyBlocked, long Failed,
    long Servfail, long Rejected, long CapacityDropped, long Cancelled, long TcpConnectionsRejected);
public sealed record DeviceDnsDiagnostic(string TrackingId, Guid? DeviceId, string IdentityState,
    string Name, string NameEvidence, string LastObservedAddress, DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc, DateTimeOffset? LastDnsActivityUtc, long CumulativeReceived, DeviceDnsCounters Window)
{ public NetworkIdentityEvidence? NetworkEvidence { get; init; } public string DeviceType { get; init; } = ""; }
public sealed record DeviceDiagnosticsSnapshot(int SchemaVersion, string InstanceId, DateTimeOffset SnapshotUtc,
    long? PolicyRevision, int WindowSeconds, int MaximumSources, long EvictedSources, DeviceDnsDiagnostic[] Devices)
{
    public LanDeviceObservation[] LanDevices { get; init; } = [];
    public int OmittedLanDevices { get; init; }
    public string DiscoveryStatus { get; init; } = "Passive host evidence only; visibility is incomplete.";
}
