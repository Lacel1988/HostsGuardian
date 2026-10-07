namespace HostsGuardian.Core.Models;

/// <summary>Engine-session observation identity, never a policy registration or permanent physical identity.</summary>
public sealed record LanDeviceObservation(Guid ObservationDeviceId, string Stability, string Presence,
    DateTimeOffset FirstObservedUtc, DateTimeOffset LastObservedUtc, NetworkIdentityEvidence[] Evidence)
{
    public DateTimeOffset? LastReadAtUtc {get;init;}
    public InferredClassificationMemory? LastReliableClassification {get;init;}
    public DeviceClassification? Classification {get;init;}
    public DeviceIdentityPresentation? Identity { get; init; }
    public string DnsActivity { get; init; } = "NOT OBSERVED";
    public string Coverage { get; init; } = "UNKNOWN";
    public string ResolverPath { get; init; } = "UNKNOWN";
    public int EvidenceOmitted { get; init; }
    public string Explanation { get; init; } = "LAN evidence does not establish the selected DNS path.";
}
