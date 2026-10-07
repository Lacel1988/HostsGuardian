namespace HostsGuardian.Core.Models;
/// <summary>Ephemeral address evidence, never a registered identity or authoritative binding.</summary>
public sealed record NetworkIdentityEvidence(string Address, string Mac, string Hostname, string Provenance, DateTimeOffset ObservedAtUtc)
{
    // Read time is not ownership confirmation. ObservedAtUtc is the kernel state-update
    // time when available, otherwise a legacy sample time with EvidenceTimeKnown=false.
    public DateTimeOffset? ReadAtUtc { get; init; }
    public DateTimeOffset? ConfirmedAtUtc { get; init; }
    public DateTimeOffset? KernelUpdatedAtUtc { get; init; }
    public bool EvidenceTimeKnown { get; init; }
    public string Interface { get; init; } = "";
    public string NeighborState { get; init; } = "Unknown";
    public string Confidence { get; init; } = "OBSERVED";
    public bool PrivateMacPossible { get; init; }
}
