namespace HostsGuardian.Core.Models;

/// <summary>Untrusted session evidence, not registration or an execution binding.</summary>
public sealed record FingerprintEvidence(string Address,string Provider,string Kind,string Value,DateTimeOffset ObservedAtUtc);
public sealed record DeviceClassification(string DeviceType,string Confidence,string Source,string Reason,
    DateTimeOffset AssessedAtUtc,FingerprintEvidence[] Evidence)
{
    public bool ConflictingEvidence {get;init;}
    public DateTimeOffset? EvidenceFreshUntilUtc {get;init;}
}
public sealed record InferredClassificationMemory(DeviceClassification Classification,string[] Provenance,DateTimeOffset RetainUntilUtc);
