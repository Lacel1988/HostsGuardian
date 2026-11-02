namespace HostsGuardian.Core.Models;

public sealed record ServiceActivity(Guid? DeviceId, Guid? ServiceId, string ServiceName, DateTimeOffset WindowStartUtc,
    int Allowed, int Blocked, int Failed, bool AmbiguousService);
public sealed record ProductActivityRead(int SchemaVersion, DateTimeOffset ObservedAtUtc, int RetentionHours,
    int MaximumBuckets, ServiceActivity[] Buckets);
public sealed record UsageEstimate(Guid? DeviceId, Guid? ServiceId, string ServiceName, int ActiveWindows,
    int EstimatedActivityMinutes, string Confidence);
public sealed record PolicyAuditRead(int SchemaVersion, bool Available, int MaximumEntries, PolicyAuditRecord[] Entries);
public sealed record PolicyAuditRecord(DateTimeOffset AtUtc, string Operation, string ActorEvidence, long? PreviousRevision,
    long? EffectiveRevision, string Outcome, string PolicyHash)
{
    public string Changes { get; init; } = "";
}
