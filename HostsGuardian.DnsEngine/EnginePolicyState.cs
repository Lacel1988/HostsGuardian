namespace HostsGuardian.DnsEngine;

public sealed record PolicyStateSnapshot(string RestoreState, bool Loaded, long? Revision, int RuleCount,
    bool SafeMode, string SafeModeReason, string PersistenceFault)
{
    public HostsGuardian.Core.Models.FullDnsPolicy? Policy { get; init; }
    public bool FilteringEnabled => Loaded && !SafeMode;
    public int ActiveRuleCount => FilteringEnabled ? RuleCount : 0;
}

/// <summary>Immutable runtime snapshots. Safe Mode is not persisted policy.</summary>
public sealed class EnginePolicyState
{
    private PolicyStateSnapshot _snapshot = new("NotLoaded", false, null, 0, true, "PolicyNotLoaded", "");
    public PolicyStateSnapshot GetSnapshot() => Volatile.Read(ref _snapshot);
    internal void Publish(PolicyStateSnapshot snapshot) => Volatile.Write(ref _snapshot, snapshot);
}
