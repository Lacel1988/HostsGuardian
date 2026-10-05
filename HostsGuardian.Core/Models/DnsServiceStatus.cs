namespace HostsGuardian.Core.Models;

/// <summary>Independent transport and policy snapshots; connectivity does not imply rule synchronization.</summary>
public sealed class DnsServiceStatus
{
    public DateTimeOffset? SnapshotUtc { get; set; }
    public string UdpState { get; set; } = "NotStarted";
    public string TcpState { get; set; } = "NotStarted";
    public string ManagementState { get; set; } = "NotStarted";
    public string Implementation { get; set; } = "";
    public string InstanceId { get; set; } = "";
    public int DnsPort { get; set; }
    public bool UdpListening { get; set; }
    public bool TcpImplemented { get; set; }
    public bool TcpListening { get; set; }
    public int TcpTargetPort { get; set; }
    public int ApiPort { get; set; }
    public string RuntimeState { get; set; } = "NotStarted";
    public bool ManagementListening { get; set; }
    public string PolicyRestoreState { get; set; } = "NotLoaded";
    public bool PolicyLoaded { get; set; }
    public long? PolicyRevision { get; set; }
    public int CommittedRuleCount { get; set; }
    public int ActiveRuleCount { get; set; }
    public int CommittedDeviceOverrideCount { get; set; }
    public int ActiveDeviceOverrideCount { get; set; }
    public bool FilteringEnabled { get; set; }
    public bool EmergencySafeMode { get; set; }
    public string SafeModeReason { get; set; } = "";
    public string PersistenceFault { get; set; } = "";
    public string UpstreamHealth { get; set; } = "NotMeasured";
    public bool UpstreamConfigured { get; set; }
    public bool FallbackConfigured { get; set; }
    public DateTimeOffset? LastUpstreamSuccessUtc { get; set; }
    public DateTimeOffset? LastUpstreamFailureUtc { get; set; }
    public string LastUpstreamOutcome { get; set; } = "NotObserved";
    public string LastUpstreamFailure { get; set; } = "";
    public bool LastUpstreamRequestUsedFallback { get; set; }
    public DateTimeOffset? LastFallbackUseUtc { get; set; }
}
