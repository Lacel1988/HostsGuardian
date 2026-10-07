using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

/// <summary>UI-owned state. Historical observations are never used as current state after failure/expiry.</summary>
public sealed class EngineStatusPresentation
{
    public static readonly TimeSpan MaximumStatusAge = TimeSpan.FromSeconds(30);
    private readonly Func<DateTimeOffset> _clock;
    private ConnectionResult? _lastResult;
    private DateTimeOffset? _confirmedUtc;
    private DateTimeOffset? _resultUtc;
    private long? _synchronizedRevision;
    private string? _synchronizedInstance;
    public DnsServiceStatus? LastConfirmed { get; private set; }
    public bool Pending { get; private set; }
    public EngineStatusPresentation(Func<DateTimeOffset>? clock = null) => _clock = clock ?? (() => DateTimeOffset.UtcNow);
    public DnsServiceStatus? Current => !Pending && _lastResult?.Ok == true &&
        _confirmedUtc.HasValue && _clock() - _confirmedUtc.Value <= MaximumStatusAge ? LastConfirmed : null;
    public string Filtering
    {
        get
        {
            var current = Current;
            if (current == null) return "Unknown";
            return current.FilteringEnabled ? "Enabled" : current.EmergencySafeMode ? "Safe Mode bypass" : "Disabled";
        }
    }
    private bool _selectionChanged;
    public string EngineHost => Current != null || (!Pending && _resultUtc != null && _clock() - _resultUtc <= MaximumStatusAge && _lastResult?.State == ConnectionState.AuthenticationFailed) ? "ONLINE" : "UNKNOWN";
    public string Management => Current != null ? "AUTHENTICATED" : Pending || _resultUtc == null || _clock() - _resultUtc > MaximumStatusAge ? "UNKNOWN" : _lastResult?.State switch
    {
        ConnectionState.AuthenticationFailed => "AUTH ERROR",
        ConnectionState.Unreachable or ConnectionState.Timeout => "UNREACHABLE",
        _ => "UNKNOWN"
    };
    public string Coverage => Current?.Coverage.State is "COMPLETE" or "PARTIAL" or "UNKNOWN" ? Current.Coverage.State : "UNKNOWN";
    public string CoverageGuidance => Coverage == "COMPLETE" ? "Assessed DNS paths use HostsGuardian; encrypted DNS is not guaranteed." :
        "DNS coverage is not fully confirmed. Check router IPv4/IPv6 DNS advertisements and client resolver settings.";
    public string DnsService => Current is { Ipv6UdpState: "Faulted" } or { Ipv6TcpState: "Faulted" } ? "DEGRADED" : Current is { } status ?
        status.UdpListening && status.TcpListening ? "RUNNING" :
        status.UdpListening || status.TcpListening ? "DEGRADED" : "DOWN" : "UNKNOWN";
    public string PolicyStatus => Pending ? "PENDING" : _selectionChanged ? "CHANGES NOT SENT" :
        _lastResult is { Ok: false } ? "FAILED" : Synchronization == "Confirmed" ? "SYNCHRONIZED" : "UNKNOWN";
    public string Upstream
    {
        get
        {
            var current = Current;
            if (current == null || current.LastUpstreamOutcome == "NotObserved") return "UNKNOWN";
            var latest = current.LastUpstreamSuccessUtc > current.LastUpstreamFailureUtc || current.LastUpstreamFailureUtc == null
                ? current.LastUpstreamSuccessUtc : current.LastUpstreamFailureUtc;
            if (latest == null || _clock() - latest > MaximumStatusAge) return "UNKNOWN";
            return current.LastUpstreamOutcome == "Response" ? current.LastUpstreamRequestUsedFallback ? "DEGRADED" : "HEALTHY" : "FAILED";
        }
    }
    public string OperationalSummary => $"Engine host: {EngineHost}\nManagement: {Management}\nDNS service: {DnsService}\n" +
        $"Filtering: {Filtering.ToUpperInvariant()}\nPolicy: {PolicyStatus}\nUpstream: {Upstream}";

    public string SafeMode
    {
        get
        {
            var status = Current;
            if (status == null) return "Safe Mode: Unknown / unconfirmed";
            return status.EmergencySafeMode ? "Safe Mode: confirmed bypass" : "Safe Mode: off (confirmed)";
        }
    }

    private DnsServiceStatus? ControllableStatus
    {
        get
        {
            var status = Current;
            if (status == null || !status.ManagementListening) return null;
            if (status.RuntimeState is not ("Running" or "Degraded")) return null;
            return status;
        }
    }
    public bool CanEnterSafeMode => ControllableStatus is { EmergencySafeMode: false };
    public bool CanExitSafeMode => ControllableStatus is { EmergencySafeMode: true, PolicyLoaded: true };

    public string DescribeDetails()
    {
        var status = Current;
        if (status == null)
            return "Current status details: Unknown / unconfirmed" +
                (_confirmedUtc.HasValue ? $"\nLast confirmation: {_confirmedUtc:O} (historical only)" : "");
        static string Time(DateTimeOffset? value) => value?.ToUniversalTime().ToString("O") ?? "Not observed";
        return $"Revision: {status.PolicyRevision}; instance: {status.InstanceId}; snapshot: {status.SnapshotUtc:O}\n" +
            $"Committed/active global rules: {status.CommittedRuleCount}/{status.ActiveRuleCount}; device overrides: {status.CommittedDeviceOverrideCount}/{status.ActiveDeviceOverrideCount}\n" +
            $"Safe Mode reason: {(status.SafeModeReason == "" ? "None reported" : status.SafeModeReason)}\n" +
            $"Policy restore: {status.PolicyRestoreState}; loaded: {status.PolicyLoaded}\n" +
            $"Persistence fault: {(status.PersistenceFault == "" ? "None reported" : status.PersistenceFault)}\n" +
            $"Upstream latest outcome: {status.LastUpstreamOutcome} (passive; not an active health check)\n" +
            $"Last upstream success UTC: {Time(status.LastUpstreamSuccessUtc)}\n" +
            $"Last upstream failure UTC: {Time(status.LastUpstreamFailureUtc)}; historical category: " +
            $"{(status.LastUpstreamFailure == "" ? "Not observed" : status.LastUpstreamFailure)}\n" +
            "Historical failure does not establish a current outage.\n" +
            $"Last observed request used fallback: {(status.LastUpstreamOutcome == "NotObserved" ? "Not observed" : status.LastUpstreamRequestUsedFallback.ToString())}\n" +
            $"Last fallback use UTC: {Time(status.LastFallbackUseUtc)}; fallback configured: {status.FallbackConfigured}\n" +
            $"IPv4 UDP/TCP: {status.UdpState}/{status.TcpState}; IPv6 UDP/TCP: {status.Ipv6UdpState}/{status.Ipv6TcpState}\n" +
            $"DNS coverage: {Coverage}; IPv4 advertisement: {status.Coverage.Ipv4Advertisement}; IPv6 advertisement: {status.Coverage.Ipv6Advertisement}\n" +
            $"Engine-host cached IPv6 resolvers: {string.Join(", ", status.Coverage.HostCachedIpv6Resolvers)}\n" +
            status.Coverage.HostEvidence + "\n" +
            $"Runtime: {status.RuntimeState}; management: {status.ManagementState}; UDP: {status.UdpState}; TCP: {status.TcpState}";
    }

    public string Synchronization
    {
        get
        {
            if (Pending) return "Pending";
            var current = Current;
            if (current == null) return "Unknown";
            return _synchronizedInstance == current.InstanceId && _synchronizedRevision == current.PolicyRevision &&
                _synchronizedRevision != null ? "Confirmed" : "Unconfirmed";
        }
    }

    public void BeginRequest() { Pending = true; }
    public void Complete(ConnectionResult result, long? synchronizedRevision = null)
    {
        Pending = false;
        _resultUtc = _clock();
        _lastResult = result.Ok && result.Transport == null ? new(ConnectionState.Incompatible, "Missing status response") : result;
        if (result.Ok && result.Transport != null)
        {
            LastConfirmed = result.Transport;
            _confirmedUtc = _clock();
            if (synchronizedRevision != null)
            {
                _selectionChanged = false;
                _synchronizedRevision = synchronizedRevision;
                _synchronizedInstance = result.Transport.InstanceId;
            }
        }
    }
    public void InvalidateSelection() { _synchronizedRevision = null; _selectionChanged = true; }
    public void Reset()
    {
        Pending = false;
        _selectionChanged = false;
        _lastResult = null;
        _resultUtc = null;
        _synchronizedRevision = null;
        LastConfirmed = null;
        _confirmedUtc = null;
    }
    public string Describe()
    {
        var current = Current;
        if (current == null)
        {
            var connection = Pending ? "Checking/request pending" : _lastResult == null ? "Not checked" :
                _lastResult.Ok ? "Stale — refresh required" : _lastResult.State.ToString();
            var history = _confirmedUtc.HasValue ? $"; last confirmed {_confirmedUtc:HH:mm:ss} UTC (historical)" : "";
            return $"Management: {connection}{history}\nDNS filtering: Unknown; policy synchronization: {Synchronization}";
        }
        return $"Management: Authenticated (confirmed {_confirmedUtc:HH:mm:ss} UTC); Engine: {current.RuntimeState}\n" +
            $"UDP: {current.UdpState}; TCP: {current.TcpState}; filtering: {Filtering}\n" +
            $"Policy: {Synchronization}; revision {current.PolicyRevision?.ToString() ?? "unknown"}; " +
            $"committed/active rules {current.CommittedRuleCount}/{current.ActiveRuleCount}; restore {current.PolicyRestoreState}\n" +
            $"Persistence: {(current.PersistenceFault == "" ? "no reported fault" : current.PersistenceFault)}; " +
            $"Upstream: {current.LastUpstreamOutcome} (passive)";
    }
}
