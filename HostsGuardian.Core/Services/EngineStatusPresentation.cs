using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

/// <summary>UI-owned state. Historical observations are never used as current state after failure/expiry.</summary>
public sealed class EngineStatusPresentation
{
    public static readonly TimeSpan MaximumStatusAge = TimeSpan.FromSeconds(30);
    private readonly Func<DateTimeOffset> _clock;
    private ConnectionResult? _lastResult;
    private DateTimeOffset? _confirmedUtc;
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
        _lastResult = result.Ok && result.Transport == null ? new(ConnectionState.Incompatible, "Missing status response") : result;
        if (result.Ok && result.Transport != null)
        {
            LastConfirmed = result.Transport;
            _confirmedUtc = _clock();
            if (synchronizedRevision != null)
            {
                _synchronizedRevision = synchronizedRevision;
                _synchronizedInstance = result.Transport.InstanceId;
            }
        }
    }
    public void InvalidateSelection() => _synchronizedRevision = null;
    public void Reset()
    {
        Pending = false;
        _lastResult = null;
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
