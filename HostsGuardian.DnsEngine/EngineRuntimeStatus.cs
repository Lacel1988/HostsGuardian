using HostsGuardian.Core.Models;

namespace HostsGuardian.DnsEngine;

/// <summary>Read-only API view of transport state; does not imply policy synchronization.</summary>
public interface IEngineRuntimeStatus
{
    DnsServiceStatus GetSnapshot();
}

public sealed class EngineRuntimeStatus : IEngineRuntimeStatus
{
    public EngineDiagnostics? Diagnostics { get; internal set; }
    internal PolicyStateSnapshot PolicyForDiagnostics => _policy.GetSnapshot();
    private readonly EngineSettings _settings;
    private readonly string _instanceId;
    // Lifecycle publication only; no DNS/upstream I/O occurs under this lock.
    private readonly object _gate = new();
    private string _ipv6UdpState = "NotStarted", _ipv6TcpState = "NotStarted";
    internal void SetIpv6UdpState(string state) { lock (_gate) _ipv6UdpState = state; }
    internal void SetIpv6TcpState(string state) { lock (_gate) _ipv6TcpState = state; }
    internal void StopIpv6Udp() { lock (_gate) if (_ipv6UdpState == "Listening") _ipv6UdpState = "Stopped"; }
    internal void StopIpv6Tcp() { lock (_gate) if (_ipv6TcpState == "Listening") _ipv6TcpState = "Stopped"; }
    private string _udpState = "NotStarted";
    private string _tcpState = "NotStarted";
    private string _managementState = "NotStarted";
    private string _runtimeState = "NotStarted";

    private readonly EnginePolicyState _policy;
    private readonly UpstreamRuntimeState _upstream;

    public EngineRuntimeStatus(EngineSettings settings, string instanceId, EnginePolicyState policy, UpstreamRuntimeState? upstream = null)
    {
        _settings = settings;
        _instanceId = instanceId;
        _policy = policy;
        _upstream = upstream ?? new UpstreamRuntimeState();
    }

    internal void SetUdpState(string state) { lock (_gate) _udpState = state; }
    internal void SetTcpState(string state) { lock (_gate) _tcpState = state; }
    internal void SetManagementState(string state) { lock (_gate) _managementState = state; }
    internal void SetUdpListening(bool listening)
    { lock (_gate) if (listening || _udpState != "Faulted") _udpState = listening ? "Listening" : "Stopped"; }
    internal void SetTcpListening(bool listening)
    { lock (_gate) if (listening || _tcpState != "Faulted") _tcpState = listening ? "Listening" : "Stopped"; }
    internal void SetManagementListening(bool listening)
    { lock (_gate) if (listening || _managementState != "Faulted") _managementState = listening ? "Listening" : "Stopped"; }
    internal void SetRuntimeState(string state) { lock (_gate) _runtimeState = state; }

    public DnsServiceStatus GetSnapshot()
    {
        lock (_gate)
        {
            var policy = _policy.GetSnapshot();
            var upstream = _upstream.GetSnapshot();
            var evidence = HostsGuardian.Core.Services.DnsCoverageEvidence.Read();
            var coverage = DnsCoverage.Evaluate(_udpState == "Listening" && _tcpState == "Listening",
                _ipv6UdpState == "Listening" && _ipv6TcpState == "Listening", evidence.HostIpv6Active) with
            { HostIpv6Active = evidence.HostIpv6Active, HostCachedIpv6Resolvers = evidence.HostCachedIpv6Resolvers, HostEvidence = evidence.HostEvidence };
            return new DnsServiceStatus
            {
                Ipv6UdpState = _ipv6UdpState,
                Ipv6TcpState = _ipv6TcpState,
                Coverage = coverage,
                Implementation = "HostsGuardian.DnsEngine",
                InstanceId = _instanceId,
                DnsPort = _settings.DnsPort,
                UdpListening = _udpState == "Listening",
                TcpImplemented = true,
                TcpListening = _tcpState == "Listening",
                TcpTargetPort = _settings.DnsPort,
                ApiPort = _settings.ApiPort,
                RuntimeState = _runtimeState == "Running" &&
                    (_udpState != "Listening" || _tcpState != "Listening" || _managementState != "Listening" ||
                     _ipv6UdpState == "Faulted" || _ipv6TcpState == "Faulted")
                    ? "Degraded" : _runtimeState,
                SnapshotUtc = DateTimeOffset.UtcNow,
                UdpState = _udpState,
                TcpState = _tcpState,
                ManagementState = _managementState,
                ManagementListening = _managementState == "Listening",
                PolicyRestoreState = policy.RestoreState,
                PolicyLoaded = policy.Loaded,
                PolicyRevision = policy.Revision,
                CommittedRuleCount = policy.RuleCount,
                ActiveRuleCount = policy.ActiveRuleCount,
                CommittedDeviceOverrideCount = policy.Policy?.Overrides.Count(o => o.State != DeviceDomainRuleState.Inherit) ?? 0,
                ActiveDeviceOverrideCount = policy.FilteringEnabled ? policy.Policy?.Overrides.Count(o => o.State != DeviceDomainRuleState.Inherit) ?? 0 : 0,
                PolicySchemaVersion = policy.Policy?.SchemaVersion,
                DeviceGroupCount = policy.Policy?.Program?.Groups.Length ?? 0,
                ServiceCatalogCount = policy.Policy?.Program?.Services.Length ?? 0,
                ProfileCount = policy.Policy?.Program?.Profiles.Length ?? 0,
                ScheduleCount = policy.Policy?.Program?.Schedules.Length ?? 0,
                FilteringEnabled = policy.FilteringEnabled,
                EmergencySafeMode = policy.SafeMode,
                SafeModeReason = policy.SafeModeReason,
                PersistenceFault = policy.PersistenceFault,
                UpstreamHealth = "NotMeasured",
                UpstreamConfigured = true,
                FallbackConfigured = _settings.FallbackEndpoint != null,
                LastUpstreamSuccessUtc = upstream.LastSuccessUtc,
                LastUpstreamFailureUtc = upstream.LastFailureUtc,
                LastUpstreamOutcome = upstream.LastOutcome,
                LastUpstreamFailure = upstream.LastFailure,
                LastUpstreamRequestUsedFallback = upstream.LastRequestUsedFallback,
                LastFallbackUseUtc = upstream.LastFallbackUseUtc
            };
        }
    }
}
