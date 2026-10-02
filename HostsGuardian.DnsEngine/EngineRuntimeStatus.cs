using HostsGuardian.Core.Models;

namespace HostsGuardian.DnsEngine;

/// <summary>Read-only API view of transport state; does not imply policy synchronization.</summary>
public interface IEngineRuntimeStatus
{
    DnsServiceStatus GetSnapshot();
}

public sealed class EngineRuntimeStatus : IEngineRuntimeStatus
{
    private readonly EngineSettings _settings;
    private readonly string _instanceId;
    private int _udpListening;
    private int _tcpListening;
    private int _managementListening;
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

    internal void SetUdpListening(bool listening) => Volatile.Write(ref _udpListening, listening ? 1 : 0);
    internal void SetTcpListening(bool listening) => Volatile.Write(ref _tcpListening, listening ? 1 : 0);
    internal void SetManagementListening(bool listening) => Volatile.Write(ref _managementListening, listening ? 1 : 0);
    internal void SetRuntimeState(string state) => Volatile.Write(ref _runtimeState, state);

    public DnsServiceStatus GetSnapshot()
    {
        var policy = _policy.GetSnapshot();
        var upstream = _upstream.GetSnapshot();
        return new DnsServiceStatus
        {
            Implementation = "HostsGuardian.DnsEngine",
            InstanceId = _instanceId,
            DnsPort = _settings.DnsPort,
            UdpListening = Volatile.Read(ref _udpListening) == 1,
            TcpImplemented = true,
            TcpListening = Volatile.Read(ref _tcpListening) == 1,
            TcpTargetPort = _settings.DnsPort,
            ApiPort = _settings.ApiPort,
            RuntimeState = Volatile.Read(ref _runtimeState),
            ManagementListening = Volatile.Read(ref _managementListening) == 1,
            PolicyRestoreState = policy.RestoreState,
            PolicyLoaded = policy.Loaded,
            PolicyRevision = policy.Revision,
            CommittedRuleCount = policy.RuleCount,
            ActiveRuleCount = policy.ActiveRuleCount,
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
