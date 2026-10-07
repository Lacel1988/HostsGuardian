using System.Net;

namespace HostsGuardian.DnsEngine;

/// <summary>DNS message processing shared by transports; never mutates policy.</summary>
public sealed class DnsRequestProcessor
{
    public AddressBindingStore Bindings { get; } = new();
    public DnsObservationStore Observations { get; } = new();
    public ProductActivityStore Activity { get; } = new();
    internal Action<DnsRequestContext>? ContextObserved { get; set; }
    public DnsTelemetry Telemetry { get; }
    private readonly RuleStore _rules;
    private readonly IPAddress _blockedAddress;
    private readonly UpstreamDnsForwarder _upstream;
    private readonly EnginePolicyState _policyState;

    public DnsRequestProcessor(RuleStore rules, EngineSettings settings, UpstreamDnsForwarder upstream, EnginePolicyState policyState, DnsTelemetry? telemetry = null)
    {
        Telemetry = telemetry ?? new DnsTelemetry(settings);
        _rules = rules;
        _blockedAddress = settings.BlockedAddress;
        _upstream = upstream;
        _policyState = policyState;
    }

    // Legacy fixture callers have no source identity and therefore inherit global policy.
    public Task<byte[]?> ProcessAsync(byte[] request, CancellationToken cancellationToken)
        => ProcessAsync(request, new(DnsTransport.Udp, "", 0, DateTimeOffset.UtcNow, null), cancellationToken);

    public Task<byte[]?> ProcessAsync(byte[] request, DnsRequestContext context, CancellationToken cancellationToken)
    { Telemetry.Received(context.Transport); return ProcessReceivedAsync(request, context, cancellationToken); }

    public string ObserveDevice(DnsRequestContext context, string kind)
    {
        var policy = _policyState.GetSnapshot().Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty;
        var identity = AddressBindingStore.Resolve(Bindings.Read(), policy, context, DateTimeOffset.UtcNow);
        return Telemetry.Devices.Record(context, identity.DeviceId, identity.State, kind, DateTimeOffset.UtcNow);
    }
    public void ObserveCapacityDrop(DnsRequestContext context)
    { var key=ObserveDevice(context,"Received"); Telemetry.Devices.Outcome(key,"Dropped",DateTimeOffset.UtcNow); }
    public async Task<byte[]?> ProcessReceivedAsync(byte[] request, DnsRequestContext context, CancellationToken cancellationToken)
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        Telemetry.Enter(context.Transport);
        var deviceKey = "";
        try
        {
        var policy = _policyState.GetSnapshot();
        var fullPolicy = policy.Policy ?? HostsGuardian.Core.Models.FullDnsPolicy.Empty with
        { GlobalBlockedDomains = System.Collections.Immutable.ImmutableArray.CreateRange(_rules.GetBlockedDomains()) };
        var bindingSnapshot = Bindings.Read();
        var identity = AddressBindingStore.Resolve(bindingSnapshot,fullPolicy,context,DateTimeOffset.UtcNow);
        deviceKey = Telemetry.Devices.Record(context,identity.DeviceId,identity.State,"Received",DateTimeOffset.UtcNow);
        ContextObserved?.Invoke(context);
        var parsed = DnsProtocol.TryParseQuestion(request, out var question);
        if (!parsed || request[4] != 0 || request[5] != 1 || (request[2] & 0xf8) != 0)
            { Telemetry.Rejected(); Telemetry.Devices.Outcome(deviceKey,"Rejected",DateTimeOffset.UtcNow); return null; }
        if (cancellationToken.IsCancellationRequested) { Telemetry.Cancelled(); Telemetry.Devices.Outcome(deviceKey,"Cancelled",DateTimeOffset.UtcNow); return null; }
        var decision = DevicePolicyEvaluator.Explain(policy, fullPolicy, bindingSnapshot, context, question.QName, DateTimeOffset.UtcNow);
        Observations.Record(context, decision);
        if (decision.Blocked)
        { var blocked = DnsProtocol.BuildBlockedResponse(request, question, _blockedAddress); Telemetry.Blocked(); Telemetry.Devices.Outcome(deviceKey,"Blocked",DateTimeOffset.UtcNow); Activity.Record(fullPolicy, decision, "Blocked", DateTimeOffset.UtcNow); return blocked; }

        var result = await _upstream.ForwardAsync(request, cancellationToken);
        if (result.Outcome == UpstreamOutcome.Response) { Telemetry.Allowed(); Telemetry.Devices.Outcome(deviceKey,"Allowed",DateTimeOffset.UtcNow); Activity.Record(fullPolicy, decision, "Allowed", DateTimeOffset.UtcNow); return result.Response; }
        if (result.Outcome == UpstreamOutcome.Cancelled) { Telemetry.Cancelled(); Telemetry.Devices.Outcome(deviceKey,"Cancelled",DateTimeOffset.UtcNow); return null; }
        var failure = DnsProtocol.BuildServerFailure(request, question);
        Telemetry.Failed(); Telemetry.Devices.Outcome(deviceKey,"Servfail",DateTimeOffset.UtcNow); Activity.Record(fullPolicy, decision, "Failed", DateTimeOffset.UtcNow); return failure;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { Telemetry.Cancelled(); Telemetry.Devices.Outcome(deviceKey,"Cancelled",DateTimeOffset.UtcNow); throw; }
        catch { Telemetry.Failed(false); Telemetry.Devices.Outcome(deviceKey,"Failed",DateTimeOffset.UtcNow); throw; }
        finally { Telemetry.ProcessingLatency.Record(System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds); Telemetry.Exit(context.Transport); }
    }
}
