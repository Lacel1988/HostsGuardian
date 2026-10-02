using System.Net;

namespace HostsGuardian.DnsEngine;

/// <summary>DNS message processing shared by transports; never mutates policy.</summary>
public sealed class DnsRequestProcessor
{
    private readonly RuleStore _rules;
    private readonly IPAddress _blockedAddress;
    private readonly UpstreamDnsForwarder _upstream;
    private readonly EnginePolicyState _policyState;

    public DnsRequestProcessor(RuleStore rules, EngineSettings settings, UpstreamDnsForwarder upstream, EnginePolicyState policyState)
    {
        _rules = rules;
        _blockedAddress = settings.BlockedAddress;
        _upstream = upstream;
        _policyState = policyState;
    }

    public async Task<byte[]?> ProcessAsync(byte[] request, CancellationToken cancellationToken)
    {
        var parsed = DnsProtocol.TryParseQuestion(request, out var question);
        if (!parsed || request[4] != 0 || request[5] != 1 || (request[2] & 0xf8) != 0)
            return null;
        if (cancellationToken.IsCancellationRequested) return null;
        var policy = _policyState.GetSnapshot();
        if (policy.FilteringEnabled && parsed && _rules.IsBlocked(question.QName) && question.QType is 1 or 28)
            return DnsProtocol.BuildBlockedResponse(request, question, _blockedAddress);

        var result = await _upstream.ForwardAsync(request, cancellationToken);
        if (result.Outcome == UpstreamOutcome.Response) return result.Response;
        if (result.Outcome == UpstreamOutcome.Cancelled) return null;
        return DnsProtocol.BuildServerFailure(request, question);
    }
}
