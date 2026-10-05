using System.Net;
using System.Net.Sockets;

namespace HostsGuardian.DnsEngine;

public enum UpstreamOutcome
{
    Response, Timeout, Cancelled, TransportFailure, InvalidResponse,
    Exhausted, Truncated, ServerFailure
}

public sealed record UpstreamResult(
    UpstreamOutcome Outcome, byte[]? Response = null, int Attempts = 0,
    bool UsedFallback = false, UpstreamOutcome? LastFailure = null);

/// <summary>Bounded UDP attempts, optional configured fallback, and response correlation.</summary>
public sealed class UpstreamDnsForwarder
{
    private readonly DnsTelemetry? _telemetry;
    private readonly IPEndPoint _primary;
    private readonly IPEndPoint? _fallback;
    private readonly int _timeoutMs;
    private readonly int _attemptsPerEndpoint;
    private readonly UpstreamRuntimeState _state;
    private readonly BoundedEventLog _log = new();
    private readonly Func<byte[], IPEndPoint, CancellationToken, Task<UpstreamResult>> _attempt;

    public UpstreamDnsForwarder(EngineSettings settings, UpstreamRuntimeState? state = null)
        : this(settings, state, null) { }

    internal UpstreamDnsForwarder(EngineSettings settings, UpstreamRuntimeState? state,
        Func<byte[], IPEndPoint, CancellationToken, Task<UpstreamResult>>? attempt, DnsTelemetry? telemetry = null)
    {
        _telemetry = telemetry;
        _primary = new IPEndPoint(settings.UpstreamAddress, settings.UpstreamPort);
        _fallback = settings.FallbackEndpoint == null ? null
            : new IPEndPoint(settings.FallbackEndpoint.Address, settings.FallbackEndpoint.Port);
        _timeoutMs = settings.UpstreamTimeoutMs;
        _attemptsPerEndpoint = settings.UpstreamRetryCount + 1;
        _state = state ?? new UpstreamRuntimeState();
        _attempt = attempt ?? AttemptAsync;
    }

    public async Task<UpstreamResult> ForwardAsync(byte[] request, CancellationToken cancellationToken)
    {
        var endpoints = _fallback == null ? new[] { _primary } : new[] { _primary, _fallback };
        var attempts = 0;
        var usedFallback = false;
        UpstreamResult last = new(UpstreamOutcome.Timeout);
        foreach (var endpoint in endpoints)
        {
            for (var attempt = 0; attempt < _attemptsPerEndpoint; attempt++)
            {
                if (cancellationToken.IsCancellationRequested)
                    return new UpstreamResult(UpstreamOutcome.Cancelled, Attempts: attempts, UsedFallback: usedFallback);
                usedFallback = endpoint != _primary;
                if (usedFallback) _log.Warning("Upstream", "Configured fallback activated");
                attempts++;
                var started = System.Diagnostics.Stopwatch.GetTimestamp();
                last = await _attempt(request, endpoint, cancellationToken).ConfigureAwait(false);
                _telemetry?.Attempt(usedFallback ? 1 : 0, last.Outcome, System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds, attempts > 1, usedFallback);
                if (last.Outcome == UpstreamOutcome.Cancelled)
                    return last with { Attempts = attempts, UsedFallback = usedFallback };
                if (last.Outcome is UpstreamOutcome.Response or UpstreamOutcome.Truncated)
                    return Complete(last with { Attempts = attempts, UsedFallback = usedFallback });
                _log.Warning("Upstream", last.Outcome.ToString());
                // A datagram too large for UDP cannot succeed at another endpoint.
                if (request.Length > 65507)
                    return Complete(last with { Attempts = attempts, UsedFallback = usedFallback });
            }
        }
        var outcome = attempts > 1 ? UpstreamOutcome.Exhausted : last.Outcome;
        return Complete(new UpstreamResult(outcome, Attempts: attempts,
            UsedFallback: usedFallback, LastFailure: last.Outcome));
    }

    private UpstreamResult Complete(UpstreamResult result)
    {
        _state.Record(result);
        if (result.Outcome is UpstreamOutcome.Exhausted or UpstreamOutcome.Truncated)
            _log.Warning("Upstream", result.Outcome.ToString());
        return result;
    }

    private async Task<UpstreamResult> AttemptAsync(byte[] request, IPEndPoint endpoint, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_timeoutMs);
        var invalidPackets = 0;
        try
        {
            using var socket = new UdpClient(AddressFamily.InterNetwork);
            await socket.SendAsync(request.AsMemory(), endpoint, deadline.Token).ConfigureAwait(false);
            while (true)
            {
                var response = await socket.ReceiveAsync(deadline.Token).ConfigureAwait(false);
                if (!response.RemoteEndPoint.Equals(endpoint) ||
                    !DnsProtocol.IsMatchingResponse(request, response.Buffer))
                {
                    _log.Warning("Upstream", "InvalidResponse");
                    if (++invalidPackets >= 8) return new UpstreamResult(UpstreamOutcome.InvalidResponse);
                    continue;
                }
                if ((response.Buffer[2] & 2) != 0)
                    return new UpstreamResult(UpstreamOutcome.Truncated);
                if ((response.Buffer[3] & 15) == 2)
                    return new UpstreamResult(UpstreamOutcome.ServerFailure);
                return new UpstreamResult(UpstreamOutcome.Response, response.Buffer);
            }
        }
        catch (OperationCanceledException)
        {
            return new UpstreamResult(cancellationToken.IsCancellationRequested
                ? UpstreamOutcome.Cancelled : invalidPackets > 0 ? UpstreamOutcome.InvalidResponse : UpstreamOutcome.Timeout);
        }
        catch (SocketException) { return new UpstreamResult(UpstreamOutcome.TransportFailure); }
    }
}
