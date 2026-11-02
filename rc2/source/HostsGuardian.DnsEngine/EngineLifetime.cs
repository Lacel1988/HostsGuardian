namespace HostsGuardian.DnsEngine;

/// <summary>Owns startup order and reverse-order cleanup, including partially completed startup.</summary>
public sealed class EngineLifetime
{
    private readonly ApiServer _api;
    private readonly DnsProxyServer _dns;
    private readonly TcpDnsServer _tcp;

    public EngineLifetime(ApiServer api, DnsProxyServer dns)
    {
        _api = api;
        _dns = dns;
        _tcp = new TcpDnsServer(dns.Settings, dns.RequestProcessor, dns.RuntimeStatus);
    }

    // Revision zero is the existing missing-file bootstrap policy, not an authorized policy.
    private bool HasIndependentDnsPolicy => _dns.PolicyState.GetSnapshot() is { FilteringEnabled: true, Revision: > 0 };

    public async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        var exitCode = 0;
        using var lifetimeWait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var diagnostics = _dns.RuntimeStatus.Diagnostics?.RunAsync(lifetimeWait.Token) ?? Task.CompletedTask;
        try
        {
            _dns.RuntimeStatus.SetRuntimeState("Starting");
            _api.InitializePolicyForStartup();
            var managementAvailable = true;
            try { await _api.StartAsync(cancellationToken); }
            catch (ManagementUnavailableException) when (!cancellationToken.IsCancellationRequested &&
                HasIndependentDnsPolicy)
            {
                managementAvailable = false;
                EngineLog.Warning("Engine", "HTTPS unavailable; continuing DNS with loaded filtering policy; repair management configuration");
            }
            await BoundedListenerRecovery.StartAsync(() => _dns.StartAsync(cancellationToken), "DNS", cancellationToken);
            await BoundedListenerRecovery.StartAsync(() => _tcp.StartAsync(cancellationToken), "TCP DNS", cancellationToken);
            _dns.RuntimeStatus.SetRuntimeState("Running");
            EngineLog.Information("Engine", managementAvailable ? "Startup complete" : "DNS startup complete; management unavailable (Degraded)");
            var cancellation = Task.Delay(Timeout.Infinite, lifetimeWait.Token);
            var completed = managementAvailable
                ? await Task.WhenAny(cancellation, _dns.Completion, _tcp.Completion, _api.Completion)
                : await Task.WhenAny(cancellation, _dns.Completion, _tcp.Completion);
            if (managementAvailable && completed == _api.Completion && !cancellationToken.IsCancellationRequested &&
                !_dns.Completion.IsCompleted && !_tcp.Completion.IsCompleted)
            {
                await completed; // Unexpected task faults remain fatal; only an observed transport stop is isolated.
                await _api.StopAsync();
                // Drain management work before checking the final policy; a last authorized request may change Safe Mode.
                if (!HasIndependentDnsPolicy)
                    throw new InvalidOperationException("Management unavailable without loaded filtering policy");
                _dns.RuntimeStatus.SetManagementState("Faulted");
                EngineLog.Failure("Management", "HTTPS stopped unexpectedly; DNS filtering continues; operator recovery required");
                completed = await Task.WhenAny(cancellation, _dns.Completion, _tcp.Completion);
            }
            await completed;
            if (!cancellationToken.IsCancellationRequested)
                throw new InvalidOperationException("Required listener stopped unexpectedly");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception)
        {
            EngineLog.Failure("Engine", "Startup or lifetime failed");
            exitCode = 1;
            _dns.RuntimeStatus.SetRuntimeState("Faulted");
            _dns.RuntimeStatus.Diagnostics?.EvaluateOnce();
        }
        finally
        {
            lifetimeWait.Cancel();
            await diagnostics;
            if (exitCode == 0) _dns.RuntimeStatus.SetRuntimeState("Stopping");
            try { await _tcp.StopAsync(); }
            catch (Exception) { EngineLog.Failure("Engine", "TCP DNS shutdown failed"); exitCode = 1; }
            try { await _dns.StopAsync(); }
            catch (Exception) { EngineLog.Failure("Engine", "DNS shutdown failed"); exitCode = 1; }
            try { await _api.StopAsync(); }
            catch (Exception) { EngineLog.Failure("Engine", "Management shutdown failed"); exitCode = 1; }
            EngineLog.Information("Engine", "Shutdown complete");
            _dns.RuntimeStatus.SetRuntimeState(exitCode == 0 ? "Stopped" : "Faulted");
        }
        return exitCode;
    }
}
