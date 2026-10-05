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

    public async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        var exitCode = 0;
        using var lifetimeWait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var diagnostics = _dns.RuntimeStatus.Diagnostics?.RunAsync(lifetimeWait.Token) ?? Task.CompletedTask;
        try
        {
            _dns.RuntimeStatus.SetRuntimeState("Starting");
            _api.InitializePolicyForStartup();
            await _api.StartAsync(cancellationToken);
            await _dns.StartAsync(cancellationToken);
            await _tcp.StartAsync(cancellationToken);
            _dns.RuntimeStatus.SetRuntimeState("Running");
            EngineLog.Information("Engine", "Startup complete");
            var cancellation = Task.Delay(Timeout.Infinite, lifetimeWait.Token);
            var completed = await Task.WhenAny(cancellation, _api.Completion, _dns.Completion, _tcp.Completion);
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
