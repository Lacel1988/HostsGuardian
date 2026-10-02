using System.Net;
using System.Net.Sockets;

namespace HostsGuardian.DnsEngine;

/// <summary>Single UDP receive owner with bounded, tracked asynchronous request work.</summary>
public sealed class DnsProxyServer : IAsyncDisposable
{
    private readonly EngineSettings _settings;
    private readonly DnsRequestProcessor _processor;
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private UdpClient? _listener;
    private CancellationTokenSource? _cancellation;
    private Task? _receiveLoop;
    private int _activeRequests;
    private readonly BoundedEventLog _log = new();
    private readonly Func<byte[], CancellationToken, Task<byte[]?>> _processRequest;
    public int ActiveRequestCount => Volatile.Read(ref _activeRequests);

    public EngineRuntimeStatus RuntimeStatus { get; }
    public EnginePolicyState PolicyState { get; } = new();
    public bool IsRunning => RuntimeStatus.GetSnapshot().UdpListening;
    internal Task Completion => _receiveLoop ?? Task.CompletedTask;
    internal EngineSettings Settings => _settings;
    public DnsRequestProcessor RequestProcessor => _processor;

    public DnsProxyServer(RuleStore rules, EngineConfig config)
        : this(rules, EngineSettings.FromConfig(config)) { }

    public DnsProxyServer(RuleStore rules, EngineSettings settings)
        : this(rules, settings, null) { }

    // Internal seam for deterministic worker exception/lifetime tests, never selected by production composition.
    internal DnsProxyServer(RuleStore rules, EngineSettings settings,
        Func<byte[], CancellationToken, Task<byte[]?>>? processRequest)
    {
        _settings = settings;
        var upstream = new UpstreamRuntimeState();
        RuntimeStatus = new EngineRuntimeStatus(settings, rules.InstanceId, PolicyState, upstream);
        _processor = new DnsRequestProcessor(rules, settings, new UpstreamDnsForwarder(settings, upstream), PolicyState);
        _processRequest = processRequest ?? _processor.ProcessAsync;
    }

    public void Start() => StartAsync().GetAwaiter().GetResult();
    public void Stop() => StopAsync().GetAwaiter().GetResult();

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_listener != null) return;
            var listener = new UdpClient(AddressFamily.InterNetwork);
            try { listener.Client.Bind(new IPEndPoint(IPAddress.Any, _settings.DnsPort)); }
            catch { listener.Dispose(); throw; }

            var cancellation = new CancellationTokenSource();
            _listener = listener;
            _cancellation = cancellation;
            RuntimeStatus.SetUdpListening(true);
            _receiveLoop = ReceiveLoopAsync(listener, cancellation.Token);
            EngineLog.Information("DNS", $"UDP listening on port {_settings.DnsPort}");
        }
        finally { _lifecycleGate.Release(); }
    }

    public async Task StopAsync()
    {
        await _lifecycleGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_listener == null) return;
            _cancellation!.Cancel();
            _listener.Dispose();
            try { await _receiveLoop!.ConfigureAwait(false); }
            finally
            {
                _cancellation.Dispose();
                _cancellation = null;
                _listener = null;
                _receiveLoop = null;
                RuntimeStatus.SetUdpListening(false);
                EngineLog.Information("DNS", "UDP stopped; owned work completed");
            }
        }
        finally { _lifecycleGate.Release(); }
    }

    private async Task ReceiveLoopAsync(UdpClient listener, CancellationToken cancellationToken)
    {
        var requests = new List<Task>(_settings.MaxConcurrentUdpRequests);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                UdpReceiveResult request;
                try { request = await listener.ReceiveAsync(cancellationToken).ConfigureAwait(false); }
                catch (Exception ex) when (cancellationToken.IsCancellationRequested &&
                    ex is OperationCanceledException or ObjectDisposedException or SocketException)
                { break; }
                catch (SocketException)
                {
                    _log.Warning("DNS", "UDP receive failed");
                    continue;
                }

                // Observe/reap completed work before admission. No unbounded queue or Task.Run.
                for (var index = requests.Count - 1; index >= 0; index--)
                {
                    if (!requests[index].IsCompleted) continue;
                    await requests[index].ConfigureAwait(false);
                    requests.RemoveAt(index);
                }
                if (requests.Count >= _settings.MaxConcurrentUdpRequests)
                {
                    _log.Warning("DNS", "UDP capacity reached; newest datagram dropped");
                    continue;
                }
                requests.Add(ProcessDatagramAsync(listener, request, cancellationToken));
            }
        }
        finally
        {
            // Fatal receive errors also cancel children, before the lifetime observes listener failure.
            _cancellation?.Cancel();
            await Task.WhenAll(requests).ConfigureAwait(false);
            RuntimeStatus.SetUdpListening(false);
        }
    }

    private async Task ProcessDatagramAsync(UdpClient listener, UdpReceiveResult request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _activeRequests);
        try
        {
            var response = await _processRequest(request.Buffer, cancellationToken).ConfigureAwait(false);
            if (response != null && !cancellationToken.IsCancellationRequested)
                await listener.SendAsync(response.AsMemory(), request.RemoteEndPoint, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (cancellationToken.IsCancellationRequested &&
            ex is OperationCanceledException or ObjectDisposedException or SocketException) { }
        catch (Exception) { _log.Warning("DNS", "Request processing or UDP response failed"); }
        finally { Interlocked.Decrement(ref _activeRequests); }
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}
