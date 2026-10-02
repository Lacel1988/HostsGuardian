using System.Net;
using System.Net.Sockets;

namespace HostsGuardian.DnsEngine;

/// <summary>Owns TCP connections and framing. All DNS decisions use the shared request processor.</summary>
public sealed class TcpDnsServer : IAsyncDisposable
{
    public const int MaximumConnections = 16;
    private readonly EngineSettings _settings;
    private readonly DnsRequestProcessor _processor;
    private readonly EngineRuntimeStatus _status;
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private readonly object _connectionsGate = new();
    private readonly Dictionary<TcpClient, Task> _connections = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _cancellation;
    private Task? _acceptLoop;
    private int _malformedReported;
    private int _limitReported;

    public bool IsRunning => _status.GetSnapshot().TcpListening;
    internal Task Completion => _acceptLoop ?? Task.CompletedTask;

    public TcpDnsServer(EngineSettings settings, DnsRequestProcessor processor, EngineRuntimeStatus status)
    {
        _settings = settings;
        _processor = processor;
        _status = status;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_listener != null) return;
            var listener = new TcpListener(IPAddress.Any, _settings.DnsPort);
            try { listener.Start(MaximumConnections); }
            catch { listener.Stop(); throw; }
            var cancellation = new CancellationTokenSource();
            _listener = listener;
            _cancellation = cancellation;
            _malformedReported = 0;
            _limitReported = 0;
            _status.SetTcpListening(true);
            _acceptLoop = AcceptLoopAsync(listener, cancellation.Token);
            EngineLog.Information("TCP DNS", $"Listening on port {_settings.DnsPort}");
        }
        finally { _lifecycleGate.Release(); }
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                lock (_connectionsGate)
                {
                    ReapCompletedConnections();
                    if (cancellationToken.IsCancellationRequested || _connections.Count >= MaximumConnections)
                    {
                        client.Dispose();
                        if (!cancellationToken.IsCancellationRequested && Interlocked.Exchange(ref _limitReported, 1) == 0)
                            EngineLog.Warning("TCP DNS", "Connection limit reached; excess connections are closed");
                        continue;
                    }
                    client.NoDelay = true;
                    _connections.Add(client, HandleConnectionAsync(client, cancellationToken));
                }
            }
        }
        catch (Exception exception) when (cancellationToken.IsCancellationRequested &&
            exception is OperationCanceledException or SocketException or ObjectDisposedException or InvalidOperationException) { }
        catch (Exception)
        {
            EngineLog.Failure("TCP DNS", "Listener failed");
            throw; // EngineLifetime observes this task and shuts down the remaining components.
        }
        finally { _status.SetTcpListening(false); }
    }

    private void ReapCompletedConnections()
    {
        var completed = new List<TcpClient>();
        foreach (var connection in _connections)
        {
            if (!connection.Value.IsCompleted) continue;
            connection.Value.GetAwaiter().GetResult();
            completed.Add(connection.Key);
        }
        foreach (var client in completed) _connections.Remove(client);
    }

    private async Task HandleConnectionAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                while (!cancellationToken.IsCancellationRequested)
                {
                    // A fixed transport read deadline bounds idle/partial-frame connection retention.
                    using var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    readDeadline.CancelAfter(TimeSpan.FromSeconds(30));
                    var request = await TcpDnsFraming.ReadAsync(stream, readDeadline.Token).ConfigureAwait(false);
                    if (request == null) break;
                    var response = await _processor.ProcessAsync(request, cancellationToken).ConfigureAwait(false);
                    if (response == null) break; // No synthetic answer/retry is introduced in this phase.
                    using var writeDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    writeDeadline.CancelAfter(TimeSpan.FromSeconds(30));
                    await TcpDnsFraming.WriteAsync(stream, response, writeDeadline.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { } // Idle deadline or Engine shutdown.
            catch (Exception exception) when (exception is EndOfStreamException or InvalidDataException)
            {
                if (Interlocked.Exchange(ref _malformedReported, 1) == 0)
                    EngineLog.Warning("TCP DNS", "Malformed/truncated framing closed; further frame warnings suppressed until restart");
            }
            catch (Exception exception) when (exception is IOException or SocketException or ObjectDisposedException)
            { } // Peer reset/disconnect or cancellation-driven socket disposal is local to this connection.
            catch (Exception)
            { EngineLog.Failure("TCP DNS", "Connection processing failed"); }
        }
    }

    public async Task StopAsync()
    {
        await _lifecycleGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_listener == null) return;
            _cancellation!.Cancel();
            _listener.Stop();
            lock (_connectionsGate)
                foreach (var connection in _connections) connection.Key.Dispose();
            try { await _acceptLoop!.ConfigureAwait(false); }
            finally
            {
                Task[] connections;
                lock (_connectionsGate) connections = _connections.Values.ToArray();
                try { await Task.WhenAll(connections).ConfigureAwait(false); }
                finally
                {
                    lock (_connectionsGate) _connections.Clear();
                    _cancellation.Dispose();
                    _cancellation = null;
                    _listener = null;
                    _acceptLoop = null;
                    _status.SetTcpListening(false);
                    EngineLog.Information("TCP DNS", "Stopped; all owned connections completed");
                }
            }
        }
        finally { _lifecycleGate.Release(); }
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}
