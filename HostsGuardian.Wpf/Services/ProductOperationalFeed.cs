using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;

namespace HostsGuardian.Wpf.Services;

/// <summary>Bounded read-only polling, independent from DNS status confirmation and policy delivery.</summary>
public sealed class ProductOperationalFeed : IDisposable
{
    private readonly OperationalConnectionObserver _availability = new();
    private DateTimeOffset _next;
    private long _cursor;
    private bool _pending, _disposed;
    private System.Windows.Threading.DispatcherTimer? _timer;
    public void Start(Func<Task> poll)
    {
        if (_timer != null || _disposed) return;
        _timer = new() { Interval = TimeSpan.FromSeconds(15) };
        _timer.Tick += async (_, _) => await poll(); _timer.Start();
    }
    public void Dispose() { _disposed = true; _timer?.Stop(); }
    public async Task PollAsync(DnsEngineService engine, DnsEngineConfig config, NotificationCenter center, Func<bool> current)
    {
        if (_disposed || _pending || DateTimeOffset.UtcNow < _next) return;
        _pending = true; _next = DateTimeOffset.UtcNow.AddSeconds(15);
        try
        {
            var read = await engine.ReadOperationalEventsAsync(config, _cursor);
            if (_disposed || !current()) return;
            var networkFailure = read.Connection.State is ConnectionState.Timeout or ConnectionState.Unreachable or ConnectionState.NetworkFailure;
            var change = _availability.Observe(read.Batch != null, networkFailure);
            if (change != OperationalAvailabilityTransition.None)
                center.Observe("operational-api", change == OperationalAvailabilityTransition.Unavailable, NotificationCategory.EngineDns,
                    NotificationSeverity.Critical, "Engine unavailable", "Read Engine health and local Monitor diagnostics before changing policy.", "Router");
            if (read.Batch is { } batch)
            { _cursor = batch.LatestSequence; OperationalNotificationObserver.Observe(center, batch); }
        }
        catch { /* Invalid/unsupported evidence never fabricates component recovery. */ }
        finally { _pending = false; }
    }
}
