using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace HostsGuardian.DnsEngine;

/// <summary>Shared receive-only refresh window. No probe, identity fallback or TTL extension.</summary>
public sealed class RequestBindingRefresh(Func<CancellationToken, Task> refresh,
    Func<DnsRequestContext,bool>? resolved = null)
{
    public static readonly TimeSpan Budget = TimeSpan.FromMilliseconds(200);
    private readonly object _gate = new();
    private Task? _pending;
    private long _lastStarted;

    public async Task EnsureAsync(DnsRequestContext context, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        if (!IPAddress.TryParse(context.SourceAddress, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            return;
        var callerStarted = Stopwatch.GetTimestamp();
        Task? work = null;
        while (Stopwatch.GetElapsedTime(callerStarted) < Budget)
        {
            if (resolved?.Invoke(context) == true) return;
            TimeSpan cooldown;
            lock (_gate)
            {
                cooldown = _pending is null ? TimeSpan.Zero : Budget - Stopwatch.GetElapsedTime(_lastStarted);
                if (_pending is null || (_pending.IsCompleted && cooldown <= TimeSpan.Zero))
                {
                    _lastStarted = Stopwatch.GetTimestamp();
                    var started = _lastStarted;
                    _pending = Task.Run(() => RunAsync(started));
                }
                if (!_pending.IsCompleted) work = _pending;
            }
            if (work is not null)
            {
                var remaining = Budget - Stopwatch.GetElapsedTime(callerStarted);
                if (remaining <= TimeSpan.Zero) return;
                try { await work.WaitAsync(remaining, cancellation); }
                catch (TimeoutException) { return; }
                cancellation.ThrowIfCancellationRequested();
                if (resolved is null || resolved(context)) return;
                work = null;
                continue;
            }
            // A staggered request must not reuse an already completed window whose
            // final read predates its packet. Wait within its own budget, then refresh.
            var left = Budget - Stopwatch.GetElapsedTime(callerStarted);
            if (left <= TimeSpan.Zero) return;
            await Task.Delay(cooldown > TimeSpan.Zero && cooldown < left ? cooldown : left, cancellation);
        }
        cancellation.ThrowIfCancellationRequested();
    }

    private async Task RunAsync(long started)
    {
        var remaining = Budget - Stopwatch.GetElapsedTime(started);
        if (remaining <= TimeSpan.Zero) return;
        using var deadline = new CancellationTokenSource(remaining);
        try
        {
            // A packet can reach the DNS worker before the helper's receive-only cache.
            // Three bounded reads allow capture to catch up without starting ARP.
            for (var attempt = 0; attempt < 3; attempt++)
            {
                await refresh(deadline.Token).WaitAsync(deadline.Token);
                if (attempt < 2) await Task.Delay(50, deadline.Token);
            }
        }
        catch { } // Failure supplies no identity; existing global-policy semantics remain.
    }
}
