using System.Net.Sockets;

namespace HostsGuardian.DnsEngine;

/// <summary>Retries only transient listener bind failures during startup. No host/service changes.</summary>
internal static class BoundedListenerRecovery
{
    public static async Task StartAsync(Func<Task> start, string component, CancellationToken cancellationToken,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        delay ??= Task.Delay;
        for (var attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try { await start().ConfigureAwait(false); return; }
            catch (SocketException exception) when (attempt < 3 &&
                exception.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.TryAgain)
            {
                EngineLog.Warning(component, "Transient startup bind failure; bounded retry pending");
                await delay(TimeSpan.FromSeconds(attempt), cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
