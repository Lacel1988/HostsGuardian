using System.Diagnostics;

namespace HostsGuardian.Core.Services;

public sealed record DnsCacheFlushResult(bool Success, string Message);

/// <summary>One verified execution path. Tests inject an executor and never flush real DNS.</summary>
public sealed class DnsCacheFlushService
{
    private readonly Func<CancellationToken, Task<int?>> _execute;
    public DnsCacheFlushService(Func<CancellationToken, Task<int?>>? execute = null)
        => _execute = execute ?? ExecuteAsync;

    public async Task<DnsCacheFlushResult> FlushAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var exit = await _execute(cancellationToken);
            return new(exit == 0, exit == 0 ? "This PC’s DNS cache was cleared." : "This PC’s DNS cache could not be cleared.");
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException)
        { return new(false, "This PC’s DNS cache could not be cleared."); }
    }

    private static async Task<int?> ExecuteAsync(CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(6));
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "ipconfig.exe"),
            Arguments = "/flushdns", UseShellExecute = false, CreateNoWindow = true
        });
        if (process == null) return null;
        try { await process.WaitForExitAsync(deadline.Token); return process.ExitCode; }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(); }
            catch (InvalidOperationException) { }
            throw;
        }
    }
}
