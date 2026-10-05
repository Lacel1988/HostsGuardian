using System.Text.Json;
using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

public sealed record MonitorEvent(DateTimeOffset AtUtc, string Level, string Component, string Message);
public sealed record LocalMonitorSnapshot(int SchemaVersion, DateTimeOffset EmittedAtUtc, int ProcessId,
    DateTimeOffset StartedAtUtc, DnsServiceStatus Status, MonitorEvent[] Events)
{
    public EngineDiagnosticsSnapshot? Diagnostics { get; init; }
    public OperationalEventBatch? OperationalEvents { get; init; }
}

/// <summary>Optional Engine-owned, read-only status file; independent of policy and management credentials.</summary>
public sealed class LocalMonitorStatusPublisher
{
    private readonly IEngineRuntimeStatus _status;
    private readonly string _path;
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;
    public LocalMonitorStatusPublisher(IEngineRuntimeStatus status, string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Monitor status path must be absolute");
        _status = status; _path = path;
    }
    public void PublishOnce()
    {
        var directory = Path.GetDirectoryName(_path)!;
        if (!Directory.Exists(directory) || new DirectoryInfo(directory).LinkTarget != null || new FileInfo(_path).LinkTarget != null)
            throw new IOException("Monitor requires an owned, existing runtime directory");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new LocalMonitorSnapshot(1, DateTimeOffset.UtcNow, Environment.ProcessId,
            _started, _status.GetSnapshot(), EngineLog.RecentEvents()) {
                Diagnostics = (_status as EngineRuntimeStatus)?.Diagnostics?.Snapshot(),
                OperationalEvents = (_status as EngineRuntimeStatus)?.Diagnostics?.Health.Read()
            }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        if (bytes.Length > 131072) throw new IOException("Monitor snapshot exceeds limit");
        var temporary = Path.Combine(directory, ".monitor-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
            using (var stream = new FileStream(temporary, options)) { stream.Write(bytes); stream.Flush(true); }
            File.Move(temporary, _path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        var reported = false;
        do
        {
            try { PublishOnce(); reported = false; }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                if (!reported) EngineLog.Warning("Monitor", "Local status unavailable; Engine remains independent");
                reported = true;
            }
            try { if (!await timer.WaitForNextTickAsync(cancellationToken)) break; }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
        } while (!cancellationToken.IsCancellationRequested);
    }
}
